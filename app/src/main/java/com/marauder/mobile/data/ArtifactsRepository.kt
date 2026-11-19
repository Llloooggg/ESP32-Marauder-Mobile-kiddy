package com.marauder.mobile.data

import android.content.Context
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File

/**
 * One captured artifact on the phone (pcap / gpx / log / csv). The canonical
 * file lives in the captures directory (see [ArtifactStore]); the record adds
 * the friendly title, provenance and extraction state that the file itself
 * cannot carry.
 */
@Serializable
data class ArtifactRecord(
    val name: String,                    // file name inside the store directory
    val createdAt: Long,
    var title: String = "",
    var kind: String = "",               // "pcap" | "gpx" | "log" | "csv" …
    var meta: Map<String, String> = emptyMap(),
    var hashState: String = HASH_NONE,   // none | done | fail
    var note: String = "",
) {
    companion object {
        const val HASH_NONE = "none"
        const val HASH_DONE = "done"
        const val HASH_FAIL = "fail"

        /**
         * Meta keys holding the SSIDs the app saw for this capture's BSSIDs
         * (`ssid.<bssid>` → ESSID). The SSID is the PBKDF2 salt, so a capture
         * that never caught a beacon can still be cracked when the scan list
         * supplies it — this is what makes the record self-contained.
         */
        const val SSID_META = "ssid."

        /** Meta key naming the BSSID a capture was aimed at, as the app pinned it. */
        const val TARGET_BSSID = "target_bssid"

        /** bssid → SSID pairs stored in a record's meta. */
        fun knownEssids(meta: Map<String, String>): Map<String, String> =
            meta.filterKeys { it.startsWith(SSID_META) }
                .mapKeys { (k, _) -> k.removePrefix(SSID_META).lowercase() }
                .filterValues { it.isNotBlank() }
    }
}

/** A listed artifact: the record plus the live file it maps to. */
data class Artifact(
    val record: ArtifactRecord,
    val file: File,
)

/**
 * JSON-indexed library over a flat capture directory. Files copied into the
 * directory by other means (an adb push, an older app version) appear as
 * generic artifacts automatically; deleting through the store removes both
 * the file and the index entry.
 */
class ArtifactStore(private val dir: File) {

    /** The directory every capture/journal/report file lives in. */
    val directory: File get() = dir

    private val indexFile = File(dir, ".artifacts-index.json")
    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true }
    private val listSerializer = ListSerializer(ArtifactRecord.serializer())
    private val knownExtensions = setOf("pcap", "gpx", "log", "csv", "jsonl", "zip")

    @Synchronized
    fun list(): List<Artifact> {
        val byName = load().associateBy { it.name }.toMutableMap()
        var changed = false
        dir.listFiles()?.forEach { f ->
            val ext = f.extension.lowercase()
            if (!f.isDirectory && ext in knownExtensions && !byName.containsKey(f.name)) {
                byName[f.name] = ArtifactRecord(
                    name = f.name,
                    createdAt = f.lastModified(),
                    title = f.nameWithoutExtension.replace('_', ' '),
                    kind = ext,
                )
                changed = true
            }
        }
        // Drop index entries whose files were removed behind our back.
        val missing = byName.keys.filter { !File(dir, it).exists() }
        if (missing.isNotEmpty()) {
            missing.forEach { byName.remove(it) }
            changed = true
        }
        val records = byName.values.sortedByDescending { it.createdAt }
        if (changed) save(records)
        return records.map { it to File(dir, it.name) }
            .filter { (_, f) -> f.exists() }
            .map { (r, f) -> Artifact(r, f) }
    }

    @Synchronized
    fun upsert(record: ArtifactRecord) {
        val all = load().associateBy { it.name }.toMutableMap()
        all[record.name] = record
        save(all.values.sortedByDescending { it.createdAt })
    }

    @Synchronized
    fun get(name: String): Artifact? =
        load().firstOrNull { it.name == name }?.let { Artifact(it, File(dir, it.name)) }
            ?.takeIf { it.file.exists() }

    /** Remove the record and its file from disk (plus any extracted-hash sidecar). */
    @Synchronized
    fun delete(name: String) {
        val all = load().toMutableList()
        all.removeAll { it.name == name }
        save(all)
        runCatching { File(dir, name).delete() }
        runCatching { hashFileFor(name).delete() }
    }

    /** Sidecar file holding the hashcat-22000 lines extracted from this capture. */
    fun hashFileFor(name: String): File = File(dir, "$name.22000.txt")

    /** Store the outcome of hash extraction: state, counts and an optional note. */
    @Synchronized
    fun setHashResult(name: String, state: String, note: String = "", counts: Map<String, String> = emptyMap()) {
        val all = load().toMutableList()
        val i = all.indexOfFirst { it.name == name }
        if (i >= 0) {
            val rec = all[i]
            all[i] = rec.copy(hashState = state, note = note, meta = rec.meta + counts)
            save(all)
        }
    }

    private fun load(): List<ArtifactRecord> = try {
        if (!indexFile.exists()) emptyList()
        else json.decodeFromString(listSerializer, indexFile.readText())
    } catch (e: Exception) {
        emptyList()   // corrupt index: rebuild from disk on the next list()
    }

    private fun save(records: List<ArtifactRecord>) {
        try {
            dir.mkdirs()
            indexFile.writeText(json.encodeToString(listSerializer, records))
        } catch (_: Exception) {
            // Best-effort: the file captures themselves stay intact.
        }
    }
}

/**
 * Process-wide artifact library: the capture directory plus its JSON index, and the
 * hash-extraction seam the artifact detail screen drives.
 */
class ArtifactsRepository(context: Context) {

    val store: ArtifactStore = ArtifactStore(File(context.getExternalFilesDir(null), "captures"))

    /**
     * Timestamped log of each board session (commands, missions with counters,
     * portal credentials, the board's own console text). One JSONL file per
     * connection, kept next to the captures and pulled into the session report.
     */
    val journal: Journal = Journal(store.directory)

    /** Replaced by the build once the `:extractor` module is linked into the app. */
    var bridge: ExtractionBridge = UnwiredExtractionBridge

    /**
     * Turn one capture into crack-ready hashes and remember the result on the
     * artifact (state + counts + a sidecar `.22000.txt`). Returns null when the
     * extractor is not wired. [knownEssids] (bssid → SSID from the app's scan
     * list) is the fallback salt source for captures that never caught a beacon:
     * without an SSID no cracker can work, so passing it rescues otherwise
     * unusable handshakes.
     */
    fun analyze(name: String, knownEssids: Map<String, String> = emptyMap()): HashExtractResult? {
        val artifact = store.get(name) ?: return null
        val salts = ArtifactRecord.knownEssids(artifact.record.meta) + knownEssids
        val result = bridge.extract(artifact.file, salts)
        if (result == null) {
            store.setHashResult(name, ArtifactRecord.HASH_FAIL, "extractor unavailable")
            return null
        }
        val diagnostics = mapOf(
            "pmkid" to result.pmkidCount.toString(),
            "handshakes" to result.handshakeSets.toString(),
            "hashLines" to result.hashLines.size.toString(),
            // Why a "0 handshakes" result happened, in the raw counts the UI shows.
            "frames" to result.frames.toString(),
            "eapol" to result.eapolFrames.toString(),
            "beacons" to result.beacons.toString(),
            "m1" to result.m1.toString(),
            "m2" to result.m2.toString(),
            "m3" to result.m3.toString(),
            "m4" to result.m4.toString(),
            "badRecords" to result.badRecords.toString(),
            "lostBytes" to result.lostBytes.toString(),
            // Which networks the extracted material belongs to — compared against the
            // BSSID the operation was aimed at, so "wrong network" is visible rather
            // than something the user has to notice by cross-reading MACs.
            "networks" to result.networks.joinToString(" "),
            // Key management per network: an SAE-only (WPA3) network has no password
            // hash to recover, and that has to be on the record, not rediscovered by
            // running a wordlist that cannot possibly succeed.
            "sae_frames" to result.saeAuthFrames.toString(),
            "sae_only" to result.saeOnlyNetworks.joinToString(" "),
            "netsec" to result.security.entries.sortedBy { it.key }
                .joinToString("; ") { "${it.key}=${it.value}" },
        )
        val attribution = CaptureAttribution.verdict(
            artifact.record.meta[ArtifactRecord.TARGET_BSSID],
            result.networks,
        )
        val explanation = CaptureAttribution.explain(attribution)
        val note = listOfNotNull(result.note, explanation).joinToString("; ").ifEmpty { null }
        val aimMeta = if (attribution is CaptureAttribution.Verdict.Mismatch) {
            mapOf("aimed_bssid" to attribution.aimed, "aimed_missing" to "1")
        } else {
            emptyMap()
        }
        if (!result.usable) {
            store.setHashResult(
                name,
                ArtifactRecord.HASH_FAIL,
                note ?: "no PMKID or handshake in this capture",
                diagnostics + aimMeta,
            )
            return result
        }
        runCatching { store.hashFileFor(name).writeText(result.hashLines.joinToString("\n")) }
        store.setHashResult(name, ArtifactRecord.HASH_DONE, note ?: "", diagnostics + aimMeta)
        return result
    }

    /** Crack-ready hash lines previously extracted for this artifact. */
    fun hashLines(name: String): List<String> =
        runCatching { store.hashFileFor(name).readLines().filter { it.isNotBlank() } }.getOrDefault(emptyList())

    /** Remember a recovered password on the artifact so the result survives restarts. */
    fun markCracked(name: String, password: String) {
        store.get(name)?.let {
            store.setHashResult(name, it.record.hashState, it.record.note, mapOf("cracked" to password))
        }
    }

    // --- Session journal ------------------------------------------------------

    /** Register a closed journal file as an artifact so it lands in the library. */
    fun registerJournal(s: JournalSummary) {
        if (s.entries <= 0) return
        store.upsert(
            ArtifactRecord(
                name = s.file.name,
                createdAt = s.file.lastModified(),
                title = "Session log (${s.entries} entries)",
                kind = "jsonl",
                meta = mapOf(
                    "entries" to s.entries.toString(),
                    "bytes" to s.file.length().toString(),
                    "truncated" to s.truncated.toString(),
                ),
            ),
        )
    }

    /** Every journal file on disk, newest first. */
    fun journalFiles(): List<File> =
        store.directory.listFiles()?.filter { it.isFile && it.extension == "jsonl" }
            ?.sortedByDescending { it.lastModified() }
            ?: emptyList()

    /** All journal entries from [files] (capped), oldest first. */
    fun journalEntries(files: List<File>, limit: Int = 4000): List<JournalEntry> {
        val all = files.flatMap { journal.read(it) }
        return if (all.size <= limit) all.sortedBy { it.at }
        else all.sortedBy { it.at }.take(limit)
    }

    // --- Session report ------------------------------------------------------

    /**
     * Build the self-audit report: `report.md` plus a zip holding it, the raw
     * journals, every artifact and its extracted hashes. The archive is
     * registered as an artifact itself so it can be shared from the library.
     */
    fun exportReport(appVersion: String, board: DeviceInfoForJournal?): ReportResult? {
        val journals = journalFiles()
        val artifacts = store.list()
        val input = ReportInput(
            appVersion = appVersion,
            board = board,
            journal = journalEntries(journals),
            artifacts = artifacts.map {
                ReportArtifact(
                    name = it.record.name,
                    title = it.record.title,
                    kind = it.record.kind,
                    createdAt = it.record.createdAt,
                    bytes = it.file.length(),
                    hashState = it.record.hashState,
                    meta = it.record.meta,
                )
            },
            files = artifacts.associate { it.record.name to it.file },
            hashSidecars = artifacts
                .filter { it.record.hashState == ArtifactRecord.HASH_DONE }
                .map { it.record.name to store.hashFileFor(it.record.name) }
                .toMap(),
            journals = journals,
        )
        val markdown = ReportBuilder.markdown(input)
        val dir = store.directory
        var i = 0
        var target: File
        do { target = File(dir, "report_$i.zip"); i++ } while (target.exists())
        val result = ReportBuilder.writeZip(target, input, markdown) ?: return null
        runCatching {
            File(dir, target.name.removeSuffix(".zip") + ".md").writeText(markdown)
        }
        store.upsert(
            ArtifactRecord(
                name = target.name,
                createdAt = System.currentTimeMillis(),
                title = "Session report (${result.entries} files)",
                kind = "zip",
                meta = mapOf("bytes" to target.length().toString(), "files" to result.entries.toString()),
            ),
        )
        return result
    }

    /** Write [text] as a CSV artifact in the library; returns its record. */
    fun writeCsvArtifact(title: String, baseName: String, text: String, rows: Int): ArtifactRecord? {
        return try {
            store.directory.mkdirs()
            var i = 0
            var f: File
            do { f = File(store.directory, "${baseName}_$i.csv"); i++ } while (f.exists())
            f.writeText(text)
            val record = ArtifactRecord(
                name = f.name,
                createdAt = System.currentTimeMillis(),
                title = title,
                kind = "csv",
                meta = mapOf("rows" to rows.toString(), "bytes" to f.length().toString()),
            )
            store.upsert(record)
            record
        } catch (e: Exception) {
            null
        }
    }
}
