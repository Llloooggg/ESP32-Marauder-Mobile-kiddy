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

    private val indexFile = File(dir, ".artifacts-index.json")
    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true }
    private val listSerializer = ListSerializer(ArtifactRecord.serializer())
    private val knownExtensions = setOf("pcap", "gpx", "log", "csv")

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

    /** Replaced by the build once the `:extractor` module is linked into the app. */
    var bridge: ExtractionBridge = UnwiredExtractionBridge

    /**
     * Turn one capture into crack-ready hashes and remember the result on the
     * artifact (state + counts + a sidecar `.22000.txt`). Returns null when the
     * extractor is not wired or the capture holds nothing usable.
     */
    fun analyze(name: String): HashExtractResult? {
        val artifact = store.get(name) ?: return null
        val result = bridge.extract(artifact.file)
        if (result == null) {
            store.setHashResult(name, ArtifactRecord.HASH_FAIL, "extractor unavailable")
            return null
        }
        if (!result.usable) {
            store.setHashResult(
                name,
                ArtifactRecord.HASH_FAIL,
                result.note ?: "no PMKID or handshake in this capture",
                mapOf("pmkid" to "0", "handshakes" to "0"),
            )
            return result
        }
        runCatching { store.hashFileFor(name).writeText(result.hashLines.joinToString("\n")) }
        store.setHashResult(
            name,
            ArtifactRecord.HASH_DONE,
            result.note ?: "",
            mapOf(
                "pmkid" to result.pmkidCount.toString(),
                "handshakes" to result.handshakeSets.toString(),
                "hashLines" to result.hashLines.size.toString(),
            ),
        )
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
}
