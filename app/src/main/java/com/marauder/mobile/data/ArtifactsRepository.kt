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

    /** Remove the record and its file from disk. */
    @Synchronized
    fun delete(name: String) {
        val all = load().toMutableList()
        all.removeAll { it.name == name }
        save(all)
        runCatching { File(dir, name).delete() }
    }

    @Synchronized
    fun updateHashState(name: String, state: String, note: String = "") {
        val all = load().toMutableList()
        val i = all.indexOfFirst { it.name == name }
        if (i >= 0) {
            all[i] = all[i].copy(hashState = state, note = note)
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

/** Process-wide artifact library (captures directory + JSON index). */
class ArtifactsRepository(context: Context) {
    val store: ArtifactStore = ArtifactStore(File(context.getExternalFilesDir(null), "captures"))
}
