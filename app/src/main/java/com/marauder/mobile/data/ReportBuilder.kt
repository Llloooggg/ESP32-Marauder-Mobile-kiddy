package com.marauder.mobile.data

import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** One library artifact as the report sees it. */
data class ReportArtifact(
    val name: String,
    val title: String,
    val kind: String,
    val createdAt: Long,
    val bytes: Long,
    val hashState: String,
    val meta: Map<String, String>,
)

/** Everything the report is made of. Deliberately Android-free so it can be tested. */
data class ReportInput(
    val generatedAt: Long = System.currentTimeMillis(),
    val appVersion: String = "",
    val board: DeviceInfoForJournal? = null,
    val journal: List<JournalEntry> = emptyList(),
    val artifacts: List<ReportArtifact> = emptyList(),
    /** artifact name → the file that holds it (included in the zip). */
    val files: Map<String, File> = emptyMap(),
    /** artifact name → its extracted hashcat-22000 sidecar (included in the zip). */
    val hashSidecars: Map<String, File> = emptyMap(),
    /** journal files to include verbatim. */
    val journals: List<File> = emptyList(),
)

/** The result of one report build: the markdown plus the archive on disk. */
data class ReportResult(val markdown: String, val archive: File, val entries: Int)

/**
 * Turns a session (journal + artifact library) into a self-audit report:
 * `report.md` (what was run, against what, what came out) plus a zip holding
 * the markdown, the raw journals, the captures and their `.22000` hash files.
 *
 * The point of the report is accountability: it lists what *you* ran on *your*
 * gear, and the cracked-password column is the result of auditing your own
 * networks.
 */
object ReportBuilder {

    /** Render the human-readable report. */
    fun markdown(input: ReportInput): String = buildString {
        appendLine("# ESP32 Marauder session report")
        appendLine()
        appendLine("Generated: ${stamp(input.generatedAt)} · app ${input.appVersion.ifBlank { "?" }}")
        input.board?.let {
            appendLine("Board: ${it.board} · firmware ${it.fw} · json proto ${it.proto}")
        }
        appendLine()

        val sessions = input.journal.count { it.kind == JournalEntry.SESSION }
        val commands = input.journal.count { it.kind == JournalEntry.COMMAND }
        val missions = input.journal.filter { it.kind == JournalEntry.MISSION && it.meta["event"] == "start" }
        val creds = input.journal.filter { it.kind == JournalEntry.CRED }
        val errors = input.journal.count { it.kind == JournalEntry.ERROR }
        val cracked = input.artifacts.mapNotNull { it.meta["cracked"]?.let { p -> it.name to p } }

        appendLine("## Summary")
        appendLine()
        appendLine("| item | value |")
        appendLine("|---|---|")
        appendLine("| board sessions | $sessions |")
        appendLine("| commands sent | $commands |")
        appendLine("| missions | ${missions.size} |")
        appendLine("| artifacts | ${input.artifacts.size} |")
        appendLine("| captures with hashes | ${input.artifacts.count { it.hashState == ArtifactRecord.HASH_DONE }} |")
        appendLine("| captures cracked | ${cracked.size} |")
        appendLine("| portal credentials | ${creds.size} |")
        appendLine("| error lines | $errors |")
        appendLine()

        if (missions.isNotEmpty()) {
            appendLine("## Missions")
            appendLine()
            appendLine("| started | title | command | kind | duration | bytes | eapol | gaps | drops | artifact |")
            appendLine("|---|---|---|---|---|---|---|---|---|---|")
            missions.forEach { start ->
                val end = input.journal.firstOrNull {
                    it.kind == JournalEntry.MISSION && it.meta["event"] == "stop" &&
                        it.meta["command"] == start.meta["command"] && it.at >= start.at
                }
                val secs = end?.meta["seconds"] ?: "running"
                appendLine(
                    "| ${stamp(start.at)} | ${cell(start.text)} | `${cell(start.meta["command"] ?: "")}` | " +
                        "${start.meta["kind"] ?: ""} | $secs | ${start.meta["bytes"] ?: ""} | " +
                        "${start.meta["eapol"] ?: ""} | ${start.meta["gaps"] ?: ""} | ${start.meta["drops"] ?: ""} | " +
                        "${cell(end?.meta["artifact"] ?: "")} |",
                )
            }
            appendLine()
        }

        if (input.artifacts.isNotEmpty()) {
            appendLine("## Artifacts")
            appendLine()
            appendLine("| created | title | kind | size | pmkid | handshakes | hash lines | cracked |")
            appendLine("|---|---|---|---|---|---|---|---|")
            input.artifacts.sortedBy { it.createdAt }.forEach { a ->
                appendLine(
                    "| ${stamp(a.createdAt)} | ${cell(a.title.ifBlank { a.name })} | ${a.kind.uppercase(Locale.US)} | " +
                        "${humanSize(a.bytes)} | ${a.meta["pmkid"] ?: "-"} | ${a.meta["handshakes"] ?: "-"} | " +
                        "${a.meta["hashLines"] ?: "-"} | ${cell(a.meta["cracked"] ?: "")} |",
                )
            }
            appendLine()
        }

        val apTargets = input.journal.filter { it.meta["target_essid"] != null }
        if (apTargets.isNotEmpty()) {
            appendLine("## Targets touched")
            appendLine()
            appendLine("| started | essid | bssid | channel | command |")
            appendLine("|---|---|---|---|---|")
            apTargets.forEach { e ->
                appendLine(
                    "| ${stamp(e.at)} | ${cell(e.meta["target_essid"] ?: "")} | ${cell(e.meta["target_bssid"] ?: "")} | " +
                        "${e.meta["target_channel"] ?: ""} | `${cell(e.meta["command"] ?: "")}` |",
                )
            }
            appendLine()
        }

        if (creds.isNotEmpty()) {
            appendLine("## Captured portal credentials")
            appendLine()
            appendLine("Only credentials submitted to a page you hosted on your own network belong here. " +
                "Collecting other people's credentials is a crime even when nothing is done with them.")
            appendLine()
            appendLine("| time | user | password |")
            appendLine("|---|---|---|")
            creds.forEach { c ->
                appendLine("| ${stamp(c.at)} | ${cell(c.meta["user"] ?: "")} | ${cell(c.meta["pass"] ?: "")} |")
            }
            appendLine()
        }

        if (cracked.isNotEmpty()) {
            appendLine("## Recovered passphrases (own-network audit)")
            appendLine()
            appendLine("| artifact | passphrase |")
            appendLine("|---|---|")
            cracked.forEach { (name, pass) -> appendLine("| ${cell(name)} | `${cell(pass)}` |") }
            appendLine()
        }

        appendLine("## Session log")
        appendLine()
        appendLine("Commands, missions, credentials and errors in full; the board's own console text is " +
            "included from the journal (it can be long).")
        appendLine()
        appendLine("```")
        val keep = input.journal.filter { it.kind != JournalEntry.OUTPUT }
        keep.forEach { e ->
            appendLine("${stamp(e.at)}  ${e.kind.uppercase(Locale.US)}  ${e.text}${suffix(e.meta)}")
        }
        val outputs = input.journal.count { it.kind == JournalEntry.OUTPUT }
        appendLine("… $outputs console line(s) of board output are in the journal file in this archive")
        appendLine("```")
        appendLine()
        appendLine("---")
        appendLine()
        appendLine("Authorised use only: this report describes activity against networks and devices you own " +
            "or have written permission to test.")
    }

    /**
     * Write the archive: `report.md` + `journal/…` + `captures/…` + `hashes/…`.
     * Returns null when the archive could not be written.
     */
    fun writeZip(target: File, input: ReportInput, markdown: String): ReportResult? {
        var entries = 0
        return try {
            target.parentFile?.mkdirs()
            ZipOutputStream(FileOutputStream(target)).use { zip ->
                put(zip, "report.md", markdown.toByteArray(Charsets.UTF_8)); entries++
                input.journals.forEach { f ->
                    if (f.exists()) { put(zip, "journal/${f.name}", f.readBytes()); entries++ }
                }
                input.artifacts.forEach { a ->
                    val f = input.files[a.name]
                    if (f != null && f.exists()) { put(zip, "captures/${a.name}", f.readBytes()); entries++ }
                    val side = input.hashSidecars[a.name]
                    if (side != null && side.exists()) {
                        put(zip, "hashes/${a.name}.22000.txt", side.readBytes()); entries++
                    }
                }
            }
            ReportResult(markdown, target, entries)
        } catch (e: Exception) {
            runCatching { target.delete() }
            null
        }
    }

    private fun put(zip: ZipOutputStream, name: String, bytes: ByteArray) {
        zip.putNextEntry(ZipEntry(name))
        zip.write(bytes)
        zip.closeEntry()
    }

    private fun cell(s: String): String = s.replace("|", "\\|").replace("\n", " ")

    private fun suffix(meta: Map<String, String>): String =
        if (meta.isEmpty()) "" else "  " + meta.entries.joinToString(" ") { (k, v) -> "$k='$v'" }

    private fun stamp(ms: Long): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(ms))

    private fun humanSize(bytes: Long): String = when {
        bytes >= 1_000_000 -> "%.1f MB".format(bytes / 1_000_000.0)
        bytes >= 1_000 -> "%.0f KB".format(bytes / 1_000.0)
        else -> "$bytes B"
    }
}
