package com.marauder.mobile.data

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.BufferedWriter
import java.io.File
import java.io.FileWriter

/**
 * One journal entry: when something happened, what kind of thing it was and the
 * text/fields describing it. Kinds the app writes:
 *  - `session`  board connected / disconnected (meta: board, fw, proto)
 *  - `command`  a command the app sent (meta: command)
 *  - `mission`  mission started / stopped (meta: command, kind, seconds, bytes…)
 *  - `cred`     an Evil Portal form submission (meta: user, pass)
 *  - `error`    firmware error line or app-level failure
 *  - `safety`   the app refused to send something (unconfirmed target, rate not
 *               acknowledged…) — what was *not* done, and why
 *  - `note`     anything worth keeping that is not one of the above
 *  - `output`   the board's own console text (the raw log)
 */
@Serializable
data class JournalEntry(
    val at: Long,
    val kind: String,
    val text: String,
    val meta: Map<String, String> = emptyMap(),
) {
    companion object {
        const val SESSION = "session"
        const val COMMAND = "command"
        const val MISSION = "mission"
        const val CRED = "cred"
        const val ERROR = "error"
        const val SAFETY = "safety"
        const val NOTE = "note"
        const val OUTPUT = "output"
    }
}

/** What [Journal.close] reports: where the journal landed and how much is in it. */
data class JournalSummary(val file: File, val entries: Int, val truncated: Boolean)

/**
 * A timestamped journal of one board session, written as JSONL (one entry per
 * line) next to the captures. It is the raw session log the report is built
 * from: every command the app sent, every mission with its counters, every
 * credential the portal caught, and the board's own console text.
 *
 * The board can be chatty (rawlog, captures streaming status lines), so the
 * `output` entries are cut off past [maxOutputBytes] — commands, missions and
 * credentials are always kept. [truncated] says so in the report.
 */
class Journal(private val dir: File, private val maxOutputBytes: Long = MAX_OUTPUT_BYTES) {

    private val json = Json { ignoreUnknownKeys = true }

    private var writer: BufferedWriter? = null
    private var current: File? = null
    private var count = 0
    private var outputBytes = 0L
    private var truncated = false

    val isActive: Boolean get() = writer != null

    /** The journal file of the running session (null when nothing is open). */
    fun file(): File? = current

    /** Start a new journal file (one per connection). */
    @Synchronized
    fun open(info: DeviceInfoForJournal?): File? {
        close()
        return try {
            dir.mkdirs()
            val f = uniqueFile(dir)
            writer = BufferedWriter(FileWriter(f))
            current = f
            count = 0
            outputBytes = 0L
            truncated = false
            if (info != null) {
                write(JournalEntry(
                    at = System.currentTimeMillis(),
                    kind = JournalEntry.SESSION,
                    text = "connected: ${info.board}",
                    meta = mapOf("board" to info.board, "fw" to info.fw, "proto" to info.proto.toString()),
                ))
            }
            f
        } catch (e: Exception) {
            writer = null
            current = null
            null
        }
    }

    /** Append one entry (nothing happens when no session is open). */
    @Synchronized
    fun record(kind: String, text: String, meta: Map<String, String> = emptyMap()) {
        if (writer == null) return
        write(JournalEntry(System.currentTimeMillis(), kind, text, meta))
    }

    /** Append the board's console text; dropped past the output budget. */
    @Synchronized
    fun output(text: String) {
        if (writer == null) return
        if (outputBytes >= maxOutputBytes) {
            if (!truncated) {
                truncated = true
                write(JournalEntry(
                    System.currentTimeMillis(), JournalEntry.NOTE,
                    "console output truncated at $maxOutputBytes B",
                ))
            }
            return
        }
        outputBytes += text.length
        write(JournalEntry(System.currentTimeMillis(), JournalEntry.OUTPUT, text))
    }

    /**
     * Close the journal and report what was written.
     *
     * A session that wrote nothing leaves no file: an empty journal is not a record of anything, and
     * keeping it filled the library with `journal 3 · 0 B` rows that looked like files to look at.
     * Nothing is hidden by this - an empty file carries no evidence to carry.
     */
    @Synchronized
    fun close(): JournalSummary? {
        val w = writer ?: return null
        val f = current
        runCatching { w.flush(); w.close() }
        writer = null
        current = null
        if (count == 0) {
            runCatching { f?.delete() }
            return null
        }
        return f?.let { JournalSummary(it, count, truncated) }
    }

    /** Read a journal file back (empty when unreadable or corrupt lines). */
    fun read(file: File): List<JournalEntry> = try {
        file.readLines().mapNotNull { line ->
            if (line.isBlank()) null
            else runCatching { json.decodeFromString(JournalEntry.serializer(), line) }.getOrNull()
        }
    } catch (e: Exception) {
        emptyList()
    }

    /** All entries in the running journal file (empty when none). */
    fun readCurrent(): List<JournalEntry> = current?.let { read(it) } ?: emptyList()

    /** Serialize entries back to JSONL (used when a journal is re-emitted). */
    fun toJsonLines(entries: List<JournalEntry>): String =
        entries.joinToString("\n") { json.encodeToString(JournalEntry.serializer(), it) }

    /** Parse a JSONL journal (used by tests and by the report builder). */
    fun fromJsonLines(text: String): List<JournalEntry> = try {
        text.lineSequence().filter { it.isNotBlank() }
            .mapNotNull { runCatching { json.decodeFromString(JournalEntry.serializer(), it) }.getOrNull() }
            .toList()
    } catch (e: Exception) {
        emptyList()
    }

    private fun write(entry: JournalEntry) {
        val w = writer ?: return
        try {
            w.write(json.encodeToString(JournalEntry.serializer(), entry))
            w.newLine()
            count++
        } catch (e: Exception) {
            runCatching { w.close() }
            writer = null
        }
    }

    private fun uniqueFile(dir: File): File {
        var i = 0
        while (true) {
            val f = File(dir, "journal_$i.jsonl")
            if (!f.exists()) return f
            i++
        }
    }

    companion object {
        /** Budget for the board's own console text in one journal. */
        const val MAX_OUTPUT_BYTES = 8_000_000L
    }
}

/** Minimal board identity a journal opening line needs (kept free of protocol types). */
data class DeviceInfoForJournal(val board: String, val fw: String, val proto: Int)
