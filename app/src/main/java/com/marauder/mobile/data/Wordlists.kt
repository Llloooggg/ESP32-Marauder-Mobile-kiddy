package com.marauder.mobile.data

import java.io.File
import java.io.InputStream
import java.io.OutputStream

/** One wordlist file the cracker can use. */
data class Wordlist(
    val fileName: String,
    val label: String,
    val createdAt: Long,
    val bytes: Long,
    val lines: Long,
    val builtin: Boolean,
)

/**
 * File-backed library of cracking wordlists (one plain-text file each, one guess
 * per line). Deliberately free of Android types so the naming, counting and
 * de-duplication logic runs as a plain JVM unit test.
 */
class WordlistStore(private val dir: File) {

    fun list(): List<Wordlist> {
        dir.mkdirs()
        val files = dir.listFiles()?.filter { it.isFile && isWordlistName(it.name) } ?: emptyList()
        return files.map { f ->
            Wordlist(
                fileName = f.name,
                label = f.nameWithoutExtension.removePrefix(BUILTIN_PREFIX).replace('_', ' '),
                createdAt = f.lastModified(),
                bytes = f.length(),
                lines = countLines(f),
                builtin = f.name.startsWith(BUILTIN_PREFIX),
            )
        }.sortedWith(compareByDescending<Wordlist> { it.builtin }.thenByDescending { it.lines })
    }

    fun file(fileName: String): File = File(dir, fileName)

    fun exists(fileName: String): Boolean = file(fileName).let { it.isFile && it.length() > 0 }

    /**
     * Copy [input] into the library under a safe, unique name derived from
     * [preferredName]. Returns the stored record, or null when the payload is empty.
     */
    fun install(preferredName: String, input: InputStream): Wordlist? {
        val base = sanitize(preferredName)
        val target = uniqueFile(base)
        var written = 0L
        var lines = 0L
        var lastWasNewline = true
        try {
            target.outputStream().use { out: OutputStream ->
                val buf = ByteArray(16 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    for (i in 0 until n) {
                        if (buf[i] == '\n'.code.toByte()) lines++
                    }
                    lastWasNewline = buf[n - 1] == '\n'.code.toByte()
                    written += n
                }
            }
        } catch (e: Exception) {
            runCatching { target.delete() }
            return null
        }
        if (written == 0L) {
            runCatching { target.delete() }
            return null
        }
        if (!lastWasNewline) lines++   // a final line without a trailing newline still counts
        return Wordlist(
            fileName = target.name,
            label = target.nameWithoutExtension.removePrefix(BUILTIN_PREFIX).replace('_', ' '),
            createdAt = target.lastModified(),
            bytes = written,
            lines = lines,
            builtin = target.name.startsWith(BUILTIN_PREFIX),
        )
    }

    fun delete(fileName: String) {
        runCatching { file(fileName).delete() }
    }

    /** First-run bookkeeping: the built-in list is copied exactly once per install. */
    fun isSeeded(): Boolean = File(dir, SEED_MARKER).exists()

    fun markSeeded() {
        dir.mkdirs()
        runCatching { File(dir, SEED_MARKER).writeText("ok") }
    }

    fun clearSeeded() {
        runCatching { File(dir, SEED_MARKER).delete() }
    }

    /** Free disk space (bytes) the store's partition can still take. */
    fun usableSpace(): Long = runCatching { dir.usableSpace }.getOrDefault(0L)

    private fun uniqueFile(base: String): File {
        dir.mkdirs()
        val stem = base.removeSuffix(".txt")
        var candidate = File(dir, "$stem.txt")
        var index = 2
        while (candidate.exists()) {
            candidate = File(dir, "$stem-$index.txt")
            index++
        }
        return candidate
    }

    private fun isWordlistName(name: String): Boolean =
        name.endsWith(".txt", ignoreCase = true) && !name.startsWith("LICENSE", ignoreCase = true)

    companion object {
        private const val SEED_MARKER = ".seeded"

        /** Marks the shipped list so the UI can show it as built-in (and never lose it silently). */
        const val BUILTIN_PREFIX = "builtin-"

        /**
         * Turns an arbitrary file name (from SAF or a URL) into something safe to
         * write: the `.txt` extension is handled separately, everything that is not
         * a letter, digit, `-` or `_` becomes `_`, runs collapse, and long names are
         * capped so deep URL paths still fit on disk.
         */
        fun sanitize(raw: String): String {
            val base = raw.substringAfterLast('/').substringAfterLast('\\')
            val stemRaw = if (base.endsWith(".txt", ignoreCase = true)) base.dropLast(4) else base
            val stem = stemRaw
                .map { if (it.isLetterOrDigit() || it == '-' || it == '_') it else '_' }
                .joinToString("")
                .replace(Regex("_{2,}"), "_")
                .trim('_')
            val withExt = if (stem.isEmpty()) "wordlist.txt" else "$stem.txt"
            return if (withExt.length > 64) withExt.take(58) + ".txt" else withExt
        }

        /** Counts newline-terminated lines without holding the file in memory. */
        fun countLines(file: File): Long {
            if (!file.isFile) return 0L
            var lines = 0L
            var lastWasNewline = true
            runCatching {
                file.inputStream().use { input ->
                    val buf = ByteArray(16 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        for (i in 0 until n) if (buf[i] == '\n'.code.toByte()) lines++
                        lastWasNewline = buf[n - 1] == '\n'.code.toByte()
                    }
                }
            }
            return if (lastWasNewline) lines else lines + 1
        }
    }
}
