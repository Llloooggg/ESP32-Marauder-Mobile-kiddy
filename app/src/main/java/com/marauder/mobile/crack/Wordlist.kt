package com.marauder.mobile.crack

import java.io.BufferedInputStream
import java.io.BufferedReader
import java.io.File

/**
 * One reader for every engine's wordlist.
 *
 * Lists arrive from wherever the user got them. Notepad writes UTF-8 with a
 * byte-order mark, some tools write UTF-16, phones write plain UTF-8. A mark left in
 * front of the first word is invisible on screen and turns `password` into
 * `\uFEFFpassword` for the hasher: the list is right and its first candidate is not,
 * which looks exactly like "the password is wrong".
 *
 * The four cracking paths (JVM, native CPU, native GPU — and their word counts) must
 * agree on what a word is, so they share this reader rather than each opening the file
 * its own way.
 */
internal object Wordlist {

    /** Opens [file] with its byte-order mark consumed and the matching charset. */
    fun reader(file: File): BufferedReader {
        val input = BufferedInputStream(file.inputStream(), BUFFER)
        input.mark(3)
        val b0 = input.read()
        val b1 = input.read()
        val b2 = input.read()
        input.reset()
        val charset = when {
            b0 == 0xFF && b1 == 0xFE -> { input.skip(2); Charsets.UTF_16LE }
            b0 == 0xFE && b1 == 0xFF -> { input.skip(2); Charsets.UTF_16BE }
            b0 == 0xEF && b1 == 0xBB && b2 == 0xBF -> { input.skip(3); Charsets.UTF_8 }
            else -> Charsets.UTF_8
        }
        return input.reader(charset).buffered(BUFFER)
    }

    /** Non-empty lines: exactly what the engines hash and what the progress count means. */
    fun count(file: File): Long = reader(file).use { r ->
        var n = 0L
        while (true) {
            val line = r.readLine() ?: break
            if (line.isNotEmpty()) n++
        }
        n
    }

    private const val BUFFER = 64 * 1024
}
