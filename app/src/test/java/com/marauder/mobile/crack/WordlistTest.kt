package com.marauder.mobile.crack

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * Wordlists are user files: Notepad saves UTF-8 with a byte-order mark, other tools
 * save UTF-16. The mark is invisible on screen and must never become part of the first
 * candidate — that turns a correct password into a miss and says nothing about why.
 */
class WordlistTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun file(name: String, bytes: ByteArray): File =
        tmp.newFile(name).apply { writeBytes(bytes) }

    @Test
    fun utf8BomDoesNotStickToTheFirstWord() {
        val text = "59db65bd\nsecond\n"
        val f = file("bom.txt", byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()) + text.toByteArray())

        Wordlist.reader(f).use { r ->
            assertEquals("59db65bd", r.readLine())
            assertEquals("second", r.readLine())
            assertNull(r.readLine())
        }
        assertEquals(2L, Wordlist.count(f))
    }

    @Test
    fun utf16LittleEndianListIsDecoded() {
        val f = file("le.txt", "\uFEFFone\ntwo\n".toByteArray(Charsets.UTF_16LE))
        Wordlist.reader(f).use { r ->
            assertEquals("one", r.readLine())
            assertEquals("two", r.readLine())
        }
        assertEquals(2L, Wordlist.count(f))
    }

    @Test
    fun utf16BigEndianListIsDecoded() {
        val f = file("be.txt", "\uFEFFone\ntwo\n".toByteArray(Charsets.UTF_16BE))
        Wordlist.reader(f).use { r ->
            assertEquals("one", r.readLine())
            assertEquals("two", r.readLine())
        }
        assertEquals(2L, Wordlist.count(f))
    }

    @Test
    fun plainUtf8AndEmptyLinesBehaveAsBefore() {
        val f = file("plain.txt", "alpha\n\nbeta\n".toByteArray())
        Wordlist.reader(f).use { r ->
            assertEquals("alpha", r.readLine())
            assertEquals("", r.readLine())
            assertEquals("beta", r.readLine())
        }
        // The count is what the progress bar means: candidates actually hashed.
        assertEquals(2L, Wordlist.count(f))
    }
}
