package com.marauder.mobile.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream

/** JVM tests for the wordlist library (naming, counting, de-duplication). */
class WordlistStoreTest {

    @get:Rule
    val folder = TemporaryFolder()

    private fun store() = WordlistStore(folder.root)

    @Test
    fun sanitizesHostileNames() {
        // A URL or path contributes only its last segment, then everything unsafe collapses.
        assertEquals("passwd.txt", WordlistStore.sanitize("../../etc/passwd"))
        assertEquals(
            "probable-v2-wpa-top4800.txt",
            WordlistStore.sanitize("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt"),
        )
        assertEquals("bad.txt", WordlistStore.sanitize("C:\\win\\bad?.txt"))
        assertEquals("wordlist.txt", WordlistStore.sanitize("   "))
        assertEquals("x.txt", WordlistStore.sanitize("x"))
        val long = WordlistStore.sanitize("a".repeat(200) + ".txt")
        assertTrue("capped name fits on disk: $long", long.length <= 64)
        assertTrue(long.endsWith(".txt"))
    }

    @Test
    fun installsCountsAndKeepsNamesUnique() {
        val s = store()
        val first = s.install("rockyou.txt", ByteArrayInputStream("a\nb\nc".toByteArray()))!!
        assertEquals(3L, first.lines)   // no trailing newline still counts the last line
        assertEquals("rockyou.txt", first.fileName)

        val second = s.install("rockyou.txt", ByteArrayInputStream("x\n".toByteArray()))!!
        assertEquals("rockyou-2.txt", second.fileName)
        assertEquals(1L, second.lines)
        assertEquals(2, s.list().size)
    }

    @Test
    fun emptyUploadsAreRejected() {
        val s = store()
        val w = s.install("empty.txt", ByteArrayInputStream(ByteArray(0)))
        assertEquals(null, w)
        assertTrue(s.list().isEmpty())
    }

    @Test
    fun licenceNotesAreNotTreatedAsWordlists() {
        java.io.File(folder.root, "LICENSE-SecLists-MIT.txt").writeText("MIT")
        store().install("builtin-probable.txt", ByteArrayInputStream("pass\n".toByteArray()))
        val items = store().list()
        assertEquals(1, items.size)
        assertTrue(items[0].builtin)
        assertEquals("probable", items[0].label)
    }

    @Test
    fun seedingHappensOnceUntilCleared() {
        val s = store()
        assertFalse(s.isSeeded())
        s.markSeeded()
        assertTrue(s.isSeeded())
        s.clearSeeded()
        assertFalse(s.isSeeded())
        assertEquals(0, s.list().size)   // the marker itself is never listed
    }

    @Test
    fun deletedFilesDisappearFromTheListing() {
        val s = store()
        val w = s.install("one.txt", ByteArrayInputStream("a\n".toByteArray()))
        assertNotNull(w)
        s.delete(w!!.fileName)
        assertTrue(s.list().isEmpty())
    }
}
