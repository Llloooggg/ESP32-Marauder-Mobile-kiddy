package com.marauder.mobile.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * A session that wrote nothing must leave nothing behind.
 *
 * The library used to carry rows like `journal 3 · 0 B`: files the app created because a connection
 * opened, and then had nothing to say. They looked like things to look at, and they were not - and
 * because the journal numbers are chosen by scanning what exists, the empty files also burned numbers.
 *
 * The rule here is deliberately narrow: an empty file is dropped, a file with one entry is kept whole.
 * Trimming a journal that has content would be hiding evidence; deleting a file with no evidence in it
 * is not hiding anything.
 */
class JournalEmptySessionTest {

    private fun tempDir(): File = File(System.getProperty("java.io.tmpdir"), "mk-journal-${System.nanoTime()}")

    @Test
    fun `a connection that produced nothing leaves no file`() {
        val dir = tempDir()
        val j = Journal(dir)
        val opened = j.open(null)
        assertNotNull("opening a journal must give a file to write into", opened)
        val summary = j.close()
        assertNull("nothing was written, so there is nothing to register: $summary", summary)
        assertTrue("the empty file must be gone: ${dir.list()?.toList()}", !opened!!.exists())
        dir.delete()
    }

    @Test
    fun `a connection that told us which board it is keeps that record`() {
        // The empty rule must not eat the one line that says a session happened and on what board.
        val dir = tempDir()
        val j = Journal(dir)
        j.open(DeviceInfoForJournal("ESP32-S3", "1.20.0", 3))
        val summary = j.close()
        assertNotNull("a journal that records the connection must survive: $summary", summary)
        assertEquals(1, summary!!.entries)
        assertTrue(j.read(summary.file).any { it.meta["board"] == "ESP32-S3" })
        dir.delete()
    }

    @Test
    fun `a session with one entry is kept whole`() {
        val dir = tempDir()
        val j = Journal(dir)
        val opened = j.open(null)
        assertNotNull(opened)
        j.record(JournalEntry.NOTE, "one thing worth keeping")
        val summary = j.close()
        assertNotNull("a journal with content must survive: $summary", summary)
        assertEquals(1, summary!!.entries)
        val entries = j.read(summary.file)
        assertEquals(1, entries.size)
        assertEquals("one thing worth keeping", entries.first().text)
        dir.delete()
    }

    @Test
    fun `journal numbers are not burned by sessions that wrote nothing`() {
        // The file name is chosen by looking at what already exists, so an empty file that is dropped
        // must not also cost its number to nothing.
        val dir = tempDir()
        val j = Journal(dir)
        repeat(3) {
            j.open(null)
            j.close()
        }
        val kept = dir.listFiles()?.map { it.name } ?: emptyList()
        assertTrue("no empty journals may remain: $kept", kept.isEmpty())
        j.open(null)
        j.record(JournalEntry.NOTE, "first real session")
        val first = j.close()!!
        assertTrue(
            "the first journal with content must be the first number: ${first.file.name}",
            Regex("journal_\\d+\\.jsonl").matches(first.file.name),
        )
        assertEquals(
            "exactly one journal file may exist: ${dir.list()?.toList()}",
            1,
            dir.listFiles()?.size ?: 0,
        )
        dir.delete()
    }

    @Test
    fun `closing twice does not invent a summary`() {
        val dir = tempDir()
        val j = Journal(dir)
        j.open(null)
        j.record(JournalEntry.COMMAND, "scanall")
        assertNotNull(j.close())
        assertNull("a closed journal has nothing more to report", j.close())
        dir.delete()
    }
}
