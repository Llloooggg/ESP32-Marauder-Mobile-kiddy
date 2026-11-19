package com.marauder.mobile.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipFile

/**
 * JVM tests for the session journal and the report it feeds: JSONL round-trip,
 * the output budget, and the markdown + zip archive layout.
 */
class JournalReportTest {

    @get:Rule
    val folder = TemporaryFolder()

    @Test
    fun journalRoundTripKeepsOrderAndFields() {
        val j = Journal(folder.root)
        val file = j.open(DeviceInfoForJournal("ESP32-S3", "1.20.0-jsonserial", 3))
        assertNotNull(file)
        j.record(JournalEntry.COMMAND, "> sniffpmkid -d -l", mapOf("command" to "sniffpmkid -d -l"))
        j.record(JournalEntry.CRED, "portal credential", mapOf("user" to "admin", "pass" to "hunter2"))
        j.output("Received EAPOL: aa:bb:cc:dd:ee:ff")
        val summary = j.close()
        assertNotNull(summary)
        assertEquals(4, summary!!.entries)
        val entries = j.read(summary!!.file)
        assertEquals(
            listOf(JournalEntry.SESSION, JournalEntry.COMMAND, JournalEntry.CRED, JournalEntry.OUTPUT),
            entries.map { it.kind },
        )
        assertEquals("hunter2", entries.first { it.kind == JournalEntry.CRED }.meta["pass"])
        assertEquals("3", entries.first { it.kind == JournalEntry.SESSION }.meta["proto"])
    }

    @Test
    fun outputBudgetKeepsCommandsAndFlagsTruncation() {
        val j = Journal(folder.root, maxOutputBytes = 40)
        j.open(null)
        repeat(50) { j.output("chatty board line $it") }
        j.record(JournalEntry.COMMAND, "> stopscan")
        val summary = j.close()!!

        assertTrue(summary.truncated)
        val entries = j.read(summary.file)
        assertTrue(entries.count { it.kind == JournalEntry.OUTPUT } < 50)
        assertTrue(entries.any { it.kind == JournalEntry.COMMAND })
        assertTrue(entries.any { it.kind == JournalEntry.NOTE && it.text.startsWith("console output truncated") })
    }

    @Test
    fun markdownCarriesMissionsCredsAndCrackedResults() {
        val journal = listOf(
            JournalEntry(1_000, JournalEntry.SESSION, "connected: ESP32-S3",
                mapOf("board" to "ESP32-S3", "fw" to "1.20.0", "proto" to "3")),
            JournalEntry(2_000, JournalEntry.MISSION, "start: Capture handshake",
                mapOf("event" to "start", "command" to "sniffpmkid -d -l", "kind" to "CAPTURE",
                    "target_essid" to "Kitchen", "target_bssid" to "aa:bb:cc:dd:ee:ff", "target_channel" to "6")),
            JournalEntry(12_000, JournalEntry.MISSION, "stop: Capture handshake",
                mapOf("event" to "stop", "command" to "sniffpmkid -d -l", "seconds" to "10", "artifact" to "sniffpmkid_0.pcap")),
            JournalEntry(13_000, JournalEntry.CRED, "portal credential", mapOf("user" to "u", "pass" to "p")),
        )
        val md = ReportBuilder.markdown(
            ReportInput(
                appVersion = "1.4.0",
                board = DeviceInfoForJournal("ESP32-S3", "1.20.0", 3),
                journal = journal,
                artifacts = listOf(
                    ReportArtifact("sniffpmkid_0.pcap", "Capture handshake", "pcap", 12_000, 4096,
                        ArtifactRecord.HASH_DONE,
                        mapOf("pmkid" to "1", "handshakes" to "2", "hashLines" to "3", "cracked" to "hunter2")),
                ),
            ),
        )
        assertTrue(md.contains("Kitchen"))                      // target table
        assertTrue(md.contains("sniffpmkid -d -l"))             // mission command
        assertTrue(md.contains("hunter2"))                      // cracked passphrase
        assertTrue(md.contains("Recovered passphrases"))
        assertTrue(md.contains("Captured portal credentials"))
        assertTrue(md.contains("Authorised use only"))
        assertFalse(md.contains("null"))
    }

    @Test
    fun zipHoldsMarkdownJournalsCapturesAndHashes() {
        val pcap = File(folder.root, "sniffpmkid_0.pcap").apply { writeBytes(byteArrayOf(1, 2, 3, 4)) }
        val hashes = File(folder.root, "sniffpmkid_0.pcap.22000.txt").apply { writeText("WPA*01*x") }
        val journalFile = File(folder.root, "journal_0.jsonl").apply { writeText("{}\n") }

        val input = ReportInput(
            artifacts = listOf(ReportArtifact(pcap.name, "cap", "pcap", 0, 4, ArtifactRecord.HASH_DONE, emptyMap())),
            files = mapOf(pcap.name to pcap),
            hashSidecars = mapOf(pcap.name to hashes),
            journals = listOf(journalFile),
        )
        val target = File(folder.root, "report_0.zip")
        val result = ReportBuilder.writeZip(target, input, "# report")

        assertTrue(target.exists())
        ZipFile(target).use { zip ->
            val names = zip.entries().toList().map { it.name }
            assertTrue(names.contains("report.md"))
            assertTrue(names.contains("journal/journal_0.jsonl"))
            assertTrue(names.contains("captures/${pcap.name}"))
            assertTrue(names.contains("hashes/${pcap.name}.22000.txt"))
            assertEquals(4, result?.entries)
        }
    }
}
