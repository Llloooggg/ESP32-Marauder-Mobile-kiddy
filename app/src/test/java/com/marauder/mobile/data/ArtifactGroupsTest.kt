package com.marauder.mobile.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * How the library separates what a cracker works on from what the app wrote about itself.
 *
 * The grouping rule belongs in one place, so that the screen and any later filter cannot drift into
 * disagreeing about which file is which. Two of these tests exist to stop a specific wrongness: an
 * unknown kind being promised to a group it was never asked about. That mistake would show up on
 * screen as a file sitting under a heading that misdescribes it - the app claiming something it has
 * not checked.
 */
class ArtifactGroupsTest {

    private fun artifact(name: String, kind: String) =
        Artifact(ArtifactRecord(name = name, createdAt = 1L, kind = kind), File(name))

    @Test
    fun `a file that a cracker or a mapping tool can work on is a capture`() {
        for (kind in listOf("pcap", "gpx", "csv")) {
            assertEquals("$kind belongs with captures", ArtifactGroup.CAPTURES, ArtifactGroups.of(kind))
        }
    }

    @Test
    fun `what the app wrote about its own run is a note`() {
        for (kind in listOf("jsonl", "json", "log", "txt")) {
            assertEquals("$kind belongs with notes", ArtifactGroup.NOTES, ArtifactGroups.of(kind))
        }
    }

    @Test
    fun `the kind does not have to be spelled the way we wrote it`() {
        // The kind comes from a stored record and from file names that older versions wrote.
        assertEquals(ArtifactGroup.CAPTURES, ArtifactGroups.of("PCAP"))
        assertEquals(ArtifactGroup.NOTES, ArtifactGroups.of("JsonL"))
    }

    @Test
    fun `an unknown kind is not promised to either group`() {
        assertEquals(ArtifactGroup.OTHER, ArtifactGroups.of("hap"))
        assertEquals(ArtifactGroup.OTHER, ArtifactGroups.of(""))
    }

    @Test
    fun `captures come first, the app's own records follow, and nothing is lost`() {
        val items = listOf(
            artifact("journal.jsonl", "jsonl"),
            artifact("field.pcap", "pcap"),
            artifact("wardrive.csv", "csv"),
            artifact("session.log", "log"),
            artifact("odd.hap", "hap"),
        )
        val groups = ArtifactGroups.ordered(items)
        assertEquals(
            "expected captures, then notes, then the rest: $groups",
            listOf(ArtifactGroup.CAPTURES, ArtifactGroup.NOTES, ArtifactGroup.OTHER),
            groups.map { it.first },
        )
        val shown = groups.flatMap { it.second }.map { it.record.name }.toSet()
        assertEquals("every file must still be reachable", items.map { it.record.name }.toSet(), shown)
    }

    @Test
    fun `the order inside a group is the order the listing gave us`() {
        // Newest-first is decided where the files are listed. Grouping must not answer that question
        // a second time, differently.
        val items = listOf(
            artifact("newer.pcap", "pcap"),
            artifact("older.pcap", "pcap"),
        )
        val captures = ArtifactGroups.ordered(items).first { it.first == ArtifactGroup.CAPTURES }.second
        assertEquals(listOf("newer.pcap", "older.pcap"), captures.map { it.record.name })
    }

    @Test
    fun `an empty group gets no heading`() {
        val groups = ArtifactGroups.ordered(listOf(artifact("a.pcap", "pcap")))
        assertTrue("only the group with files may appear: $groups", groups.size == 1)
    }

    @Test
    fun `the headings name their group and count it`() {
        assertTrue(ArtifactGroups.label(ArtifactGroup.CAPTURES, 3).contains("3"))
        assertTrue(ArtifactGroups.label(ArtifactGroup.CAPTURES, 3).contains("Capture"))
        // The app's own files must not be labelled as captures - that would promise a cracker's work.
        val notes = ArtifactGroups.label(ArtifactGroup.NOTES, 2)
        assertTrue(notes.contains("2"))
        assertTrue("the note heading must not read like a capture: $notes", !notes.startsWith("Capture"))
    }
}
