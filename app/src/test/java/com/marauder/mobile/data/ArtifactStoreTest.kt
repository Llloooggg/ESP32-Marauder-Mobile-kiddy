package com.marauder.mobile.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/** JVM round-trips for the capture-library index (no Android deps needed). */
class ArtifactStoreTest {

    @get:Rule
    val folder = TemporaryFolder()

    private fun store() = ArtifactStore(folder.root)

    @Test
    fun discoversUnknownFiles() {
        File(folder.root, "sniffpmkid_0.pcap").writeBytes(byteArrayOf(1, 2, 3))
        File(folder.root, "tracker_0.gpx").writeText("<gpx/>")
        File(folder.root, "notes.txt").writeText("ignored")

        val items = store().list()
        assertEquals(setOf("sniffpmkid_0.pcap", "tracker_0.gpx"), items.map { it.record.name }.toSet())
        assertEquals("pcap", items.first { it.record.name.endsWith(".pcap") }.record.kind)
    }

    @Test
    fun indexRoundTripAndUpsert() {
        val s = store()
        val f = File(folder.root, "capture_0.pcap").apply { writeText("x") }
        s.upsert(ArtifactRecord(name = f.name, createdAt = 100, title = "Kitchen AP", kind = "pcap"))

        val got = store().get(f.name)!!
        assertEquals("Kitchen AP", got.record.title)

        // upsert with the same name replaces, not duplicates
        s.upsert(ArtifactRecord(name = f.name, createdAt = 100, title = "Renamed", kind = "pcap"))
        assertEquals(1, store().list().size)
        assertEquals("Renamed", store().get(f.name)!!.record.title)
    }

    @Test
    fun deleteRemovesFileAndRecord() {
        val s = store()
        val f = File(folder.root, "gone_0.pcap").apply { writeText("x") }
        s.upsert(ArtifactRecord(name = f.name, createdAt = 1, kind = "pcap"))
        s.delete(f.name)
        assertNull(store().get(f.name))
        assertNull("file should be removed", if (f.exists()) f else null)
        assertEquals(0, store().list().size)
    }

    @Test
    fun corruptIndexRebuildsFromDisk() {
        val f = File(folder.root, "keep_0.pcap").apply { writeText("x") }
        store().upsert(ArtifactRecord(name = f.name, createdAt = 5, title = "T", kind = "pcap"))
        File(folder.root, ".artifacts-index.json").writeText("{{{not json")

        val items = store().list()
        assertEquals(1, items.size)
        assertEquals(f.name, items[0].record.name)
        assertNotNull(items[0].record.kind)
    }

    @Test
    fun indexEntriesForMissingFilesArePruned() {
        val s = store()
        val f = File(folder.root, "temp_0.pcap").apply { writeText("x") }
        s.upsert(ArtifactRecord(name = f.name, createdAt = 7, kind = "pcap"))
        f.delete()
        assertEquals(0, store().list().size)
    }
}
