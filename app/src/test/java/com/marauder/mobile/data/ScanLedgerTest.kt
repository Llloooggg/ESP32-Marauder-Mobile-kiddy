package com.marauder.mobile.data

import com.marauder.mobile.protocol.DeviceMessage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The firmware's list slots move; the ledger has to keep identity (BSSID) and
 * prove when an index stopped meaning what it used to.
 */
class ScanLedgerTest {

    private fun ap(index: Int, bssid: String, essid: String = "net", selected: Boolean = false) =
        DeviceMessage.Ap(
            index = index, channel = 6, rssi = -50, selected = selected, packets = 10,
            sec = 4, wps = false, stations = 0, bssid = bssid, essid = essid,
        )

    private fun sta(apSlot: Int, index: Int, mac: String) =
        DeviceMessage.Sta(ap = apSlot, index = index, selected = false, packets = 5, mac = mac)

    @Test
    fun `index drift is reported and old slots stop being trusted`() {
        val ledger = ScanLedger()
        // An empty list is a real snapshot too: filling it changes every slot.
        assertTrue(ledger.commitAps(listOf(ap(0, "AA:BB:CC:DD:EE:01"), ap(1, "AA:BB:CC:DD:EE:02"))))
        assertEquals(1, ledger.apGeneration)

        // A rescan put the second network first: slot 1 is now a different AP.
        assertTrue(ledger.commitAps(listOf(ap(0, "AA:BB:CC:DD:EE:02"), ap(1, "AA:BB:CC:DD:EE:01"))))
        assertEquals(2, ledger.apGeneration)
        assertEquals(1, ledger.indexOf("AA:BB:CC:DD:EE:01"))
        assertEquals("AA:BB:CC:DD:EE:02", ledger.bssidAt(0))
    }

    @Test
    fun `identical snapshot does not bump the generation`() {
        val ledger = ScanLedger()
        ledger.commitAps(listOf(ap(0, "AA:BB:CC:DD:EE:01"), ap(1, "AA:BB:CC:DD:EE:02")))
        assertFalse(ledger.commitAps(listOf(ap(0, "AA:BB:CC:DD:EE:01"), ap(1, "AA:BB:CC:DD:EE:02", essid = "renamed"))))
        assertEquals(1, ledger.apGeneration)
    }

    @Test
    fun `clients are attributed by bssid, and stay put when slots move`() {
        val ledger = ScanLedger()
        ledger.commitAps(listOf(ap(0, "AA:BB:CC:DD:EE:01"), ap(1, "AA:BB:CC:DD:EE:02")))
        // Slot 1's clients belong to ...EE:02 at this moment.
        ledger.commitStations(listOf(sta(apSlot = 1, index = 7, mac = "11:22:33:44:55:66")))
        assertTrue(ledger.stationsTrusted)
        assertEquals(
            listOf("11:22:33:44:55:66"),
            ledger.stationsOf("AA:BB:CC:DD:EE:02").map { it.mac },
        )
        assertEquals(emptyList<String>(), ledger.stationsOf("AA:BB:CC:DD:EE:01").map { it.mac })

        // Now the list re-orders: the mapping is no longer provable.
        ledger.commitAps(listOf(ap(0, "AA:BB:CC:DD:EE:02"), ap(1, "AA:BB:CC:DD:EE:01")))
        assertFalse(ledger.stationsTrusted)

        // Re-fetching clients against the new snapshot restores trust and keeps the
        // same attribution — the client is still on ...EE:02, whatever its slot is.
        ledger.commitStations(listOf(sta(apSlot = 0, index = 7, mac = "11:22:33:44:55:66")))
        assertTrue(ledger.stationsTrusted)
        assertEquals(
            listOf("11:22:33:44:55:66"),
            ledger.stationsOf("AA:BB:CC:DD:EE:02").map { it.mac },
        )
    }

    @Test
    fun `a network that left the list has no slot to send`() {
        val ledger = ScanLedger()
        ledger.commitAps(listOf(ap(0, "AA:BB:CC:DD:EE:01")))
        ledger.commitAps(listOf(ap(0, "AA:BB:CC:DD:EE:09")))
        assertNull(ledger.indexOf("AA:BB:CC:DD:EE:01"))
        assertNull(ledger.pin("aa:bb:cc:dd:ee:01"))
    }

    @Test
    fun `selection state and client slots come from the live snapshot`() {
        val ledger = ScanLedger()
        ledger.commitAps(
            listOf(
                ap(0, "AA:BB:CC:DD:EE:01", selected = true),
                ap(1, "AA:BB:CC:DD:EE:02"),
            ),
        )
        ledger.commitStations(listOf(sta(apSlot = 0, index = 3, mac = "11:22:33:44:55:66")))
        assertEquals(setOf("AA:BB:CC:DD:EE:01"), ledger.selectedBssids())
        assertEquals(3, ledger.stationIndex("11:22:33:44:55:66"))
        assertEquals("AA:BB:CC:DD:EE:01", ledger.stationOwner("11:22:33:44:55:66"))
    }

    @Test
    fun `clients whose ap slot is not in the snapshot are dropped instead of guessed`() {
        val ledger = ScanLedger()
        ledger.commitAps(listOf(ap(0, "AA:BB:CC:DD:EE:01")))
        ledger.commitStations(listOf(sta(apSlot = 5, index = 1, mac = "11:22:33:44:55:66")))
        assertTrue(ledger.stationsByBssid.isEmpty())
    }
}
