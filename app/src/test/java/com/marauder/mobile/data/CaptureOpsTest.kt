package com.marauder.mobile.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The two firmware behaviours that silently blank a PMKID/EAPOL capture: a `-c` run that
 * keeps hopping, and a leftover selection that switches the sniffer into selected-only
 * mode. These assertions are the app's contract with the firmware tree
 * (CommandLine.cpp:1046-1077, WiFiScan.cpp:10616-10623, 10997-11006, 13028-13046).
 */
class CaptureOpsTest {

    @Test
    fun `a passive sniff pinned to a channel needs the hopping setting off`() {
        assertTrue(CaptureOps.needsHopOff("sniffpmkid -c 3"))
        assertTrue(CaptureOps.needsHopOff("sniffpmkid -c 11 -serial"))
    }

    @Test
    fun `an unpinned passive sniff keeps hopping, on purpose`() {
        // Bare `sniffpmkid` is meant to walk every channel: turning hopping off would
        // leave the board on whatever channel it last used.
        assertFalse(CaptureOps.needsHopOff("sniffpmkid"))
        assertFalse(CaptureOps.needsHopOff("sniffpmkid -serial"))
    }

    @Test
    fun `the deauth modes are not claimed to be stoppable by that setting`() {
        // `sniffpmkid -d` runs WIFI_SCAN_ACTIVE_EAPOL, which the ChanHop gate at
        // WiFiScan.cpp:10997 does not cover: claiming otherwise would be a promise the
        // firmware does not keep.
        assertFalse(CaptureOps.needsHopOff("sniffpmkid -d -c 3"))
        assertFalse(CaptureOps.needsHopOff("sniffpmkid -d -l -c 3"))
    }

    @Test
    fun `every untargeted sniff needs an empty selection`() {
        assertTrue(CaptureOps.needsEmptySelection("sniffpmkid"))
        assertTrue(CaptureOps.needsEmptySelection("sniffpmkid -c 3"))
        assertTrue(CaptureOps.needsEmptySelection("sniffpmkid -d"))
    }

    @Test
    fun `the list mode is the one that wants a selection instead`() {
        // `-l` is refused outright when nothing is selected (CommandLine.cpp:1051-1056),
        // so clearing the selection would break the run the user asked for.
        assertFalse(CaptureOps.needsEmptySelection("sniffpmkid -d -l"))
        assertFalse(CaptureOps.needsEmptySelection("sniffpmkid -l"))
    }

    @Test
    fun `only sniffpmkid is affected, not the other sniffs`() {
        assertFalse(CaptureOps.needsHopOff("sniffbeacon"))
        assertFalse(CaptureOps.needsEmptySelection("scanall"))
        assertFalse(CaptureOps.needsEmptySelection("attack -t deauth -c"))
    }

    @Test
    fun `the pinned channel is read back for the message shown to the user`() {
        assertEquals(3, CaptureOps.pinnedChannel("sniffpmkid -c 3"))
        assertEquals(0, CaptureOps.pinnedChannel("sniffpmkid"))
    }

    /**
     * `CommandLine::startScanFromCLI` never reads the arguments of the scan verbs it is
     * called with, so `-c` on them is thrown away. Verified against the firmware: the
     * function only prints a line and calls `StartScan(mode)`.
     */
    @Test
    fun `a scan verb other than sniffpmkid throws its channel flag away`() {
        assertTrue(CaptureOps.channelFlagIgnored("sniffbeacon -c 6"))
        assertTrue(CaptureOps.channelFlagIgnored("scanall -c 1"))
        assertFalse(CaptureOps.channelFlagIgnored("sniffbeacon"))
        assertFalse(CaptureOps.channelFlagIgnored("sniffpmkid -c 6"))
    }

    @Test
    fun `channel -s plus ChanHop holds a channel only for the gated modes`() {
        // WiFiScan::channelHop returns early for these modes when ChanHop is off, so
        // pinning the radio is a real pin for them.
        assertTrue(CaptureOps.channelPinWillHold("sniffbeacon -c 6"))
        assertTrue(CaptureOps.channelPinWillHold("sniffprobe -c 11"))
        assertTrue(CaptureOps.channelPinWillHold("sniffraw -c 1"))
        // These modes are not in that gate list: they hop whatever the setting says.
        assertTrue(CaptureOps.alwaysHops("scanall -c 6"))
        assertTrue(CaptureOps.alwaysHops("sniffsae -c 6"))
        assertTrue(CaptureOps.alwaysHops("sniffmultissid -c 6"))
        assertFalse(CaptureOps.alwaysHops("sniffbeacon -c 6"))
        assertFalse(CaptureOps.alwaysHops("scanall"))
    }

    @Test
    fun `sniffpmkid without -l hops no matter what the settings say`() {
        // WIFI_SCAN_ACTIVE_EAPOL is not in the ChanHop gate list (WiFiScan.cpp:10997-11006):
        // this is the mode that lost a client's M2 in a real run on our own AP, because the
        // board was on the target channel for the deauth and somewhere else on the rejoin.
        assertTrue(CaptureOps.unhoppableHopping("sniffpmkid -d -c 8"))
        assertTrue(CaptureOps.unhoppableHopping("sniffpmkid -c 8 -d -serial"))
        // `-l` confines the hop to the selected APs' channels, which is what holds the pin.
        assertFalse(CaptureOps.unhoppableHopping("sniffpmkid -d -l -c 8"))
        // No `-c`, nothing pinned, so nothing to be disappointed about.
        assertFalse(CaptureOps.unhoppableHopping("sniffpmkid -d"))
        // The passive mode is gated, and the app turns that setting off for it.
        assertFalse(CaptureOps.unhoppableHopping("sniffpmkid -c 8"))
    }

    @Test
    fun `the refusal wording matches what the firmware prints`() {
        // CommandLine.cpp:1053 — verified against the firmware source, not paraphrased.
        val firmwareLine = "You don't have any targets selected. Use select"
        assertTrue(firmwareLine.contains(CaptureOps.NO_TARGETS_SELECTED))
        val firmwareWriteFailure = "Could not successfully update setting \"ChanHop\""
        assertTrue(firmwareWriteFailure.contains(CaptureOps.SETTING_WRITE_FAILED))
    }

    // Who transmitted the EAPOL the board reported. The MAC in `Received EAPOL: <mac>` is addr2 —
    // the firmware reads the address at byte offset 10 of the frame (`WiFiScan.cpp:10639-10643`) —
    // so it names the transmitter, which is what tells a targeted run whether its client is talking.

    @Test
    fun `an EAPOL sent by the target network is the access point side`() {
        assertEquals(
            CaptureOps.EapolSide.ACCESS_POINT,
            CaptureOps.eapolSide("50:ff:20:90:5a:ef", "50:FF:20:90:5A:EF"),
        )
        assertEquals(
            CaptureOps.EapolSide.CLIENT,
            CaptureOps.eapolSide("b8:87:6e:08:c1:d8", "50:FF:20:90:5A:EF"),
        )
    }

    @Test
    fun `the field run of 246 ap-only frames reads as a silent client`() {
        // The exact shape of the 130 s run: the board printed the target's own BSSID over and over
        // and not one frame came from the client it was aimed at.
        val senders = mapOf("50:ff:20:90:5a:ef" to 246)
        assertEquals(CaptureOps.EapolSide.ACCESS_POINT, CaptureOps.eapolVerdict(senders, "50:FF:20:90:5A:EF"))
    }

    @Test
    fun `a single client frame changes the verdict`() {
        val senders = mapOf("50:ff:20:90:5a:ef" to 246, "b8:87:6e:08:c1:d8" to 1)
        assertEquals(CaptureOps.EapolSide.CLIENT, CaptureOps.eapolVerdict(senders, "50:FF:20:90:5A:EF"))
    }

    @Test
    fun `no verdict without a pinned target or without EAPOL`() {
        // The app does not claim a silent client when it cannot say which client should have
        // answered, and silence about EAPOL is not the same claim as EAPOL from one side.
        assertEquals(CaptureOps.EapolSide.UNKNOWN, CaptureOps.eapolVerdict(mapOf("50:ff:20:90:5a:ef" to 9), null))
        assertEquals(CaptureOps.EapolSide.UNKNOWN, CaptureOps.eapolVerdict(emptyMap(), "50:FF:20:90:5A:EF"))
        assertEquals(CaptureOps.EapolSide.UNKNOWN, CaptureOps.eapolSide("50:ff:20:90:5a:ef", ""))
    }
}
