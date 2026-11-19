package com.marauder.mobile.data

import com.marauder.mobile.data.ScanLedger.ApPin
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pinning an operation to one BSSID on a firmware that only speaks list slots, and
 * where `select -a` toggles while the targeted attacks use *every* selected AP.
 */
class TargetLockTest {

    private fun pin(index: Int, bssid: String, essid: String, selected: Boolean = false) =
        ApPin(bssid = bssid, essid = essid, channel = 6, index = index, selected = selected, rssi = -40)

    @Test
    fun `selection filter quotes the name and survives spaces`() {
        assertEquals("'equals \"Home Wi-Fi\"'", TargetLock.selectionFilter("Home Wi-Fi"))
    }

    @Test
    fun `a name containing an apostrophe uses the mirrored quoting`() {
        assertEquals("\"equals 'Joe's Home'\"", TargetLock.selectionFilter("Joe's Home"))
    }

    @Test
    fun `names the firmware cannot take fall back to slots`() {
        assertNull(TargetLock.selectionFilter(""))            // hidden network
        assertNull(TargetLock.selectionFilter("   "))
        assertNull(TargetLock.selectionFilter("cat or dog"))  // the firmware's filter separator
        assertNull(TargetLock.selectionFilter("a\"b'c"))      // both quote kinds, no escapes
        assertNull(TargetLock.selectionFilter("bad\nname"))
    }

    @Test
    fun `the plan selects by name, not by the slot it happened to be in`() {
        val target = pin(1, "AA:BB:CC:DD:EE:02", "Home Wi-Fi")
        val list = listOf(pin(0, "AA:BB:CC:DD:EE:01", "Other"), target)

        val plan = TargetLock.plan(target, list)
        assertTrue(plan.byEssid)
        assertEquals(listOf("select -a 0 -f 'equals \"Home Wi-Fi\"'"), plan.commands)
    }

    @Test
    fun `same-named duplicates are pinned out by their live slots`() {
        val target = pin(0, "AA:BB:CC:DD:EE:01", "Cafe")
        val list = listOf(
            target,
            pin(1, "AA:BB:CC:DD:EE:02", "Cafe"),
            pin(2, "AA:BB:CC:DD:EE:03", "Cafe"),
            pin(3, "AA:BB:CC:DD:EE:04", " neighbour"),
        )

        val plan = TargetLock.plan(target, list)
        assertEquals(
            listOf(
                "select -a 0 -f 'equals \"Cafe\"'",
                "select -a 1",
                "select -a 2",
            ),
            plan.commands,
        )
        assertEquals(listOf("AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"), plan.duplicates)
    }

    @Test
    fun `hidden networks fall back to slots and clear other selections`() {
        val target = pin(2, "AA:BB:CC:DD:EE:05", "", selected = false)
        val list = listOf(
            pin(0, "AA:BB:CC:DD:EE:01", "First", selected = true),
            pin(1, "AA:BB:CC:DD:EE:02", "Second", selected = true),
            target,
        )

        val plan = TargetLock.plan(target, list)
        assertEquals(false, plan.byEssid)
        assertEquals(listOf("select -a 2", "select -a 0", "select -a 1"), plan.commands)
        assertNotNull(plan.fallbackReason)
    }

    @Test
    fun `verification rejects a target that ended up unselected`() {
        val list = listOf(
            pin(0, "AA:BB:CC:DD:EE:01", "Home Wi-Fi", selected = true),
            pin(1, "AA:BB:CC:DD:EE:02", "Home Wi-Fi"),
        )
        val outcome = TargetLock.verify("AA:BB:CC:DD:EE:02", "Home Wi-Fi", list)
        assertTrue(outcome is TargetLock.Outcome.TargetNotSelected)
    }

    @Test
    fun `verification rejects a foreign network left selected`() {
        val list = listOf(
            pin(0, "AA:BB:CC:DD:EE:01", "Home Wi-Fi", selected = true),
            pin(1, "AA:BB:CC:DD:EE:02", "Neighbours", selected = true),
        )
        val outcome = TargetLock.verify("AA:BB:CC:DD:EE:01", "Home Wi-Fi", list)
        assertTrue(outcome is TargetLock.Outcome.ExtraTargets)
        assertEquals(setOf("AA:BB:CC:DD:EE:02"), (outcome as TargetLock.Outcome.ExtraTargets).extras)
    }

    @Test
    fun `verification allows the target's own duplicate access points, and says so`() {
        val list = listOf(
            pin(0, "AA:BB:CC:DD:EE:01", "Cafe", selected = true),
            pin(1, "AA:BB:CC:DD:EE:02", "Cafe", selected = true),
        )
        val outcome = TargetLock.verify("AA:BB:CC:DD:EE:01", "Cafe", list)
        assertTrue(outcome is TargetLock.Outcome.Locked)
        assertEquals(setOf("AA:BB:CC:DD:EE:02"), (outcome as TargetLock.Outcome.Locked).duplicates)
    }

    @Test
    fun `a network the board forgot cannot be attacked`() {
        val outcome = TargetLock.verify("AA:BB:CC:DD:EE:09", "Gone", listOf(pin(0, "AA:BB:CC:DD:EE:01", "Here")))
        assertTrue(outcome is TargetLock.Outcome.TargetGone)
    }

    // --- clearing the selection (an untargeted sniff must not be blinded by it) -----

    @Test
    fun `the clear plan toggles exactly the selected slots and nothing else`() {
        val list = listOf(
            pin(0, "AA:BB:CC:DD:EE:01", "First", selected = true),
            pin(1, "AA:BB:CC:DD:EE:02", "Second"),
            pin(4, "AA:BB:CC:DD:EE:03", "Third", selected = true),
        )
        // `select -a` toggles, so a deselect command is the selected slots themselves.
        // The firmware splits that argument on "," (CommandLine.cpp:1837), so one write covers all.
        assertEquals(listOf("select -a 0,4"), TargetLock.clearPlan(list))
    }

    @Test
    fun `an already clear list needs no commands`() {
        assertEquals(emptyList<String>(), TargetLock.clearPlan(listOf(pin(0, "AA:BB:CC:DD:EE:01", "First"))))
    }

    @Test
    fun `stillSelected is what the caller re-reads to prove the clear landed`() {
        val before = listOf(
            pin(0, "AA:BB:CC:DD:EE:01", "First", selected = true),
            pin(1, "AA:BB:CC:DD:EE:02", "Second", selected = true),
        )
        assertEquals(setOf("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"), TargetLock.stillSelected(before))
        val after = listOf(
            pin(0, "AA:BB:CC:DD:EE:01", "First"),
            pin(1, "AA:BB:CC:DD:EE:02", "Second"),
        )
        assertEquals(emptySet<String>(), TargetLock.stillSelected(after))
    }
}
