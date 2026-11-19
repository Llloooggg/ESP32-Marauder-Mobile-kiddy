package com.marauder.mobile.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A capture aimed at one BSSID can hold another network's material; that must be visible. */
class CaptureAttributionTest {

    @Test
    fun `no aim recorded means nothing to compare`() {
        assertEquals(CaptureAttribution.Verdict.Unaimed, CaptureAttribution.verdict(null, listOf("AA:BB:CC:DD:EE:01")))
        assertEquals(CaptureAttribution.Verdict.Unaimed, CaptureAttribution.verdict("  ", listOf("AA:BB:CC:DD:EE:01")))
        assertNull(CaptureAttribution.explain(CaptureAttribution.Verdict.Unaimed))
    }

    @Test
    fun `an empty capture is unknown, not a mismatch`() {
        // Saying "wrong network" when nothing was extracted at all would be a lie:
        // the honest answer is "we cannot tell".
        assertEquals(CaptureAttribution.Verdict.Unknown, CaptureAttribution.verdict("AA:BB:CC:DD:EE:01", emptyList()))
        assertNull(CaptureAttribution.explain(CaptureAttribution.Verdict.Unknown))
    }

    @Test
    fun `the aimed network matching clears it, case-insensitively`() {
        val verdict = CaptureAttribution.verdict("aa:bb:cc:dd:ee:01", listOf("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"))
        assertEquals(CaptureAttribution.Verdict.Match, verdict)
        assertNull(CaptureAttribution.explain(verdict))
    }

    @Test
    fun `material from other networks is reported as a mismatch, naming both sides`() {
        val verdict = CaptureAttribution.verdict(
            "AA:BB:CC:DD:EE:01",
            listOf("aa:bb:cc:dd:ee:09", "AA:BB:CC:DD:EE:07"),
        )
        assertTrue(verdict is CaptureAttribution.Verdict.Mismatch)
        val explanation = CaptureAttribution.explain(verdict)!!
        assertTrue(explanation.contains("AA:BB:CC:DD:EE:01"))
        assertTrue(explanation.contains("AA:BB:CC:DD:EE:09"))
        assertTrue(explanation.contains("AA:BB:CC:DD:EE:07"))
    }
}
