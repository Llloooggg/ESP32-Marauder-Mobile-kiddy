package com.marauder.mobile.crack

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The arithmetic of a time left, and the two sentences that go with it.
 *
 * Both matter more than they look: a wordlist run is long, and the only number on the screen that
 * tells a user whether to wait or stop is this one. It is a division by a rate measured during the
 * same run, so the rules worth pinning are that it is linear in what remains, silent before a rate
 * exists, and honest about what a stopped run never paid for.
 */
class EtaTest {

    @Test
    fun noRateMeansNoEstimate() {
        assertNull(Eta.seconds(1_000_000, 0.0))
        assertNull(Eta.seconds(1_000_000, -1.0))
        // Nothing left is not "zero seconds left"; there is no time to estimate.
        assertNull(Eta.seconds(0, 5_000.0))
        assertNull(Eta.seconds(-5, 5_000.0))
    }

    @Test
    fun theEstimateIsLinearInTheRemainingCount() {
        // This is the whole reason a measured rate may be extrapolated at all: PBKDF2 costs 4096 rounds
        // wherever the guess sits in the list, so doubling what is left doubles the time.
        assertEquals(5L, Eta.seconds(5_000, 1_000.0))
        assertEquals(10L, Eta.seconds(10_000, 1_000.0))
        assertEquals(5L, Eta.seconds(10_000, 2_000.0))
    }

    @Test
    fun aShortRemainderIsStillNotZero() {
        // Rounding 0.4 s to 0 would read as "done", which is a different claim than a short wait.
        assertEquals(1L, Eta.seconds(1, 10_000.0))
    }

    @Test
    fun theBasisSentenceQuotesTheNumbersTheEstimateWasBuiltFrom() {
        val left = 5_000L
        val why = Eta.basis(left, 1_234.5)
        val leftText = String.format("%,d", left)
        val rateText = String.format("%,d", 1_235L)
        assertTrue(why, why.contains(leftText))
        assertTrue(why, why.contains(rateText))
        assertTrue(why, why.contains("4096"))
    }

    @Test
    fun aStoppedRunSaysWhatItNeverPaidFor() {
        val line = Eta.stopped(12_345L, 1_024)
        assertTrue(line, line.contains(String.format("%,d", 1_024)))
        assertTrue(line, line.contains("hashed"))
        assertFalse(line, line.contains("exhausted"))
    }

    @Test
    fun anEngineThatStopsBetweenWordsInventsNoBatch() {
        val line = Eta.stopped(7L, 0)
        assertFalse(line, line.contains("batch"))
        assertTrue(line, line.contains(String.format("%,d", 7L)))
    }

    @Test
    fun secondsForAgreesWithTheEstimate() {
        // MeasuredRate is the same maths on a measured sample; the two paths must not drift.
        val rate = MeasuredRate(1_000L, 1_000)
        val seconds = rate.secondsFor(5_000)!!
        assertNotNull(seconds)
        assertEquals(Eta.seconds(5_000, 1_000.0)!!, seconds.toLong())
    }
}
