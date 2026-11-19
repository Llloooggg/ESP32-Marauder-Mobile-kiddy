package com.marauder.mobile.crack

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Rate maths with a fake clock — the number the UI divides the ETA by must be
 * guesses per second over a window, never the cumulative guess count (that bug
 * made RATE read the same as TRIED and dropped the ETA to zero).
 *
 * A window closes on the sample whose elapsed time reaches the window length;
 * the window starts at the first sample of the run.
 */
class RateMeterTest {

    private class FakeClock(var at: Long = 0) : RateMeter.Clock {
        override fun nanoTime(): Long = at
        fun advance(nanos: Long) { at += nanos }
    }

    private val window = 1_000_000_000L

    @Test
    fun windowRateCountsOnlyTheGuessesMadeInThatWindow() {
        val clock = FakeClock()
        val meter = RateMeter(windowNanos = window, clock = clock)

        var last = RateMeter.Tick(0.0, false)
        repeat(100) { i ->
            if (i > 0) clock.advance(10_101_011)   // 99 steps ≈ 1 s of work
            last = meter.sample(1)
        }

        assertTrue("the window must close once a second of work is in it", last.newWindow)
        assertEquals(100.0, last.rate, 0.01)
        assertEquals(100.0, meter.overall(), 0.01)
    }

    @Test
    fun aSlowingDownSecondWindowIsNotReportedAsTheRunningTotal() {
        val clock = FakeClock()
        val meter = RateMeter(windowNanos = window, smoothing = 0.3, clock = clock)

        repeat(100) { i ->
            if (i > 0) clock.advance(10_101_011)
            meter.sample(1)
        }                                        // ~100 h/s
        var last = RateMeter.Tick(0.0, false)
        repeat(40) {
            clock.advance(25_000_002)
            last = meter.sample(1)
        }                                        // ~40 h/s

        assertTrue(last.newWindow)
        assertEquals(82.0, last.rate, 0.01)      // 0.7 * 100 + 0.3 * 40
        // The old code reported the cumulative count (140) as the rate here.
        assertTrue("rate must stay below the cumulative guess count", last.rate < 140.0)
        assertEquals(70.0, meter.overall(), 0.01)  // 140 guesses / 2 s
    }

    @Test
    fun nothingIsReportedBeforeTheFirstWindowCompletes() {
        val clock = FakeClock()
        val meter = RateMeter(windowNanos = window, clock = clock)

        repeat(10) { i ->
            if (i > 0) clock.advance(100_000_000)
            val t = meter.sample(1)
            assertEquals(0.0, t.rate, 0.0)
            assertTrue("sample ${i + 1} must not close the window", !t.newWindow)
        }
        clock.advance(100_000_000)
        val t = meter.sample(1)
        assertTrue(t.newWindow)
        assertEquals(11.0, t.rate, 0.01)         // 11 guesses in 1 s
        assertEquals(11, meter.total())
    }
}
