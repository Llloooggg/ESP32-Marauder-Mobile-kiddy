package com.marauder.mobile.crack

/**
 * Guess-rate estimate for a running crack.
 *
 * The rate the UI shows must be guesses-per-second over a *window*, not the
 * cumulative guess count divided by that window: dividing the running total by
 * a one-second window makes the chip read "rate == tried" (which then collapses
 * every ETA to zero — the bug this class exists to prevent).
 *
 * [Clock] is injectable so the maths can be tested without sleeping.
 */
class RateMeter(
    private val windowNanos: Long = DEFAULT_WINDOW_NANOS,
    private val smoothing: Double = 0.3,
    private val clock: Clock = SystemNanoClock,
) {

    private var started = false
    private var startedAt = 0L
    private var windowStart = 0L
    private var windowGuesses = 0L
    private var totalGuesses = 0L
    private var smoothed = 0.0

    /**
     * Adds [guesses] work units. [Tick.rate] is the current estimate (0 until the
     * first window completes) and [Tick.newWindow] marks the sample that closed a
     * window — that is when a UI should publish progress.
     */
    fun sample(guesses: Long): Tick {
        val now = clock.nanoTime()
        if (!started) {                  // a clock that reads 0 is legitimate, so
            started = true               // the "first sample" flag cannot be a value
            startedAt = now
            windowStart = now
        }
        totalGuesses += guesses
        windowGuesses += guesses
        val elapsed = now - windowStart
        if (elapsed < windowNanos) return Tick(smoothed, false)
        val windowRate = windowGuesses * NANOS_PER_SECOND.toDouble() / elapsed
        smoothed = if (smoothed <= 0.0) windowRate
        else smoothed * (1.0 - smoothing) + windowRate * smoothing
        windowStart = now
        windowGuesses = 0L
        return Tick(smoothed, true)
    }

    /**
     * Average over the whole run: steadier than the window estimate, which is
     * what an ETA wants (a phone throttles, so the window jumps around).
     */
    fun overall(): Double {
        if (!started) return 0.0
        val elapsed = (clock.nanoTime() - startedAt).coerceAtLeast(1L)
        return totalGuesses * NANOS_PER_SECOND.toDouble() / elapsed
    }

    /** Work units counted so far. */
    fun total(): Long = totalGuesses

    fun reset() {
        started = false
        startedAt = 0L
        windowStart = 0L
        windowGuesses = 0L
        totalGuesses = 0L
        smoothed = 0.0
    }

    /** One window's outcome, as returned by [sample]. */
    data class Tick(val rate: Double, val newWindow: Boolean)

    fun interface Clock {
        fun nanoTime(): Long
    }

    companion object {
        const val DEFAULT_WINDOW_NANOS = 1_000_000_000L
        private const val NANOS_PER_SECOND = 1_000_000_000L
    }
}

object SystemNanoClock : RateMeter.Clock {
    override fun nanoTime(): Long = System.nanoTime()
}
