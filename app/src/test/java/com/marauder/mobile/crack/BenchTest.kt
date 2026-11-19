package com.marauder.mobile.crack

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The arithmetic behind a throughput figure, and the rule `AUTO` uses to pick an engine.
 *
 * Both are pure functions on purpose: a rate that came from a sample nobody can name, and a backend
 * chosen by a branch nobody can read, are the two ways a cracker ends up reporting a number or a
 * capability that the device never supported.
 */
class BenchTest {

    @Test
    fun rateIsLinearInSampleSize() {
        val rate = measuredRate(1024, 1_000_000_000L)!!
        assertEquals(1024L, rate.guessesPerSecond)
        // The whole point of measuring a short sample: N guesses take N/rate seconds, so an ETA can
        // be extrapolated from it. If this arithmetic drifts, every "about 3 h left" is wrong.
        assertEquals(10.0, rate.secondsFor(10_240)!!, 0.0001)
        assertEquals(1024, rate.samples)
    }

    @Test
    fun tinySamplesAreRefusedInsteadOfReported() {
        // A rate over a handful of guesses is mostly launch overhead. Refusing it is what stops a
        // driver setup cost from being presented as throughput.
        assertNull(measuredRate(MIN_SAMPLES - 1, 1_000_000L))
        assertNull(measuredRate(1, 1_000_000_000L))
        assertNotNull(measuredRate(MIN_SAMPLES, 1_000_000L))
    }

    @Test
    fun aClockThatDidNotMoveCannotProduceARate() {
        // Dividing by a coerced 1 ns would report billions of guesses per second: confident-looking,
        // and a lie. The same goes for a clock that went backwards.
        assertNull(measuredRate(BENCH_GUESSES, 0L))
        assertNull(measuredRate(BENCH_GUESSES, -5L))
    }

    @Test
    fun describeQuotesTheSampleItCameFrom() {
        assertTrue(MeasuredRate(1_900L, 1024).describe().contains("over 1024"))
        assertTrue(MeasuredRate(900L, 64).describe().contains("900 guesses/s"))
    }

    @Test
    fun autoTakesTheGraphicsCoresWhenTheDriverProvesThem() {
        val choice = autoBackend(GpuFacts(present = true, deviceName = "Adreno (TM) 640", selfTestReason = null))
        assertEquals(Backend.GPU, choice.backend)
        assertTrue("the answer must name the device it picked: ${choice.why}", choice.why.contains("Adreno (TM) 640"))
        assertTrue(choice.why.contains("known-answer"))
    }

    @Test
    fun theSentenceAboutWhichEngineRunsFitsOneLineOfAPhoneScreen() {
        // This sentence states what is about to run. It sits under the backend chooser on a phone,
        // where a wrapped sentence reads as a paragraph and stops being an answer. The device's own
        // name is the only variable part, so the budget is checked with a name as long as the ones
        // real drivers report.
        val longName = "Adreno (TM) 725"
        val why = autoBackend(GpuFacts(present = true, deviceName = longName, selfTestReason = null)).why
        assertTrue("why is ${why.length} chars: $why", why.length <= 62)
        val unnamed = autoBackend(GpuFacts(present = true, deviceName = null, selfTestReason = null)).why
        assertTrue("why is ${unnamed.length} chars: $unnamed", unnamed.length <= 62)
    }

    @Test
    fun autoTakesTheCpuAndSaysWhatIsMissingWhenThereIsNoDevice() {
        val choice = autoBackend(GpuFacts(present = false, deviceName = null, selfTestReason = null))
        assertEquals(Backend.CPU, choice.backend)
        assertTrue("a silent fallback would look like a choice: ${choice.why}", choice.why.isNotBlank())
        assertTrue(choice.why.contains("CPU"))
    }

    @Test
    fun aDeviceThatCannotProveItsHashesIsNeverTreatedAsFasterHardware() {
        // The known-answer test failing means "unknown output", not "slow": the CPU engine has to win
        // even though this is the same device that would otherwise be quicker.
        val choice = autoBackend(
            GpuFacts(present = true, deviceName = "Freedreno", selfTestReason = "GPU self-test failed: vector 3"),
        )
        assertEquals(Backend.CPU, choice.backend)
        assertTrue(choice.why.contains("Freedreno"))
        assertTrue(choice.why.contains("known-answer test"))
    }

    @Test
    fun usableIsFalseWheneverThereIsAGap() {
        assertFalse(GpuFacts(present = true, deviceName = "x", selfTestReason = "bad").usable)
        assertFalse(GpuFacts(present = false, deviceName = "x", selfTestReason = null).usable)
        assertTrue(GpuFacts(present = true, deviceName = "x", selfTestReason = null).usable)
        // A usable device must not carry a complaint, and a refused one must carry one: the UI prints
        // whichever it gets, and a blank sentence next to a refusal is unreadable.
        assertNull(GpuFacts(present = true, deviceName = "x", selfTestReason = null).gap)
        assertNotNull(GpuFacts(present = false, deviceName = null, selfTestReason = null).gap)
    }
}
