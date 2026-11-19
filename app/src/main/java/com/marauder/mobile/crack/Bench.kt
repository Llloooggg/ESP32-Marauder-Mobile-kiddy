package com.marauder.mobile.crack

/**
 * Measuring what a cracker costs on this device.
 *
 * PBKDF2-HMAC-SHA1 with 4096 rounds is the whole price of one guess, and it is linear: the time
 * for N guesses is N times the time for one. That is what makes a short measurement useful — and
 * what makes a careless one wrong: a rate taken over twenty guesses measures the driver's launch
 * overhead and the JVM's warm-up as much as it measures the hash, and a number like that ends up
 * in an ETA that the run then misses. So the sample is bigger, the warm-up is excluded, and a
 * sample that is too small to mean anything is refused rather than reported.
 */

/** Guesses timed by every engine's `bench()`. ~0.1 s of real PBKDF2 on a phone core. */
const val BENCH_GUESSES = 1024

/** Guesses run before the timed sample, so the number is not the warm-up (JIT, driver setup). */
const val BENCH_WARMUP = 64

/** Guesses below this tell you nothing about throughput; the rate is refused. */
const val MIN_SAMPLES = 64

data class MeasuredRate(val guessesPerSecond: Long, val samples: Int) {
    /** How long [guesses] would take at this rate, in seconds; null when nothing was measured. */
    fun secondsFor(guesses: Long): Double? =
        if (guessesPerSecond <= 0) null else guesses.toDouble() / guessesPerSecond

    /** The same rate the screen prints: "1.9 k guesses/s over 1024". */
    fun describe(): String = "%s guesses/s over %d".format(
        if (guessesPerSecond >= 1000) "%.1f k".format(guessesPerSecond / 1000.0) else guessesPerSecond.toString(),
        samples,
    )
}

/**
 * A rate from a timed sample, or null when the sample cannot support one. The elapsed time is
 * guarded as well as the sample size: a native call that returned before doing the work, or a
 * clock that did not move, would otherwise divide by (a coerced) 1 ns and report a rate of
 * billions of guesses per second — a number that looks confident and is a lie.
 */
fun measuredRate(samples: Int, elapsedNanos: Long): MeasuredRate? {
    if (samples < MIN_SAMPLES) return null
    if (elapsedNanos <= 0) return null
    return MeasuredRate(samples.toLong() * 1_000_000_000L / elapsedNanos, samples)
}

/** What `AUTO` settled on, and the sentence that says why, for the UI to show verbatim. */
data class AutoChoice(val backend: Backend, val why: String)

/**
 * What this device's graphics side can actually be trusted with, read from the driver at the moment
 * the choice is made. [usable] is the gate every GPU run has to pass: a device that fails its
 * known-answer test is not a slower calculator, it is a calculator with unknown output, and on a
 * cracker a wrong hash looks exactly like a password that is not in the list.
 */
data class GpuFacts(
    val present: Boolean,
    val deviceName: String?,
    val selfTestReason: String?,
) {
    val usable: Boolean get() = present && selfTestReason == null

    /** Why [usable] is false, in the driver's own words where it has any, or null when it is fine. */
    val gap: String?
        get() = when {
            !present -> "no usable Vulkan device was found here"
            selfTestReason != null -> "$deviceName failed its known-answer test: $selfTestReason"
            else -> null
        }
}

/**
 * How `AUTO` settles. The rule is the obvious one: the graphics cores whenever this device can be
 * trusted with them, because they run the same computation on quicker hardware — and the CPU engine
 * when they cannot, with the reason shown instead of a silent fallback.
 *
 * No ratio and no head-to-head race between the engines first: a rate is a sample, not the run, and
 * PBKDF2 throughput does not change between one part of a wordlist and the next, so timing both
 * engines would only delay a decision the driver gate already answers. What has to be checked is
 * whether the device can produce correct hashes at all, which is what its known-answer test says.
 */
fun autoBackend(gpu: GpuFacts): AutoChoice = when {
    gpu.usable -> AutoChoice(
        Backend.GPU,
        "${gpu.deviceName ?: "the Vulkan device"} is present and passed its known-answer test, so AUTO " +
            "runs the graphics cores: the same computation on quicker hardware",
    )
    else -> AutoChoice(
        Backend.CPU,
        (gpu.gap ?: "the graphics cores are not usable here") + ", so AUTO runs the CPU engine",
    )
}





