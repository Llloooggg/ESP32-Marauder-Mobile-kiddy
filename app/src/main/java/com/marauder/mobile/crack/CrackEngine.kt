package com.marauder.mobile.crack

import java.io.File

/**
 * Contract between the crack UI and a native cracking backend. The real
 * implementation binds to the native (NDK) engine; [NoopCrackEngine] keeps the
 * UI wiring compilable until the engine is linked in.
 */
sealed interface CrackEvent {
    /** Periodic progress tick. [rate] is guesses/second over the last window. */
    data class Progress(val done: Long, val total: Long, val rate: Double) : CrackEvent

    /** A password was found for hash [hashIndex] (index into the config's hash list). */
    data class Found(val hashIndex: Int, val password: String) : CrackEvent

    /** Engine finished (exhausted, stopped, or found). [completed] = wordlist exhausted with no crack. */
    data class Finished(val completed: Boolean) : CrackEvent

    data class Error(val message: String) : CrackEvent
}

enum class Backend { AUTO, CPU, GPU }

/**
 * A backend this device cannot honour, in words the UI shows verbatim, or null when it can.
 *
 * This is asked at run time rather than decided at build time, because "this build has Vulkan
 * support compiled in" and "this phone's driver will produce correct PMKs" are different
 * claims, and only the second one matters. The reasons are quoted verbatim from the native
 * probe, so the screen says what the driver actually reported instead of a generic shrug.
 *
 * `GPU` is refused rather than quietly run as CPU: a run labelled "GPU" whose rate came from
 * the CPU is a number nobody can act on. `AUTO` and `CPU` have no gap here because they are
 * served by whichever CPU engine this device can prove — the native one when its known-answer
 * test passes, the JVM one otherwise — and the crack screen names which one that is.
 */
fun backendGap(backend: Backend): String? = when (backend) {
    Backend.GPU -> when {
        !NativeCrypto.available ->
            "GPU backend needs the native cracking library, and it is unavailable here: " +
                (NativeCrypto.unavailableReason ?: "unknown reason")
        !NativeCrypto.gpuPresent ->
            "GPU backend refused by this device: ${NativeCrypto.gpuUnavailableReason}"
        else -> null
    }
    Backend.AUTO, Backend.CPU -> null
}

/**
 * hashcat's mode-22000 self-test hash (ST_HASH in module_22000.c): essid
 * "hashcat-essid", password "hashcat!". Both engines bench against this, so their
 * numbers mean the same work.
 */
internal const val BENCH_HASH =
    "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***"

data class CrackConfig(
    /** hashcat 22000 lines (one per target network). */
    val hashLines: List<String>,
    /** wordlist files, applied in order (already materialised on disk) */
    val wordlists: List<File>,
    val backend: Backend = Backend.AUTO,
    /** 0 = let the engine pick a sensible core count */
    val threads: Int = 0,
)

interface CrackEngine {
    /**
     * Timed throughput on this device: the same known-answer target the real loop uses, over
     * [BENCH_GUESSES] guesses. Null when this engine cannot produce a number here (no native
     * library, no Vulkan driver, or a driver that failed its own known-answer test).
     *
     * The sample is deliberately bigger than it used to be. PBKDF2's 4096 rounds are the whole
     * cost of a guess and the work is linear, so a timed rate can be extended to a whole wordlist —
     * but only if the sample measures the hash and not the driver's launch overhead or the JVM's
     * warm-up, which is what a twenty-guess figure mostly measured.
     */
    suspend fun bench(): MeasuredRate?

    /**
     * Start (or restart) a session; the returned flow emits until [Finished].
     * Collecting on the main dispatcher is expected. Only one session at a time;
     * starting a new one cancels the previous.
     */
    fun run(config: CrackConfig): kotlinx.coroutines.flow.Flow<CrackEvent>

    /** Request cooperative stop of the running session. */
    fun stop()
}

/** Placeholder engine used while the native engine is being built. */
object NoopCrackEngine : CrackEngine {
    override suspend fun bench(): MeasuredRate? = null

    override fun run(config: CrackConfig): kotlinx.coroutines.flow.Flow<CrackEvent> =
        kotlinx.coroutines.flow.flow {
            emit(CrackEvent.Error("Cracker engine is not linked into this build yet."))
            emit(CrackEvent.Finished(completed = false))
        }

    override fun stop() {}
}
