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
    /** Quick throughput probe. Returns null when no native engine is available. */
    suspend fun bench(): Long?

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
    override suspend fun bench(): Long? = null

    override fun run(config: CrackConfig): kotlinx.coroutines.flow.Flow<CrackEvent> =
        kotlinx.coroutines.flow.flow {
            emit(CrackEvent.Error("Cracker engine is not linked into this build yet."))
            emit(CrackEvent.Finished(completed = false))
        }

    override fun stop() {}
}
