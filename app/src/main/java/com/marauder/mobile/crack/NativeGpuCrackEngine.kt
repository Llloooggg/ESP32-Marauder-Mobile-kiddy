package com.marauder.mobile.crack

import com.marauder.extractor.CrackCore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The built-in cracker with the 4096 PBKDF2 rounds of every guess run on the device's
 * graphics cores over Vulkan.
 *
 * Same contract, same events and the same word-by-word semantics as [JvmCrackEngine] and
 * [NativeCpuCrackEngine]. The three engines differ in one thing only — where the hashing
 * runs — because everything else is shared on purpose:
 *
 *  * the 22000 line is parsed by [CrackCore] here, and the target material is handed to the
 *    native side as the same TLV blob the CPU engine sends, so no engine can hold its own
 *    opinion about what a hash means;
 *  * the MIC/PMKID comparison happens on the CPU, inside the native core, using the very
 *    same `verify_with_pmk` the CPU engine calls. A GPU run and a CPU run therefore cannot
 *    report different things about one hash line, which is the failure this split would
 *    otherwise have;
 *  * a native failure surfaces as [CrackEvent.Error], never as an empty result: "nothing in
 *    this wordlist matched" and "the GPU could not run" look identical to a user, and only
 *    one of them is an answer.
 *
 * Unlike the CPU engine, this one runs a known-answer gate of its own before touching a
 * wordlist: the shader is compiled offline and executed by whatever driver the phone
 * happens to ship, so it is checked against hashcat's published PMKID vector and against
 * this repo's own CPU PBKDF2 (every salt alignment, the 63-octet passphrase and the
 * hash-the-key-first path) on this device, on this driver. If that fails the run stops
 * with the reason instead of reporting "not cracked" for a password that is in the list.
 */
class NativeGpuCrackEngine : CrackEngine {

    private val stopRequested = AtomicBoolean(false)

    override suspend fun bench(): MeasuredRate? = withContext(Dispatchers.Default) {
        if (!NativeCrypto.gpuPresent) return@withContext null
        // A driver that disagrees with the CPU core cannot produce a meaningful rate either,
        // so the gate is the same one a real run uses.
        if (NativeCrypto.gpuSelfTest() != null) return@withContext null
        val target = CrackCore.parse(BENCH_HASH) ?: return@withContext null
        val index = listOf(NativeCrypto.TargetIndex(0, target.material()))
        // The first batches go to setting up the driver's command buffers, not to hashing; timing
        // them is what produced a GPU "rate" that no real run ever matched.
        val warmup = (0 until BENCH_WARMUP).map { "warmup-guess-$it" }
        warmup.chunked(GPU_BATCH).forEach { NativeCrypto.gpuCrackBatch(index, it) }
        val tries = (0 until BENCH_GUESSES).map { "bench-guess-$it" }
        val t0 = System.nanoTime()
        tries.chunked(GPU_BATCH).forEach { NativeCrypto.gpuCrackBatch(index, it) }
        measuredRate(tries.size, System.nanoTime() - t0)
    }

    override fun run(config: CrackConfig): Flow<CrackEvent> = flow {
        stopRequested.set(false)

        backendGap(config.backend)?.let {
            emit(CrackEvent.Error(it))
            emit(CrackEvent.Finished(completed = false))
            return@flow
        }

        // Real GPU work (25 PBKDF2 derivations), so it happens here rather than while the
        // screen is being drawn: run() is already collected on a worker thread. The verdict
        // is cached for the life of the process, so this costs one probe per install.
        NativeCrypto.gpuSelfTest()?.let {
            emit(CrackEvent.Error("GPU refused, run not started: $it"))
            emit(CrackEvent.Finished(completed = false))
            return@flow
        }

        val parsed = config.hashLines.mapIndexedNotNull { index, line ->
            CrackCore.parse(line)?.let { index to it }
        }
        val skipped = config.hashLines.size - parsed.size
        if (skipped > 0) emit(CrackEvent.Error("$skipped hash line(s) could not be parsed and were skipped"))
        if (parsed.isEmpty()) {
            emit(CrackEvent.Error("no crackable hash lines in this session"))
            emit(CrackEvent.Finished(completed = false))
            return@flow
        }

        val lists = config.wordlists.filter { it.isFile }
        if (lists.isEmpty()) {
            emit(CrackEvent.Error("no wordlist files found on disk"))
            emit(CrackEvent.Finished(completed = false))
            return@flow
        }
        val totalWords = lists.sumOf { countWords(it) }
        if (totalWords == 0L) {
            emit(CrackEvent.Error("wordlists are empty"))
            emit(CrackEvent.Finished(completed = false))
            return@flow
        }

        // Position in this list IS the native target index, so a pair coming back from the
        // native side maps straight to the hash line it belongs to. Identical to the CPU
        // engine, including the (wordIndex, targetIndex) result shape.
        val targets = parsed.map { (hashIndex, target) ->
            NativeCrypto.TargetIndex(hashIndex, target.material())
        }

        val cracked = HashSet<Int>()          // hash-line indices already recovered
        var done = 0L
        val meter = RateMeter()
        var stopped = false
        var discarded = 0                     // words read into a batch but never hashed
        var gpuFailed: String? = null

        outer@ for (list in lists) {
            list.bufferedReader().use { reader ->
                var batch = ArrayList<String>(GPU_BATCH)
                while (true) {
                    val word = reader.readLine()
                    if (word != null && word.isNotEmpty()) batch.add(word)
                    val eof = word == null
                    if (!eof && batch.size < GPU_BATCH) continue
                    if (batch.isEmpty() && eof) break

                    currentCoroutineContext().ensureActive()
                    if (stopRequested.get()) {
                        // A stop can only be noticed between batches, and a GPU batch is the unit the
                        // driver was handed: the words already read are reported, never counted as tried.
                        stopped = true
                        discarded = batch.size
                        break
                    }

                    val hits = try {
                        NativeCrypto.gpuCrackBatch(targets, batch)
                    } catch (t: Throwable) {
                        // The native side reported a real problem (unreadable material, a
                        // corrupt batch, a salt the kernel would derive wrongly, a lost
                        // device). "Not found" would be a lie.
                        gpuFailed = t.message ?: t.javaClass.simpleName
                        break
                    }

                    var w = 0
                    while (w < hits.size) {
                        val wordIndex = hits[w]
                        val targetIndex = hits[w + 1]
                        w += 2
                        val hashIndex = targets[targetIndex].hashIndex
                        if (cracked.add(hashIndex)) {
                            emit(CrackEvent.Found(hashIndex, batch[wordIndex]))
                        }
                    }

                    done += batch.size
                    val tick = meter.sample(batch.size.toLong())
                    if (tick.newWindow) emit(CrackEvent.Progress(done, totalWords, tick.rate))
                    batch = ArrayList<String>(GPU_BATCH)
                    if (cracked.size == parsed.size) break   // every target recovered
                }
            }
            if (stopped || gpuFailed != null || cracked.size == parsed.size) break
        }

        gpuFailed?.let {
            emit(CrackEvent.Error("GPU engine stopped: $it"))
            emit(CrackEvent.Progress(done, totalWords, meter.overall()))
            emit(CrackEvent.Finished(completed = false))
            return@flow
        }

        // The run average, not the last window: an ETA needs a rate that does not jump
        // every time the device throttles.
        emit(CrackEvent.Progress(done, totalWords, meter.overall()))
        emit(CrackEvent.Finished(completed = !stopped, discardedWords = discarded))
    }.flowOn(Dispatchers.Default)

    override fun stop() {
        stopRequested.set(true)
    }

    private fun countWords(file: File): Long = runCatching {
        file.bufferedReader().use { it.lineSequence().count { line -> line.isNotEmpty() }.toLong() }
    }.getOrDefault(0L)

    private companion object {
        /**
         * Candidates per native call. Each candidate costs one PBKDF2 block pair per target
         * ESSID, so the native side sees wordCount x saltCount pairs; the native engine
         * splits a call that needs more than one dispatch and verifies every PMK on the CPU.
         *
         * 512 keeps JNI traffic and one Vulkan device setup small next to a million PBKDF2
         * rounds, while still letting `stop()` land inside a second on a phone.
         */
        const val GPU_BATCH = 512
    }
}
