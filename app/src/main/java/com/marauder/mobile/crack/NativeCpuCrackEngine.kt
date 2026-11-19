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
 * The built-in cracker running on the device's CPU cores through the native core.
 *
 * Same contract, same events and the same word-by-word semantics as [JvmCrackEngine];
 * only the inner loop differs. Deliberately shared rather than reimplemented:
 *
 *  * the 22000 line is parsed by [CrackCore] here, and the pre-computed buffers are
 *    handed to the native side as the TLV blob, so the two engines cannot hold
 *    different opinions about what a hash means;
 *  * a candidate is only reported when the native verification matches, and a native
 *    failure is surfaced as an error, never as an empty result. An empty result and a
 *    wrong answer look identical to a user, which is exactly why the difference has to
 *    be made in code.
 *
 * Wordlists are read and owned by this class; the native call receives a batch of
 * candidate octets and returns `(wordIndex, targetIndex)` pairs. That keeps stop
 * responsive (checked between batches), keeps JNI traffic proportional to the batch
 * rather than to one guess, and keeps the file/UTF-8 handling in one language.
 */
class NativeCpuCrackEngine(
    /** 0 = let the native side use every core it finds. */
    private val threads: Int = 0,
) : CrackEngine {

    private val stopRequested = AtomicBoolean(false)

    override suspend fun bench(): MeasuredRate? = withContext(Dispatchers.Default) {
        if (!NativeCrypto.available) return@withContext null
        val target = CrackCore.parse(BENCH_HASH) ?: return@withContext null
        val index = listOf(NativeCrypto.TargetIndex(0, target.material()))
        // One thread, so this is comparable with the JVM engine's figure rather than a
        // measure of how many cores the phone happens to have. Same target, same number of
        // guesses, same batches as the real loop: two engines whose numbers cannot be compared
        // are two numbers nobody can choose between.
        val tries = (0 until BENCH_GUESSES).map { "bench-guess-$it" }
        val t0 = System.nanoTime()
        tries.chunked(NATIVE_BATCH).forEach { NativeCrypto.crackBatch(index, it, 1) }
        measuredRate(tries.size, System.nanoTime() - t0)
    }

    override fun run(config: CrackConfig): Flow<CrackEvent> = flow {
        stopRequested.set(false)

        backendGap(config.backend)?.let {
            emit(CrackEvent.Error(it))
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
        if (!NativeCrypto.available) {
            emit(CrackEvent.Error("native engine unavailable: ${NativeCrypto.unavailableReason}"))
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

        // Position in this list IS the native target index, so a pair coming back from
        // the native side maps straight to the hash line it belongs to.
        val targets = parsed.map { (hashIndex, target) ->
            NativeCrypto.TargetIndex(hashIndex, target.material())
        }

        val cracked = HashSet<Int>()          // hash-line indices already recovered
        var done = 0L
        val meter = RateMeter()
        var stopped = false
        var discarded = 0                     // words read into a batch but never hashed
        var nativeFailed: String? = null

        outer@ for (list in lists) {
            Wordlist.reader(list).use { reader ->
                var batch = ArrayList<String>(NATIVE_BATCH)
                while (true) {
                    val word = reader.readLine()
                    if (word != null && word.isNotEmpty()) batch.add(word)
                    val eof = word == null
                    if (!eof && batch.size < NATIVE_BATCH) continue
                    if (batch.isEmpty() && eof) break

                    currentCoroutineContext().ensureActive()
                    if (stopRequested.get()) {
                        // A stop lands between batches, so the words already read out of the file are
                        // paid for by the reader but not by PBKDF2: they are reported, not counted as tried.
                        stopped = true
                        discarded = batch.size
                        break
                    }

                    val hits = try {
                        NativeCrypto.crackBatch(targets, batch, threads)
                    } catch (t: Throwable) {
                        // The native core reported a real problem (unreadable material,
                        // a corrupt batch). Saying "not found" here would be a lie.
                        nativeFailed = t.message ?: t.javaClass.simpleName
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
                    batch = ArrayList<String>(NATIVE_BATCH)
                    if (cracked.size == parsed.size) break   // every target recovered
                }
            }
            if (stopped || nativeFailed != null || cracked.size == parsed.size) break
        }

        nativeFailed?.let {
            emit(CrackEvent.Error("native engine stopped: $it"))
            emit(CrackEvent.Progress(done, totalWords, meter.overall()))
            emit(CrackEvent.Finished(completed = false))
            return@flow
        }

        // The run average, not the last window: an ETA needs a rate that does not jump
        // every time the phone throttles.
        emit(CrackEvent.Progress(done, totalWords, meter.overall()))
        emit(CrackEvent.Finished(completed = !stopped, discardedWords = discarded))
    }.flowOn(Dispatchers.Default)

    override fun stop() {
        stopRequested.set(true)
    }

    private fun countWords(file: File): Long = runCatching { Wordlist.count(file) }.getOrDefault(0L)

    private companion object {
        /**
         * Candidates per native call. Big enough that JNI traffic and thread startup
         * disappear next to 4096 PBKDF2 iterations per candidate; small enough that
         * `stop()` still lands in well under a second on a phone.
         */
        const val NATIVE_BATCH = 64
    }
}
