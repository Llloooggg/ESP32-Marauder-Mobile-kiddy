package com.marauder.mobile.crack

import com.marauder.extractor.CrackCore
import com.marauder.extractor.WpaCrypto
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
 * The built-in cracker: pure-JVM WPA2 verification through [CrackCore]
 * (identical semantics to hashcat mode 22000, KAT-verified). PBKDF2-HMAC-SHA1
 * at 4096 iterations dominates the cost, so candidate words are checked
 * per-essid — one PBKDF2 per (word, essid), then every target sharing that
 * essid is verified cheaply against the same PMK.
 *
 * [CrackConfig.threads] and [Backend.GPU] are accepted but not specialised:
 * this engine runs one tight loop and the GPU path would need the deferred
 * native/Vulkan backend.
 */
class JvmCrackEngine : CrackEngine {

    private val stopRequested = AtomicBoolean(false)

    override suspend fun bench(): MeasuredRate? = withContext(Dispatchers.Default) {
        // Timing the PBKDF2 against hashcat's own self-test target — the exact
        // per-guess cost the cracking loop pays. The warm-up is not timed: the JVM compiles
        // this loop while it runs, and a rate that includes the interpreted part is a rate for
        // the first guesses only, which is exactly the number an ETA would get wrong.
        val target = CrackCore.parse(BENCH_HASH) ?: return@withContext null
        repeat(BENCH_WARMUP) { target.verify("warmup-guess-$it") }
        val t0 = System.nanoTime()
        repeat(BENCH_GUESSES) { target.verify("bench-guess-$it") }
        measuredRate(BENCH_GUESSES, System.nanoTime() - t0)
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

        // PBKDF2 salt == essid, so one derivation serves every target of a network.
        val groups = parsed.groupBy { String(it.second.essid, Charsets.ISO_8859_1) }

        val cracked = HashSet<Int>()
        var done = 0L
        val meter = RateMeter()
        var stopped = false
        var discarded = 0

        outer@ for (list in lists) {
            list.bufferedReader().use { reader ->
                while (true) {
                    val word = reader.readLine() ?: break
                    if (word.isEmpty()) continue
                    currentCoroutineContext().ensureActive()
                    if (stopRequested.get()) {
                        // This engine stops at word granularity, so exactly the line just read is left
                        // unhashed. It is still reported: a count of guesses tried must be a count of
                        // guesses paid for.
                        stopped = true
                        discarded = 1
                        break
                    }

                    for (group in groups.values) {
                        val live = group.filter { (hashIndex, _) -> hashIndex !in cracked }
                        if (live.isEmpty()) continue
                        val pmk = WpaCrypto.pbkdf2Sha1(word, live.first().second.essid, 4096, 32)
                        for ((hashIndex, target) in live) {
                            if (target.verifyWithPmk(pmk)) {
                                cracked += hashIndex
                                emit(CrackEvent.Found(hashIndex, word))
                            }
                        }
                    }

                    done++
                    val tick = meter.sample(1)
                    if (tick.newWindow) emit(CrackEvent.Progress(done, totalWords, tick.rate))
                    if (cracked.size == parsed.size) break // every target recovered
                }
            }
            if (stopped || cracked.size == parsed.size) break
        }

        // The run's average is steadier than the last window, and an ETA needs a
        // rate that does not jump every time the phone throttles.
        emit(CrackEvent.Progress(done, totalWords, meter.overall()))
        emit(CrackEvent.Finished(completed = !stopped, discardedWords = discarded))
    }.flowOn(Dispatchers.Default)

    override fun stop() {
        stopRequested.set(true)
    }

    private fun countWords(file: File): Long = runCatching {
        file.bufferedReader().use { it.lineSequence().count { line -> line.isNotEmpty() }.toLong() }
    }.getOrDefault(0L)
}
