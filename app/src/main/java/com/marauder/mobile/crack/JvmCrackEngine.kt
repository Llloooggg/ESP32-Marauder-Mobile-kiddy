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

    override suspend fun bench(): Long? = withContext(Dispatchers.Default) {
        // Timing the PBKDF2 against hashcat's own self-test target — the exact
        // per-guess cost the cracking loop pays.
        val target = CrackCore.parse(BENCH_HASH) ?: return@withContext null
        val tries = 20
        val t0 = System.nanoTime()
        repeat(tries) { target.verify("bench-guess-$it") }
        val dt = System.nanoTime() - t0
        tries.toLong() * 1_000_000_000L / dt.coerceAtLeast(1L)
    }

    override fun run(config: CrackConfig): Flow<CrackEvent> = flow {
        stopRequested.set(false)

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
        var windowStart = System.nanoTime()
        var stopped = false

        outer@ for (list in lists) {
            list.bufferedReader().use { reader ->
                while (true) {
                    val word = reader.readLine() ?: break
                    if (word.isEmpty()) continue
                    currentCoroutineContext().ensureActive()
                    if (stopRequested.get()) {
                        stopped = true
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
                    val now = System.nanoTime()
                    if (now - windowStart >= 1_000_000_000L) {
                        emit(CrackEvent.Progress(done, totalWords, done * 1_000_000_000.0 / (now - windowStart)))
                        windowStart = now
                    }
                    if (cracked.size == parsed.size) break // every target recovered
                }
            }
            if (stopped || cracked.size == parsed.size) break
        }

        val finalRate = done * 1_000_000_000.0 / (System.nanoTime() - windowStart).coerceAtLeast(1L)
        emit(CrackEvent.Progress(done, totalWords, finalRate))
        emit(CrackEvent.Finished(completed = !stopped))
    }.flowOn(Dispatchers.Default)

    override fun stop() {
        stopRequested.set(true)
    }

    private fun countWords(file: File): Long = runCatching {
        file.bufferedReader().use { it.lineSequence().count { line -> line.isNotEmpty() }.toLong() }
    }.getOrDefault(0L)

    private companion object {
        /**
         * hashcat's mode-22000 self-test hash (ST_HASH in module_22000.c):
         * essid "hashcat-essid", password "hashcat!".
         */
        const val BENCH_HASH =
            "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***"
    }
}
