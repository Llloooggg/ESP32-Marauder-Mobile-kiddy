package com.marauder.mobile.crack

import com.marauder.mobile.data.PcapExtractionBridge
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * End-to-end checks of the JVM engine against the official hashcat mode-22000
 * self-test vector (module_22000.c ST_HASH / ST_PASS = "hashcat!").
 */
class JvmCrackEngineTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val pmkidLine =
        "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***"

    private fun wordlist(vararg words: String): File =
        tmp.newFile("list.txt").apply { writeText(words.joinToString("\n") + "\n") }

    @Test
    fun benchReportsRealisticThroughput() = runBlocking {
        val rate = JvmCrackEngine().bench()
        assertNotNull(rate)
        // 4096 PBKDF2 iterations: any working JVM sits well above 10 guesses/s.
        assertTrue("bench rate ${rate!!.guessesPerSecond} too low", rate.guessesPerSecond > 10)
        // The number must come from a sample big enough to be about the hash, not the warm-up.
        assertEquals(BENCH_GUESSES, rate.samples)
    }

    @Test
    fun cracksOfficialPmkidVector() = runBlocking {
        val engine = JvmCrackEngine()
        val config = CrackConfig(hashLines = listOf(pmkidLine), wordlists = listOf(wordlist("nope", "password", "hashcat!")))
        val events = engine.run(config).toList()

        val found = events.filterIsInstance<CrackEvent.Found>()
        assertEquals(1, found.size)
        assertEquals(0, found[0].hashIndex)
        assertEquals("hashcat!", found[0].password)
        assertTrue(events.last() is CrackEvent.Finished)
        assertTrue((events.last() as CrackEvent.Finished).completed)
        assertTrue(events.any { it is CrackEvent.Progress && it.done > 0 })
    }

    @Test
    fun cracksTheOfficialVectorFromAListSavedWithABom() = runBlocking {
        // What Notepad writes: UTF-8 with a byte-order mark. The mark must not become
        // part of the first word, or the one-line list "59db65bd" is a miss.
        val list = tmp.newFile("bom.txt").apply {
            writeBytes(byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()) +
                "hashcat!\n".toByteArray())
        }
        val events = JvmCrackEngine().run(
            CrackConfig(hashLines = listOf(pmkidLine), wordlists = listOf(list))
        ).toList()

        val found = events.filterIsInstance<CrackEvent.Found>()
        assertEquals(1, found.size)
        assertEquals("hashcat!", found[0].password)
    }

    @Test
    fun findsEveryTargetEvenWhenSeveralShareTheEssid() = runBlocking {
        // Same network twice (e.g. a PMKID + a handshake): both indices must report.
        val engine = JvmCrackEngine()
        val config = CrackConfig(hashLines = listOf(pmkidLine, pmkidLine), wordlists = listOf(wordlist("hashcat!")))
        val events = engine.run(config).toList()
        val found = events.filterIsInstance<CrackEvent.Found>().map { it.hashIndex to it.password }
        assertEquals(setOf(0 to "hashcat!", 1 to "hashcat!"), found.toSet())
    }

    @Test
    fun missExhaustsWithCompletedTrue() = runBlocking {
        val engine = JvmCrackEngine()
        val config = CrackConfig(hashLines = listOf(pmkidLine), wordlists = listOf(wordlist("a", "b", "c")))
        val events = engine.run(config).toList()
        assertTrue(events.none { it is CrackEvent.Found })
        assertTrue((events.last() as CrackEvent.Finished).completed)
    }

    @Test
    fun unparsableLinesAndMissingWordlistsSurfaceAsErrors() = runBlocking {
        val engine = JvmCrackEngine()
        val badHashes = engine.run(CrackConfig(hashLines = listOf("not a hash"), wordlists = listOf(wordlist("x")))).toList()
        assertTrue(badHashes.any { it is CrackEvent.Error })
        assertTrue(badHashes.last() is CrackEvent.Finished)

        val missingLists = engine.run(CrackConfig(hashLines = listOf(pmkidLine), wordlists = listOf(File("Z:/nope.txt")))).toList()
        assertTrue(missingLists.any { it is CrackEvent.Error })
    }

    @Test
    fun stopEndsSessionWithoutCompletedFlag() = runBlocking {
        val engine = JvmCrackEngine()
        val big = tmp.newFile("big.txt")
        big.bufferedWriter().use { w -> repeat(100_000) { w.write("guess-$it\n") } }

        var finished: CrackEvent.Finished? = null
        var sawProgress = false
        engine.run(CrackConfig(hashLines = listOf(pmkidLine), wordlists = listOf(big))).collect { event ->
            when (event) {
                is CrackEvent.Progress -> if (!sawProgress) { sawProgress = true; engine.stop() }
                is CrackEvent.Finished -> finished = event
                else -> Unit
            }
        }
        assertTrue(sawProgress)
        assertNotNull(finished)
        assertEquals(false, finished!!.completed)
        // The word this engine had already read from the file is the price the screen must not count:
        // TRIED is guesses hashed, and the JVM engine stops at word granularity, so exactly one line
        // was read and left unhashed. A stop that reports nothing here makes the count uncheckable.
        assertTrue("a stopped run must report what it left unhashed", finished!!.discardedWords >= 1)
    }

    @Test
    fun anExhaustedRunReportsNothingLeftUnhashed() = runBlocking {
        val engine = JvmCrackEngine()
        val list = wordlist("nope", "password")
        val events = engine.run(CrackConfig(hashLines = listOf(pmkidLine), wordlists = listOf(list))).toList()
        val finished = events.filterIsInstance<CrackEvent.Finished>().single()
        assertTrue(finished.completed)
        assertEquals(0, finished.discardedWords)
    }

    @Test
    fun bridgeReportsMissingAndNonPcapFilesGracefully() {
        val bridge = PcapExtractionBridge()
        assertNull(bridge.extract(File("Z:/definitely-not-here.pcap")))

        val junk = tmp.newFile("junk.pcap").apply { writeText("this string is definitely not a pcap file") }
        val res = bridge.extract(junk)
        assertNotNull(res)
        assertTrue(!res!!.usable)
        assertTrue(res.note!!.contains("not a libpcap file"))
    }
}
