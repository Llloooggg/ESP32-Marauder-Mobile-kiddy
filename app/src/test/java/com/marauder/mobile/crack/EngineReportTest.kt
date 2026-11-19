package com.marauder.mobile.crack

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What the engine report may say, and how long it may say it for.
 *
 * The length rule is not decoration. These two lines are the app's answer to "which cracker am I
 * about to run, and on whose authority", and they are read on a phone at arm's length while someone
 * is trying to start a crack: a sentence that wraps into a paragraph stops being an answer and starts
 * being a manual page. So the sentences this app writes itself have a checked budget - the first
 * version of this report ran to two lines per engine, and nothing in the code stopped it.
 *
 * What comes from the device is not length-limited (a driver's refusal is its own words), but it is
 * position-limited: it may only appear after a short prefix, so our preamble never pushes the device's
 * own statement off the screen.
 */
class EngineReportTest {

    private val verdicts = listOf(
        "never asked" to null,
        "passed" to ProbeVerdict.Passed("Test GPU"),
        "refused" to ProbeVerdict.Refused("no Vulkan device"),
        "died" to ProbeVerdict.Died("the driver stopped while being asked"),
    )

    @Test
    fun `always two lines, and each names the engine it is about`() {
        for (backend in Backend.entries) {
            for ((name, verdict) in verdicts) {
                val lines = EngineReport.lines(backend, verdict, null)
                assertEquals("$backend/$name must be two lines", 2, lines.size)
                assertTrue("line 1 of $backend/$name must be about the CPU", lines[0].startsWith("CPU: "))
                assertTrue("line 2 of $backend/$name must be about the GPU", lines[1].startsWith("GPU: "))
            }
        }
    }

    @Test
    fun `the sentences this app writes are one line each`() {
        // Every combination where the line is entirely ours: no driver text to inherit.
        for (backend in Backend.entries) {
            val noNative = EngineReport.lines(backend, null, null)
            for (line in noNative) {
                assertTrue("$line is ${line.length} chars, over the budget of ${EngineReport.LINE_LIMIT}",
                    line.length <= EngineReport.LINE_LIMIT)
            }
        }
        val refused = EngineReport.lines(Backend.AUTO, ProbeVerdict.Refused("no Vulkan device"), null)
        assertTrue(refused[1].length <= EngineReport.LINE_LIMIT)
    }

    @Test
    fun `a proven driver is named, and the line is still one line`() {
        // The device name is the whole point of this sentence, so the length has to be budgeted
        // against a name as long as the ones real drivers report - not against a made-up short one.
        val realName = "Adreno (TM) 725"
        val line = EngineReport.lines(Backend.AUTO, ProbeVerdict.Passed(realName), null)[1]
        assertTrue("must name the device: $line", line.contains(realName))
        assertTrue("must say what was proven: $line", line.contains("known-answer"))
        assertTrue("$line is ${line.length} chars, over the budget of ${EngineReport.LINE_LIMIT}",
            line.length <= EngineReport.LINE_LIMIT)
    }

    @Test
    fun `a long reason still puts the device's words near the left edge`() {
        // The reason is the driver's sentence, not ours: what we control is how much screen we take
        // before it starts.
        val longReason = "the device's own explanation, which no tool can shorten and which may run on for a while"
        val line = EngineReport.lines(Backend.GPU, ProbeVerdict.Refused(longReason), null)[1]
        val where = line.indexOf(longReason)
        assertTrue("the driver's words begin at $where, past the prefix budget", inPrefix(where))
        val died = EngineReport.lines(Backend.AUTO, ProbeVerdict.Died(longReason), null)[1]
        assertTrue(inPrefix(died.indexOf(longReason)))
    }

    private fun inPrefix(index: Int): Boolean = index in 0..24

    @Test
    fun `a driver that died is never presented as ready`() {
        for (backend in Backend.entries) {
            val gpu = EngineReport.lines(backend, ProbeVerdict.Died("the helper process died"), null)[1]
            assertTrue(gpu.contains("died"))
            assertFalse("the report claims a dead driver is ready: $gpu", gpu.contains("ready"))
        }
    }

    @Test
    fun `an unasked driver is reported as unasked, not as good or bad`() {
        for (backend in Backend.entries) {
            val gpu = EngineReport.lines(backend, null, null)[1]
            assertTrue("must say it has not asked: $gpu", gpu.contains("not asked"))
            assertFalse(gpu.contains("ready"))
            assertFalse(gpu.contains("unusable"))
        }
    }

    @Test
    fun `a run that asks the graphics says the CPU is not used`() {
        val cpu = EngineReport.lines(Backend.GPU, ProbeVerdict.Passed("Test GPU"), null)[0]
        assertTrue("a forced-GPU run must not imply the CPU also runs: $cpu", cpu.contains("not used"))
    }

    @Test
    fun `AUTO says which way it falls back, and a proven driver is called ready`() {
        val auto = EngineReport.lines(Backend.AUTO, null, null)
        // The shape of the claim, not one wording: AUTO must state that the CPU runs when the
        // graphics cannot be proven right on this device.
        assertTrue("AUTO must say when the CPU runs: ${auto[0]}", auto[0].contains("used when"))
        assertTrue("AUTO must say it turns on proof, not on assumption: ${auto[0]}", auto[0].contains("proven"))
        val proven = EngineReport.lines(Backend.AUTO, ProbeVerdict.Passed("Test GPU"), null)[1]
        assertTrue(proven.contains("ready"))
        assertTrue("the device that proved itself has to be named: $proven", proven.contains("Test GPU"))
    }

    @Test
    fun `the engine that will run when the native one is missing says so`() {
        val line = EngineReport.lines(Backend.CPU, null, "lib not loaded on this device")[0]
        assertTrue("must name the JVM engine: $line", line.contains("JVM"))
        assertTrue("must carry the reason: $line", line.contains("lib not loaded"))
    }
}
