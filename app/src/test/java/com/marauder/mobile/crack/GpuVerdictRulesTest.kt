package com.marauder.mobile.crack

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What an answer about a graphics driver is allowed to turn into.
 *
 * None of this needs a phone. The point of the whole arrangement - helper process, sealed verdict,
 * one mapping function - is that the app's claims about a device follow rules that hold whichever
 * device answers. A phone whose driver is missing, a phone whose driver is wrong and a phone whose
 * driver died are three different situations, and this app has to say three different true things
 * about them.
 */
class GpuVerdictRulesTest {

    private val died = ProbeVerdict.Died("the process that asks your graphics driver died")
    private val noDevice = ProbeVerdict.Refused("libvulkan.so was not found on this device")
    private val wrongHashes = ProbeVerdict.Refused("PMK does not match the CPU core", "TestGPU 1")
    private val proven = ProbeVerdict.Passed("TestGPU 1")

    @Test
    fun `only a driver that proved itself reaches the graphics cores`() {
        val expected = mapOf(
            proven to Backend.GPU,
            wrongHashes to Backend.CPU,
            noDevice to Backend.CPU,
            died to Backend.CPU,
        )
        for ((verdict, backend) in expected) {
            val choice = autoBackend(gpuFacts(verdict))
            assertEquals("what AUTO does about $verdict", backend, choice.backend)
            assertTrue("the reason for $backend has to be a sentence", choice.why.isNotBlank())
        }
    }

    @Test
    fun `a driver that did not survive being asked is refused in words`() {
        val facts = gpuFacts(died)
        assertFalse("a dead helper is not a usable graphics side", facts.usable)
        val gap = facts.gap!!
        assertTrue(gap.contains("died"))
        assertTrue("the sentence has to say why this matters: $gap", gap.contains("known answer"))
        // ...and it has to survive into the choice the user is shown.
        assertTrue(autoBackend(facts).why.contains("died"))
    }

    @Test
    fun `missing hardware and distrustworthy hardware are not described the same way`() {
        val absent = gpuFacts(noDevice).gap!!
        val distrusted = gpuFacts(wrongHashes).gap!!

        assertTrue(absent, absent.contains("no usable Vulkan device"))
        assertTrue(absent, absent.contains("libvulkan.so was not found on this device"))

        assertTrue(distrusted, distrusted.contains("TestGPU 1"))
        assertTrue(distrusted, distrusted.contains("failed its known-answer test"))

        // A user reading either sentence is being told which problem the phone has. Mixing them up is
        // how "there is no GPU here" ends up reported about a phone that has one.
        assertFalse(absent.contains("failed its known-answer test"))
        assertFalse(distrusted.contains("no usable Vulkan device"))
    }

    @Test
    fun `a device that was never asked is a gap, not a free pass`() {
        val gap = backendGap(Backend.GPU, gpu = null, libraryReason = null)
        assertNotNull("asking has to be a precondition of running", gap)
        assertTrue(gap!!, gap.contains("has not been asked"))
    }

    @Test
    fun `a proven driver leaves nothing to refuse`() {
        assertNull(backendGap(Backend.GPU, gpuFacts(proven), libraryReason = null))
    }

    @Test
    fun `a broken graphics side never stands in the way of the phone's own cores`() {
        val broken = listOf(gpuFacts(died), gpuFacts(noDevice), gpuFacts(wrongHashes))
        for (facts in broken) {
            assertNull("CPU: $facts", backendGap(Backend.CPU, facts, libraryReason = null))
            assertNull("AUTO: $facts", backendGap(Backend.AUTO, facts, libraryReason = null))
        }
    }

    @Test
    fun `a GPU run that cannot honour its name says so before spending wordlist time`() {
        for (facts in listOf(gpuFacts(died), gpuFacts(noDevice), gpuFacts(wrongHashes))) {
            val gap = backendGap(Backend.GPU, facts, libraryReason = null)
            assertNotNull("$facts must be refused", gap)
            assertTrue("refusal words for $facts", gap!!.contains("cannot start"))
        }
    }

    @Test
    fun `the native library gates everything, whatever the driver says`() {
        val gap = backendGap(Backend.GPU, gpuFacts(proven), libraryReason = "no library for this ABI")
        assertNotNull(gap)
        assertTrue(gap!!, gap.contains("no library for this ABI"))
    }
}
