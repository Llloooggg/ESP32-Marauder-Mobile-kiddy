package com.marauder.mobile.crack

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What a backend selection is allowed to promise on a given device.
 *
 * The GPU path is compiled into every build now, so nothing decides statically whether it
 * can run — the answer comes from probing this phone's Vulkan driver at run time. These
 * tests pin the shape of that answer rather than its content, because the content depends on
 * the machine running the test:
 *
 *  * a refused GPU must say why, in a non-blank sentence. A `false` with no reason is how a
 *    UI ends up showing "GPU unavailable" next to a button that still says GPU;
 *  * a GPU that is reported available must name the device it would use, otherwise the rate
 *    a run reports belongs to an unnamed piece of hardware;
 *  * AUTO/CPU are always permitted, because they are served by whichever CPU engine this
 *    device can prove — native or JVM — and refusing them would strand the user with no
 *    cracker at all.
 */
class BackendSelectionTest {

    @Test
    fun autoAndCpuAreAlwaysPermitted() {
        assertNull(backendGap(Backend.AUTO))
        assertNull(backendGap(Backend.CPU))
    }

    @Test
    fun gpuRefusalAlwaysCarriesAReason() {
        val gap = backendGap(Backend.GPU)
        if (gap == null) {
            assertTrue(
                "GPU is reported usable, so it must name the device that would run",
                NativeCrypto.gpuDeviceName.isNotBlank(),
            )
        } else {
            assertTrue("GPU refusal message is blank", gap.isNotBlank())
            assertNotNull("the probe must report a reason too", NativeCrypto.gpuUnavailableReason)
        }
    }

    /**
     * The GPU path uses the same native library as the CPU batch path (one material blob,
     * one verification routine), so a device that has that library must never be told the
     * GPU is missing it. It may legitimately be told there is no usable Vulkan driver.
     */
    @Test
    fun gpuIsNeverBlamedOnTheNativeLibraryWhenItIsPresent() {
        if (!NativeCrypto.available) return   // no native library in this test environment
        val gap = backendGap(Backend.GPU)
        if (gap != null) {
            assertTrue("GPU refused for a missing native library that is actually loaded: $gap",
                !gap.contains("native cracking library"))
        }
    }
}
