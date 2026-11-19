package com.marauder.mobile.crack

import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.marauder.mobile.MarauderApp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * The properties this app must keep on every phone, tested on a real one.
 *
 * Deliberately not "does the GPU work on this model": one device cannot answer that, and the answer
 * changes per driver anyway. What is the same everywhere is the shape of the outcomes. Three things
 * can happen when the graphics side is asked - it proves itself, it refuses, or the process asking it
 * dies - and on all three the app has to stay alive, name what happened, and choose a backend it can
 * actually honour. Measured once on a POCO F5, the third case killed the whole app inside
 * `vkUpdateDescriptorSets`; a test that only checks the happy path would have shipped that.
 *
 * The two tests are order-independent: leaving one with a dead helper still leaves the other true.
 */
@RunWith(AndroidJUnit4::class)
class GpuAcrossAnyDriverTest {

    private val app: MarauderApp
        get() = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as MarauderApp

    @Test
    fun askingAboutTheGraphicsDriverAlwaysArrivesAsWords() {
        val verdict = app.gpuCore.probe()
        // Reaching the next line is most of the point: on one phone this call ended the process.
        val choice = app.pickAuto()
        assertTrue("a backend choice needs a reason for the screen", choice.why.isNotBlank())
        when (verdict) {
            is ProbeVerdict.Passed -> {
                assertTrue("a passed gate has to name the device it passed on", verdict.deviceName.isNotBlank())
                assertEquals(
                    "a driver that proved itself is what AUTO should use: ${choice.why}",
                    Backend.GPU, choice.backend,
                )
            }
            is ProbeVerdict.Refused, is ProbeVerdict.Died -> assertEquals(
                "AUTO may not use a graphics side this device cannot prove: ${choice.why}",
                Backend.CPU, choice.backend,
            )
        }
    }

    @Test
    fun aHelperThatDiesBecomesASentenceThisAppCanStillActOn() {
        app.gpuCore.probe()
        val pid = app.gpuCore.helperPid()
        assumeTrue("no helper process is running to end", pid > 0)

        Process.killProcess(pid)
        // Wait for the process to be really gone, so what follows cannot be blamed on a half-dead one.
        var waited = 0
        while (File("/proc/$pid").exists() && waited < 3_000) {
            Thread.sleep(100)
            waited += 100
        }
        assumeTrue("the system would not end the helper", !File("/proc/$pid").exists())

        val verdict = app.gpuCore.probe()
        assertTrue(
            "with its helper gone, this app must not keep claiming the graphics side works: $verdict",
            verdict is ProbeVerdict.Died,
        )
        assertTrue("and it must not call it usable", !app.gpuFacts().usable)
        assertEquals(
            "the run has to go to hardware this device can prove: ${app.pickAuto().why}",
            Backend.CPU, app.pickAuto().backend,
        )
        // The words are what the user sees, so they have to be there rather than implied.
        assertTrue((verdict as ProbeVerdict.Died).words.isNotBlank())
        // Getting this far is the claim: the driver crashed, and this process did not.
    }
}
