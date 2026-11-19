package com.marauder.mobile

import android.app.Application
import com.marauder.mobile.capture.CaptureSink
import com.marauder.mobile.crack.AutoChoice
import com.marauder.mobile.crack.Backend
import com.marauder.mobile.crack.CrackEngine
import com.marauder.mobile.crack.GpuFacts
import com.marauder.mobile.crack.JvmCrackEngine
import com.marauder.mobile.crack.autoBackend
import com.marauder.mobile.crack.NativeCpuCrackEngine
import com.marauder.mobile.crack.NativeCrypto
import com.marauder.mobile.crack.NativeGpuCrackEngine
import com.marauder.mobile.data.ArtifactsRepository
import com.marauder.mobile.data.PcapExtractionBridge
import com.marauder.mobile.data.SettingsRepository
import com.marauder.mobile.data.WordlistsRepository
import com.marauder.mobile.location.LocationRepository
import com.marauder.mobile.usb.UsbSerialManager

/** Holds the single, process-wide USB serial link to the ESP32 and app settings. */
class MarauderApp : Application() {

    lateinit var usb: UsbSerialManager
        private set

    lateinit var settings: SettingsRepository
        private set

    /** Writes streamed captures to phone storage (the on-phone SD-card replacement). */
    lateinit var captureSink: CaptureSink
        private set

    /** Phone GNSS used to tag wardrive rows (the on-phone GPS-module replacement). */
    lateinit var location: LocationRepository
        private set

    /** Library of on-phone captures (pcap/gpx/log) with a JSON index. */
    lateinit var artifacts: ArtifactsRepository
        private set

    /** Cracking wordlists (built-in list + SAF imports + URL downloads). */
    lateinit var wordlists: WordlistsRepository
        private set

    /**
     * The cracker back ends available on this device, created once per kind.
     *
     * The native (NDK) CPU engine is used only when it loaded, agrees on the material
     * protocol and passed its own known-answer test here; otherwise [cpuEngine] is the JVM
     * engine and [engineReport] says why the native one is not. The GPU engine is created
     * even when this device has no usable Vulkan driver — asking it is what produces the
     * refusal message the UI shows — but a GPU run checks the driver itself before spending
     * any wordlist time on it.
     */
    private val engines = mutableMapOf<Backend, CrackEngine>()

    /** Which cracker a given backend selection actually runs, and why, for the UI. */
    fun engineReport(backend: Backend): List<String> {
        val cpuReason = NativeCrypto.unavailableReason
        val cpu = when (backend) {
            Backend.GPU -> "not used: this run asks the graphics cores"
            Backend.AUTO -> "used only if the graphics cores cannot be proven correct on this device"
            else -> if (cpuReason == null) "native CPU engine (known-answer self-test passed on this device)"
            else "JVM engine: $cpuReason"
        }
        val gpu = when {
            !NativeCrypto.available -> "unavailable: no native library"
            !NativeCrypto.gpuPresent -> "unavailable: ${NativeCrypto.gpuUnavailableReason}"
            NativeCrypto.gpuSelfTestPassed -> "ready: ${NativeCrypto.gpuDeviceName} (known-answer self-test passed)"
            else -> "available: ${NativeCrypto.gpuDeviceName} — its known-answer test has not run yet on this driver"
        }
        return listOf("CPU: $cpu", "GPU: $gpu")
    }

    /**
     * The graphics facts behind a backend choice, read from the driver. [NativeCrypto.gpuSelfTest]
     * does real GPU work, so this must not run on the UI thread — [pickAuto] is called from a worker.
     */
    fun gpuFacts(): GpuFacts = GpuFacts(
        present = NativeCrypto.gpuPresent,
        deviceName = NativeCrypto.gpuDeviceName.takeIf { it.isNotEmpty() },
        selfTestReason = if (NativeCrypto.available && NativeCrypto.gpuPresent) NativeCrypto.gpuSelfTest() else null,
    )

    /**
     * What `AUTO` runs on this device right now, and the sentence that says why. The graphics cores
     * are taken whenever their driver is present and passes the known-answer test — same computation,
     * quicker hardware — and the CPU engine is taken when they are not, with the driver's reason
     * shown instead of a silent fallback.
     *
     * Reading the driver's verdict does real GPU work, so this must be called from a worker thread,
     * not while the screen is being drawn.
     */
    fun pickAuto(): AutoChoice = autoBackend(gpuFacts())

    /**
     * The engine for a backend choice. `AUTO` is resolved to a concrete backend by [pickAuto] before
     * it gets here, so the run always says which engine it settled on; a bare `AUTO` (a fresh
     * session that never measured) stays on the CPU engine, the one this build can prove without a
     * graphics driver.
     */
    fun engineFor(backend: Backend): CrackEngine = engines.getOrPut(backend) {
        // A GPU selection on a device with no native library still gets a working engine:
        // the run itself refuses with the driver's own words (backendGap), and the report
        // line above the button already says the GPU is unavailable. Handing back a
        // placeholder would hide the real reason behind a generic message.
        if (backend == Backend.GPU) {
            if (NativeCrypto.available) NativeGpuCrackEngine() else JvmCrackEngine()
        } else {
            if (NativeCrypto.available) NativeCpuCrackEngine() else JvmCrackEngine()
        }
    }

    override fun onCreate() {
        super.onCreate()
        usb = UsbSerialManager(this)
        settings = SettingsRepository(this)
        captureSink = CaptureSink(this)
        location = LocationRepository(this)
        artifacts = ArtifactsRepository(this)
        wordlists = WordlistsRepository(this)
        artifacts.bridge = PcapExtractionBridge()
    }
}
