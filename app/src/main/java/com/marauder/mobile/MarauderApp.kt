package com.marauder.mobile

import android.app.Application
import com.marauder.mobile.capture.CaptureSink
import com.marauder.mobile.crack.AutoChoice
import com.marauder.mobile.crack.Backend
import com.marauder.mobile.crack.CrackEngine
import com.marauder.mobile.crack.GpuFacts
import com.marauder.mobile.crack.GpuCoreClient
import com.marauder.mobile.crack.JvmCrackEngine
import com.marauder.mobile.crack.ProbeVerdict
import com.marauder.mobile.crack.autoBackend
import com.marauder.mobile.crack.gpuFacts as factsFromVerdict
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
     * The app's only contact with this device's graphics driver. It is a binder to a second process
     * (`:gpucore`), because the driver is somebody else's code and can die while being asked — and
     * the app being alive to say so is the difference between a device the user can act on and a
     * crash dialog. Nothing in this process calls Vulkan directly.
     */
    lateinit var gpuCore: GpuCoreClient
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
        val gpu = when (val asked = gpuCore.lastVerdict()) {
            null -> "not asked yet: this app says nothing about the graphics cores of a device it has " +
                "not asked, and asking it is what the first GPU run does"
            is ProbeVerdict.Passed ->
                "ready: ${asked.deviceName} (known-answer passed, asked in a separate process)"
            is ProbeVerdict.Refused ->
                "unusable: ${asked.reason}" + (asked.deviceName?.let { " [$it]" } ?: "")
            is ProbeVerdict.Died -> "unusable: ${asked.words}"
        }
        return listOf("CPU: $cpu", "GPU: $gpu")
    }

    /**
     * The graphics facts behind a backend choice, read from this device's driver. The asking is real
     * GPU work and it happens in the helper process, so this must not run on the UI thread —
     * [pickAuto] is called from a worker. Whatever the answer is, it arrives as data: a driver that
     * dies while being asked shows up as a [ProbeVerdict.Died], not as this process dying.
     */
    fun gpuFacts(): GpuFacts = factsFromVerdict(gpuCore.probe())

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
            if (NativeCrypto.available) NativeGpuCrackEngine(gpuCore) else JvmCrackEngine()
        } else {
            if (NativeCrypto.available) NativeCpuCrackEngine() else JvmCrackEngine()
        }
    }

    override fun onCreate() {
        super.onCreate()
        // Android runs this class in every process of the app, the graphics helper included. That one
        // needs none of what follows, and it is better off not holding a second USB manager, a second
        // settings store and a second artifact index pointed at the same files.
        if (isGpuHelperProcess()) return
        gpuCore = GpuCoreClient(this)
        usb = UsbSerialManager(this)
        settings = SettingsRepository(this)
        captureSink = CaptureSink(this)
        location = LocationRepository(this)
        artifacts = ArtifactsRepository(this)
        wordlists = WordlistsRepository(this)
        artifacts.bridge = PcapExtractionBridge()
    }

    /**
     * True in the graphics helper, whose process name is this package plus `:gpucore`. Read from
     * `/proc/self/cmdline` rather than `Application.getProcessName()`, which only exists on API 28
     * and this build supports 26.
     */
    private fun isGpuHelperProcess(): Boolean = try {
        java.io.File("/proc/self/cmdline")
            .readText()
            .split('\u0000')
            .firstOrNull()
            .orEmpty()
            .endsWith(":gpucore")
    } catch (t: Throwable) {
        // Cannot tell, so behave like the main process: the worst case there is a helper holding
        // repositories it never uses, which is waste. The other direction would be a service
        // missing something it asked for.
        false
    }
}
