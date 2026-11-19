package com.marauder.mobile

import android.app.Application
import com.marauder.mobile.capture.CaptureSink
import com.marauder.mobile.crack.CrackEngine
import com.marauder.mobile.crack.JvmCrackEngine
import com.marauder.mobile.crack.NativeCpuCrackEngine
import com.marauder.mobile.crack.NativeCrypto
import com.marauder.mobile.crack.NoopCrackEngine
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
     * The cracker backend the UI drives. The native (NDK) engine is used only when it
     * loaded, agrees on the material protocol and passed its own known-answer test on
     * this device; otherwise the JVM engine runs and [crackEngineInfo] states why the
     * native one did not (see `NativeCrypto.unavailableReason`).
     */
    var crackEngine: CrackEngine = NoopCrackEngine
        private set

    /** Which cracker is live and, when it is not the native one, the reason why. */
    var crackEngineInfo: String = "not initialised"
        private set

    override fun onCreate() {
        super.onCreate()
        usb = UsbSerialManager(this)
        settings = SettingsRepository(this)
        captureSink = CaptureSink(this)
        location = LocationRepository(this)
        artifacts = ArtifactsRepository(this)
        wordlists = WordlistsRepository(this)
        artifacts.bridge = PcapExtractionBridge()
        crackEngineInfo = NativeCrypto.unavailableReason?.let { "JVM engine: $it" }
            ?: "native CPU engine (known-answer self-test passed on this device)"
        crackEngine = if (NativeCrypto.available) NativeCpuCrackEngine() else JvmCrackEngine()
    }
}
