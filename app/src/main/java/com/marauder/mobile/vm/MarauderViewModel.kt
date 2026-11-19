package com.marauder.mobile.vm

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.marauder.mobile.MarauderApp
import com.marauder.mobile.capture.CaptureSink
import com.marauder.mobile.data.AnalyzerKind
import com.marauder.mobile.data.ArtifactRecord
import com.marauder.mobile.data.ArtifactsRepository
import com.marauder.mobile.data.GpxAssembler
import com.marauder.mobile.data.DeviceInfoForJournal
import com.marauder.mobile.data.HashExtractResult
import com.marauder.mobile.data.JournalEntry
import com.marauder.mobile.data.ListCsv
import com.marauder.mobile.data.ListType
import com.marauder.mobile.data.LiveClassifier
import com.marauder.mobile.data.NmeaAssembler
import com.marauder.mobile.data.WardriveAssembler
import com.marauder.mobile.data.Wordlist
import com.marauder.mobile.data.WordlistsRepository
import com.marauder.mobile.location.LocationRepository
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.withContext
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import com.marauder.mobile.protocol.CaptureFrame
import com.marauder.mobile.protocol.Crc32
import com.marauder.mobile.protocol.DeviceMessage
import com.marauder.mobile.protocol.LineParser
import com.marauder.mobile.protocol.ParsedLine
import com.marauder.mobile.esp.EspFlasher
import com.marauder.mobile.esp.Firmware
import com.marauder.mobile.esp.FirmwareRepository
import com.marauder.mobile.esp.FlashProfile
import com.marauder.mobile.esp.FlashStage
import com.marauder.mobile.esp.FlashUiState
import com.marauder.mobile.esp.UsbFlashLink
import com.marauder.mobile.usb.UsbSerialManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

enum class LineKind { INPUT, OUTPUT, SYSTEM, ERROR }

data class ConsoleEntry(val id: Long, val text: String, val kind: LineKind)

data class AnalyzerState(
    val kind: AnalyzerKind? = null,
    val samples: List<Int> = emptyList(),
    val channels: List<Int> = emptyList(),
    val values: List<Int> = emptyList(),
    val page: Int = 0,
)

/** Live state of an on-phone capture (pcap streamed to storage, or a wardrive CSV). */
data class CaptureUiState(
    val active: Boolean = false,
    val path: String? = null,
    val kind: String = "",          // "pcap" | "wardrive"
    val bytes: Long = 0,
    val missedFrames: Long = 0,     // gaps in the frame sequence (transport loss)
    val droppedPackets: Long = 0,   // packets the device ring couldn't hold
    val rows: Int = 0,              // wardrive rows written
)

/** Evil Portal with a host-supplied page: pick an HTML file on the phone, stream
 *  it to the device (no SD card), target a scanned AP, then run and watch creds. */
data class EvilPortalUiState(
    val phase: Phase = Phase.NeedsHtml,
    val fileName: String? = null,
    val htmlBytes: Int = 0,
    val deviceMax: Int = 0,         // MAX_HTML_SIZE reported by the device (0 until known)
    val targetApIndex: Int? = null,
    val message: String? = null,
    val creds: List<DeviceMessage.Cred> = emptyList(),
) {
    enum class Phase { NeedsHtml, Uploading, Ready, Running, Error }
    val htmlReady: Boolean get() = phase == Phase.Ready || phase == Phase.Running
}

class MarauderViewModel(application: Application) : AndroidViewModel(application) {

    private val app = application as MarauderApp
    private val usb: UsbSerialManager = app.usb
    private val settings = app.settings
    private val captureSink: CaptureSink = app.captureSink
    private val location: LocationRepository = app.location

    // --- Connection ----------------------------------------------------------
    val status: StateFlow<UsbSerialManager.Status> = usb.status
    val connectedName: StateFlow<String?> = usb.connectedName

    // --- Theme (persisted; dark is the default) ------------------------------
    val darkTheme: StateFlow<Boolean> =
        settings.darkTheme.stateIn(viewModelScope, SharingStarted.Eagerly, true)

    fun toggleTheme() {
        viewModelScope.launch { settings.setDarkTheme(!darkTheme.value) }
    }

    // --- App settings: Lab gate, auto-analysis, serial line rate --------------

    /** High-impact operations get their own Home section when this is on. */
    val labMode: StateFlow<Boolean> =
        settings.labMode.stateIn(viewModelScope, SharingStarted.Eagerly, false)

    /** Extract hashes the moment a capture closes. */
    val autoAnalyze: StateFlow<Boolean> =
        settings.autoAnalyze.stateIn(viewModelScope, SharingStarted.Eagerly, true)

    private val _lineRate = MutableStateFlow(0)

    /** Line rate the user wants (`0` = leave the board at its 115200 default). */
    val lineRate: StateFlow<Int> = _lineRate.asStateFlow()

    private val _activeLineRate = MutableStateFlow(0)

    /** Rate the serial link actually runs at right now (0 = not known yet). */
    val activeLineRate: StateFlow<Int> = _activeLineRate.asStateFlow()

    fun setLabMode(enabled: Boolean) {
        viewModelScope.launch { settings.setLabMode(enabled) }
    }

    fun setAutoAnalyze(enabled: Boolean) {
        viewModelScope.launch { settings.setAutoAnalyze(enabled) }
    }

    /** Rate the board is believed to be at; the app's own default on connect. */
    private var pendingBaud: Int? = null
    private var baudTimeout: Job? = null

    /**
     * Ask the board to change the USB-serial line rate (`jsonbaud <rate>`), and
     * remember the choice. The firmware answers `{"t":"baud"}` at the OLD rate and
     * switches immediately after it, so the acknowledgement is the whole basis of
     * trust: no ack means we keep listening where we were and say so instead of
     * pretending the link got faster. A CH340 bridge that cannot sustain the rate
     * shows up exactly like that — and unplugging/replugging the board brings it
     * back to 115200.
     */
    fun setLineRate(rate: Int) {
        viewModelScope.launch { settings.setLineRate(rate) }
        _lineRate.value = rate
        applyLineRate(rate)
    }

    /** Re-apply the stored line rate (used after a capture negotiation or reconnect). */
    fun applyStoredLineRate() {
        if (_lineRate.value > 0) applyLineRate(_lineRate.value)
    }

    private fun applyLineRate(rate: Int) {
        baudTimeout?.cancel()
        val target = if (rate > 0) rate else DEFAULT_LINE_RATE
        if (target == _activeLineRate.value) return
        pendingBaud = target
        usb.send("jsonbaud $target")
        baudTimeout = viewModelScope.launch {
            delay(BAUD_ACK_TIMEOUT_MS)
            if (pendingBaud == target) {
                pendingBaud = null
                _snackbar.tryEmit(
                    "The board never confirmed $target baud — staying at " +
                        "${_activeLineRate.value.ifZero(DEFAULT_LINE_RATE)}. If the console turned to garbage, " +
                        "unplug and replug the board: it always boots at 115200.",
                )
                appendConsole(
                    "jsonbaud $target not confirmed — keeping ${_activeLineRate.value.ifZero(DEFAULT_LINE_RATE)}",
                    LineKind.ERROR,
                )
            }
        }
    }

    private fun Int.ifZero(fallback: Int): Int = if (this == 0) fallback else this

    // --- Authorised-use notice (asked once, re-shown from About) --------------
    private val _termsAccepted = MutableStateFlow(false)
    val termsAccepted: StateFlow<Boolean> = _termsAccepted.asStateFlow()

    private val _termsVisible = MutableStateFlow(false)
    val termsVisible: StateFlow<Boolean> = _termsVisible.asStateFlow()

    init {
        viewModelScope.launch { settings.termsAccepted.collect { _termsAccepted.value = it } }
        viewModelScope.launch { settings.lineRate.collect { _lineRate.value = it } }
    }

    /** First board contact asks for acceptance; About can bring the notice back. */
    fun showTerms() {
        _termsVisible.value = true
    }

    fun acceptTerms() {
        _termsVisible.value = false
        _termsAccepted.value = true
        viewModelScope.launch { settings.setTermsAccepted(true) }
    }

    // --- Device state --------------------------------------------------------
    private val _info = MutableStateFlow<DeviceMessage.Info?>(null)
    val info: StateFlow<DeviceMessage.Info?> = _info.asStateFlow()

    private val _deviceStatus = MutableStateFlow<DeviceMessage.Status?>(null)
    val deviceStatus: StateFlow<DeviceMessage.Status?> = _deviceStatus.asStateFlow()

    // --- Structured lists ----------------------------------------------------
    private val _aps = MutableStateFlow<List<DeviceMessage.Ap>>(emptyList())
    val aps: StateFlow<List<DeviceMessage.Ap>> = _aps.asStateFlow()
    private val _stations = MutableStateFlow<List<DeviceMessage.Sta>>(emptyList())
    val stations: StateFlow<List<DeviceMessage.Sta>> = _stations.asStateFlow()
    private val _ssids = MutableStateFlow<List<DeviceMessage.SsidRow>>(emptyList())
    val ssids: StateFlow<List<DeviceMessage.SsidRow>> = _ssids.asStateFlow()
    private val _ips = MutableStateFlow<List<DeviceMessage.Ip>>(emptyList())
    val ips: StateFlow<List<DeviceMessage.Ip>> = _ips.asStateFlow()
    private val _probes = MutableStateFlow<List<DeviceMessage.Probe>>(emptyList())
    val probes: StateFlow<List<DeviceMessage.Probe>> = _probes.asStateFlow()
    private val _airtags = MutableStateFlow<List<DeviceMessage.Airtag>>(emptyList())
    val airtags: StateFlow<List<DeviceMessage.Airtag>> = _airtags.asStateFlow()
    // proto >= 3 structured lists
    private val _drones = MutableStateFlow<List<DeviceMessage.Rid>>(emptyList())
    val drones: StateFlow<List<DeviceMessage.Rid>> = _drones.asStateFlow()
    private val _geofences = MutableStateFlow<List<DeviceMessage.Fence>>(emptyList())
    val geofences: StateFlow<List<DeviceMessage.Fence>> = _geofences.asStateFlow()

    // proto >= 3 live streams (latest sample; drives the Fox Hunt / CSI readouts)
    private val _foxHunt = MutableStateFlow<DeviceMessage.FoxHunt?>(null)
    val foxHunt: StateFlow<DeviceMessage.FoxHunt?> = _foxHunt.asStateFlow()
    private val _csi = MutableStateFlow<DeviceMessage.Csi?>(null)
    val csi: StateFlow<DeviceMessage.Csi?> = _csi.asStateFlow()

    private val _listLoading = MutableStateFlow<ListType?>(null)
    val listLoading: StateFlow<ListType?> = _listLoading.asStateFlow()

    // --- Console -------------------------------------------------------------
    private val _console = MutableStateFlow<List<ConsoleEntry>>(emptyList())
    val console: StateFlow<List<ConsoleEntry>> = _console.asStateFlow()

    // --- Analyzer ------------------------------------------------------------
    private val _analyzer = MutableStateFlow(AnalyzerState())
    val analyzer: StateFlow<AnalyzerState> = _analyzer.asStateFlow()

    // --- Firmware flashing ---------------------------------------------------
    private val _flash = MutableStateFlow(FlashUiState())
    val flash: StateFlow<FlashUiState> = _flash.asStateFlow()

    // --- On-phone capture (SD-card / GPS-module replacement) -----------------
    private val _capture = MutableStateFlow(CaptureUiState())
    val capture: StateFlow<CaptureUiState> = _capture.asStateFlow()

    // --- Evil Portal with a host-supplied page (SD-card replacement) ---------
    private val _evilPortal = MutableStateFlow(EvilPortalUiState())
    val evilPortal: StateFlow<EvilPortalUiState> = _evilPortal.asStateFlow()

    // --- Missions (supervised live activities) --------------------------------
    private val artifacts: ArtifactsRepository = app.artifacts
    private val _activeMission = MutableStateFlow<Mission?>(null)
    val activeMission: StateFlow<Mission?> = _activeMission.asStateFlow()
    private var missionSeq = 0L
    private var apPollJob: Job? = null
    private val eapolRx = Regex("Received EAPOL:\\s*([0-9A-Fa-f:]{17})")

    // Upload handshake replies ({"t":"portal",...}); the upload coroutine awaits
    // "recv" then "set". extraBufferCapacity so tryEmit never drops a reply.
    private val portalEvents = MutableSharedFlow<DeviceMessage.Portal>(extraBufferCapacity = 8)
    private var portalJob: Job? = null

    /** True once the connected firmware advertised the proto ≥ 2 "capstream" cap. */
    private var captureCapable = false
    private var negotiated = false
    private var wardriving = false
    private val wardriveSeen = HashSet<String>()

    /** Credentials the portal caught this session (kept so they can be saved as CSV). */
    private val credsSeen = mutableListOf<DeviceMessage.Cred>()

    // Phone-GPS activities (each runs while its live screen is open; the SD-less
    // board has no GPS module, so these are served from the phone's own GNSS).
    private var gpsData = false      // gpsdata / nmea live console
    private var gpsTracking = false  // gpstracker → GPX track file
    private var poiOpen = false      // gpspoi session (persists across screens until -e)
    private var poiOut: OutputStream? = null
    private var poiPath: String? = null
    private var poiCount = 0

    // --- One-shot messages ---------------------------------------------------
    private val _snackbar = MutableSharedFlow<String>(extraBufferCapacity = 16)
    val snackbar: SharedFlow<String> = _snackbar.asSharedFlow()

    /** Show a transient message in the UI (used by screens that act outside the VM). */
    fun queueMessage(text: String) {
        _snackbar.tryEmit(text)
    }

    private val apBuf = ArrayList<DeviceMessage.Ap>()
    private val staBuf = ArrayList<DeviceMessage.Sta>()
    private val ssidBuf = ArrayList<DeviceMessage.SsidRow>()
    private val ipBuf = ArrayList<DeviceMessage.Ip>()
    private val probeBuf = ArrayList<DeviceMessage.Probe>()
    private val airtagBuf = ArrayList<DeviceMessage.Airtag>()
    private val ridBuf = ArrayList<DeviceMessage.Rid>()
    private val fenceBuf = ArrayList<DeviceMessage.Fence>()

    /** bssid → ESSID as the scan list reported it (crack-salt fallback). */
    private val essidsSeen = LinkedHashMap<String, String>()

    private var consoleSeq = 0L
    private var sessionJob: Job? = null
    private var liveJob: Job? = null
    private var flashJob: Job? = null

    init {
        // Copy the built-in wordlist out of the APK once, before the cracker is ever opened.
        viewModelScope.launch(Dispatchers.IO) { app.wordlists.seedBuiltInIfNeeded() }
        viewModelScope.launch { usb.lines.collect(::onLine) }
        viewModelScope.launch {
            // Binary capture frames carved out of the serial stream: append each to
            // the active capture file and keep the UI counters current.
            usb.captureFrames.collect { frame ->
                if (captureSink.isActive) {
                    captureSink.write(frame)
                    _capture.value = _capture.value.copy(
                        bytes = captureSink.bytes,
                        missedFrames = captureSink.missedFrames,
                    )
                    _activeMission.value?.let {
                        if (!it.done) _activeMission.value = it.copy(
                            bytes = captureSink.bytes,
                            missedFrames = captureSink.missedFrames,
                        )
                    }
                }
            }
        }
        viewModelScope.launch {
            usb.events.collect { msg ->
                appendConsole(msg, LineKind.SYSTEM)
                _snackbar.tryEmit(msg)
            }
        }
        viewModelScope.launch {
            // While wardriving, turn each refreshed AP list into WigleWiFi rows.
            aps.collect { if (wardriving) onWardriveAps(it) }
        }
        viewModelScope.launch {
            usb.status.collect { st ->
                when (st) {
                    UsbSerialManager.Status.CONNECTED -> startSession()
                    UsbSerialManager.Status.DISCONNECTED -> {
                        sessionJob?.cancel()
                        onDisconnected()
                    }
                    else -> {}
                }
            }
        }
    }

    // --- Connection API ------------------------------------------------------
    fun availableDevices(): List<UsbSerialManager.DeviceOption> = usb.availableDevices()
    fun connect(option: UsbSerialManager.DeviceOption) = usb.connect(option)
    fun connectFirst(): Boolean = usb.connectFirst()
    fun disconnect() = usb.disconnect()

    // --- Command API ---------------------------------------------------------

    /** Run a firmware command and echo it into the console. */
    fun runCommand(command: String) {
        val text = command.trim()
        if (text.isEmpty()) return
        appendConsole("> $text", LineKind.INPUT)
        usb.send(text)
    }

    fun stopScan() = runCommand("stopscan")

    fun refreshList(type: ListType) {
        bufferFor(type).clear()
        _listLoading.value = type
        usb.send("jsonlist ${type.code}") // internal: not echoed
    }

    fun startAnalyzer(command: String, kind: AnalyzerKind) {
        _analyzer.value = AnalyzerState(kind = kind)
        appendConsole("> $command", LineKind.INPUT)
        usb.send(command)
    }

    /** The id the next console entry will get — capture before [startLiveActivity]
     *  so a live screen can show only the output produced by its own command. */
    fun consoleMark(): Long = consoleSeq

    /** Run [command] and keep its live view fed: poll status (and its list, if any)
     *  every ~1.3 s while it runs so counters and rows update in real time.
     *
     *  When the firmware supports capstream (proto ≥ 2), a pcap-producing command
     *  is streamed to phone storage (`-serial`) instead of the device SD card, and
     *  `wardrive` is served entirely on the phone (AP list + phone GPS → CSV). */
    fun startLiveActivity(command: String, list: ListType?) {
        val trimmed = command.trim()
        val head = trimmed.substringBefore(' ')

        if (head == "wardrive" && captureCapable) {
            startWardrive(trimmed)
            return
        }
        // GPS features are served from the phone's GNSS (the board has no module).
        when (head) {
            "gpsdata" -> { startGpsConsole(nmea = false); return }
            "nmea" -> { startGpsConsole(nmea = true); return }
            "gpstracker" -> { if (trimmed.contains("stop")) stopTracking() else startTracking(); return }
            "gpspoi" -> { handlePoi(trimmed); return }
        }

        val capturing = LiveClassifier.of(trimmed).capture && captureCapable
        if (capturing) {
            val path = captureSink.begin(trimmed.substringBefore(' '), CaptureFrame.TYPE_PCAP)
            _capture.value = CaptureUiState(active = true, path = path, kind = "pcap")
        }

        // Append -serial so the firmware streams the pcap to us over the wire.
        appendConsole("> $trimmed", LineKind.INPUT)
        usb.send(if (capturing) "$trimmed -serial" else trimmed)

        list?.let {
            bufferFor(it).clear()
            _listLoading.value = it
        }
        liveJob?.cancel()
        liveJob = viewModelScope.launch {
            delay(500)
            while (isActive && usb.status.value == UsbSerialManager.Status.CONNECTED) {
                usb.send("jsonstatus")
                if (list != null) usb.send("jsonlist ${list.code}")
                delay(1300)
            }
        }
    }

    /** Leave a live screen: stop polling, close any capture, and for continuous
     *  scans/attacks stop the firmware scan (mirrors pressing Back on the device). */
    fun stopLiveActivity(continuous: Boolean) {
        liveJob?.cancel()
        liveJob = null
        _listLoading.value = null
        if (wardriving) stopWardrive()
        if (gpsTracking) { stopTracking(); return } // stopTracking closes the GPX + capture itself
        if (gpsData) { gpsData = false; maybeStopLocation() }
        if (captureSink.isActive) endCapture()
        // A GPS-only screen (gpsdata/nmea/tracker/poi) never started a device scan,
        // so only send stopscan for real device scans/attacks.
        if (continuous && !gpsData) usb.send("stopscan")
    }

    // --- Mission engine -------------------------------------------------------

    /**
     * Start a supervised live mission: stops whatever the firmware is running,
     * applies [preCommands] (e.g. `select -a 3`), then sends [command]. A
     * CAPTURE mission forces `-serial` (stream to the phone) and finalizes an
     * artifact in the library when it ends. Only one mission at a time.
     */
    fun startMission(
        title: String,
        command: String,
        kind: MissionKind,
        preCommands: List<String> = emptyList(),
        stopOnIdle: Boolean = true,
        target: MissionTarget? = null,
    ): Boolean {
        if (usb.status.value != UsbSerialManager.Status.CONNECTED) return false
        if (_activeMission.value?.done == false) stopMission()

        var cmd = command.trim()
        // Any pcap-writing command gets streamed to the phone (the SD-card replacement),
        // not only the ones the UI labels as captures.
        val capturing = kind == MissionKind.CAPTURE || LiveClassifier.of(cmd).capture
        if (capturing && !captureCapable) {
            _snackbar.tryEmit("This firmware cannot stream captures (no capstream cap)")
            return false
        }

        usb.send("stopscan")
        preCommands.forEach { runCommand(it) }

        if (capturing) {
            if (!cmd.contains("-serial")) cmd += " -serial"
            val path = captureSink.begin(cmd.substringBefore(' '), CaptureFrame.TYPE_PCAP)
            _capture.value = CaptureUiState(active = true, path = path, kind = "pcap")
        }
        runCommand(cmd)
        _activeMission.value = Mission(
            id = missionSeq++,
            title = title,
            kind = kind,
            command = cmd,
            startedAt = System.currentTimeMillis(),
            stopOnIdle = stopOnIdle,
            target = target,
        )
        journalMission("start", title, cmd, kind, target)
        startMissionPolling(cmd)
        return true
    }

    /** Journal line for a mission boundary (start/stop) with its counters. */
    private fun journalMission(
        event: String,
        title: String,
        command: String,
        kind: MissionKind,
        target: MissionTarget?,
        m: Mission? = null,
    ) {
        val meta = mutableMapOf(
            "event" to event,
            "command" to command,
            "kind" to kind.name,
        )
        target?.let {
            meta["target_essid"] = it.essid
            meta["target_bssid"] = it.bssid
            meta["target_channel"] = it.channel.toString()
        }
        if (m != null) {
            meta["seconds"] = (((m.endedAt ?: System.currentTimeMillis()) - m.startedAt) / 1000L).toString()
            meta["bytes"] = m.bytes.toString()
            meta["eapol"] = m.eapolTotal.toString()
            meta["gaps"] = m.missedFrames.toString()
            meta["drops"] = m.ringDrops.toString()
            m.artifactName?.let { meta["artifact"] = it }
        }
        artifacts.journal.record(JournalEntry.MISSION, "$event: $title", meta)
    }

    /** Stop the running mission (and finalize its capture, if any). */
    fun stopMission() {
        val m = _activeMission.value ?: return
        if (m.done) return
        runCommand("stopscan")
        finalizeMission(m, natural = false)
    }

    private fun startMissionPolling(cmd: String) {
        val list = LiveClassifier.of(cmd).list
        liveJob?.cancel()
        liveJob = viewModelScope.launch {
            delay(500)
            while (isActive && usb.status.value == UsbSerialManager.Status.CONNECTED) {
                usb.send("jsonstatus")
                if (list != null) usb.send("jsonlist ${list.code}")
                delay(1300)
            }
        }
    }

    /** The firmware ended the mission on its own (jsonstatus went idle). */
    private fun maybeFinishMission(s: DeviceMessage.Status) {
        val m = _activeMission.value ?: return
        if (m.done) return
        // A capture needs headroom on the board: with little heap left the firmware
        // ring starts shedding frames (or aborts), so stop early and keep what we got.
        if (m.streamsCapture && s.free in 1 until LOW_HEAP_BYTES) {
            runCommand("stopscan")
            finalizeMission(m, natural = false)
            _snackbar.tryEmit("Board memory low (${s.free / 1024} KB) — capture stopped")
            return
        }
        if (!m.stopOnIdle) return
        if (!s.running && System.currentTimeMillis() - m.startedAt > 3000) {
            finalizeMission(m, natural = true)
            _snackbar.tryEmit(if (m.streamsCapture) "Capture finished" else "${m.title} stopped")
        }
    }

    private fun finalizeMission(m: Mission, natural: Boolean) {
        liveJob?.cancel()
        liveJob = null
        var artifactName = m.artifactName
        if (captureSink.isActive) {
            val summary = captureSink.end()
            _capture.value = CaptureUiState(
                path = summary?.path,
                kind = "pcap",
                bytes = summary?.bytes ?: 0L,
                missedFrames = summary?.missedFrames ?: 0L,
            )
            if (summary != null && summary.bytes > 0) {
                artifactName = registerCapture(summary, m)
                // Analyse it right away: the library then tells the user in the
                // same breath whether the capture is crackable, and if not, why.
                artifactName?.let { autoAnalyzeCapture(it) }
            }
        }
        _activeMission.value = m.copy(
            done = true,
            endedAt = System.currentTimeMillis(),
            artifactName = artifactName,
            bytes = captureSink.bytes,
            missedFrames = captureSink.missedFrames,
        )
        journalMission(
            "stop", m.title, m.command, m.kind, m.target,
            _activeMission.value ?: m,
        )
    }

    /** Register a closed capture file as an artifact record; returns its name. */
    private fun registerCapture(s: CaptureSink.Summary, m: Mission?): String? {
        if (s.bytes <= 0 || s.path.isBlank()) return null
        val name = File(s.path).name
        val meta = mutableMapOf(
            "path" to s.path,
            "bytes" to s.bytes.toString(),
        )
        if (s.missedFrames > 0) meta["missedFrames"] = s.missedFrames.toString()
        if (m != null) {
            meta["command"] = m.command
            if (m.eapolTotal > 0) meta["eapolFrames"] = m.eapolTotal.toString()
            if (m.ringDrops > 0) meta["ringDrops"] = m.ringDrops.toString()
        }
        // The salt has to travel with the capture: a Marauder pcap often holds the
        // handshake but no beacon (the ESP32 stays on the target channel), and
        // without the SSID no cracker can derive the PMK.
        synchronized(essidsSeen) {
            essidsSeen.forEach { (bssid, essid) -> meta[ArtifactRecord.SSID_META + bssid] = essid }
        }
        artifacts.store.upsert(
            ArtifactRecord(
                name = name,
                createdAt = System.currentTimeMillis(),
                title = m?.title ?: name,
                kind = name.substringAfterLast('.', ""),
                meta = meta,
            ),
        )
        return name
    }

    /**
     * Remembers which ESSID belongs to which BSSID, as the firmware's scan list
     * reported it. Kept so captures that never caught a beacon can still be
     * turned into crackable hashes (the SSID is the PBKDF2 salt).
     */
    private fun rememberEssids(aps: List<DeviceMessage.Ap>) {
        synchronized(essidsSeen) {
            for (ap in aps) {
                if (ap.essid.isBlank() || ap.bssid.isBlank()) continue
                essidsSeen[ap.bssid.lowercase()] = ap.essid
            }
            while (essidsSeen.size > MAX_ESSIDS_SEEN) {
                essidsSeen.remove(essidsSeen.keys.first())
            }
        }
    }

    /**
     * Extract hashes as soon as a capture closes, and say plainly what came out.
     * "EAPOL frames on the console but 0 handshakes" is the confusing case, so
     * the counters behind the number (which handshake messages arrived, how many
     * records the link dropped) are part of the message.
     */
    private fun autoAnalyzeCapture(name: String) {
        if (!autoAnalyze.value) return
        val live = synchronized(essidsSeen) { HashMap(essidsSeen) }
        viewModelScope.launch(Dispatchers.IO) {
            val r = runCatching { artifacts.analyze(name, live) }.getOrNull() ?: return@launch
            _snackbar.tryEmit(explainExtraction(r))
        }
    }

    /** One honest sentence about what extraction produced, with its counters. */
    private fun explainExtraction(r: HashExtractResult): String {
        val counts = buildString {
            append("frames ${r.frames}, EAPOL ${r.eapolFrames} ")
            append("(M1 ${r.m1}, M2 ${r.m2}, M3 ${r.m3}, M4 ${r.m4})")
            if (r.badRecords > 0) append(", ${r.badRecords} record(s) lost in transit (+${r.lostBytes} B)")
        }
        return if (r.usable) {
            "Capture holds ${r.pmkidCount} PMKID, ${r.handshakeSets} handshake(s) — ready to crack [$counts]"
        } else {
            "No crackable credential in this capture — ${r.note ?: "no PMKID or handshake"} [$counts]"
        }
    }

    /** Watch the firmware console for capture-success lines ("Received EAPOL:"). */
    private fun onConsoleLine(raw: String) {
        val m = _activeMission.value ?: return
        if (m.done || !m.streamsCapture) return
        val match = eapolRx.find(raw) ?: return
        val mac = match.groupValues[1].lowercase()
        _activeMission.value = m.copy(eapol = m.eapol + (mac to (m.eapol[mac] ?: 0) + 1))
    }

    // --- Artifacts ------------------------------------------------------------

    /** Close the session journal (if open) and register it as a library artifact. */
    private fun closeJournalAndRegister() {
        artifacts.journal.close()?.let { artifacts.registerJournal(it) }
    }

    /**
     * Build the session report (report.md + zip of journals, captures and hashes)
     * off the main thread. Returns the archive file so the UI can share it.
     */
    suspend fun exportReport(): File? = withContext(Dispatchers.IO) {
        closeJournalAndRegister()
        val info = _info.value
        val board = info?.let { DeviceInfoForJournal(it.board, it.fw, it.proto) }
        artifacts.exportReport(appVersion(), board)?.archive
    }

    /** Version name of this build, for the report header. */
    private fun appVersion(): String = try {
        val pi = app.packageManager.getPackageInfo(app.packageName, 0)
        "${pi.versionName} (${pi.longVersionCode})"
    } catch (e: Exception) {
        ""
    }

    /**
     * Save the current structured list [type] as a CSV artifact in the library.
     * Returns the artifact name (null when the list is empty or unwritable).
     */
    fun exportListArtifact(type: ListType): String? {
        val out = when (type) {
            ListType.ACCESS_POINTS -> CsvExport("Access points", "aps", ListCsv.aps(_aps.value), _aps.value.size)
            ListType.STATIONS -> CsvExport("Clients", "stations", ListCsv.stations(_stations.value), _stations.value.size)
            ListType.PROBES -> CsvExport("Probe requests", "probes", ListCsv.probes(_probes.value), _probes.value.size)
            ListType.SSIDS -> CsvExport("SSIDs", "ssids", ListCsv.ssids(_ssids.value), _ssids.value.size)
            ListType.IPS -> CsvExport("Hosts", "hosts", ListCsv.ips(_ips.value), _ips.value.size)
            ListType.AIRTAGS -> CsvExport("Trackers", "trackers", ListCsv.airtags(_airtags.value), _airtags.value.size)
            ListType.DRONES -> CsvExport("Remote ID drones", "drones", ListCsv.drones(_drones.value), _drones.value.size)
            ListType.GEOFENCES -> CsvExport(
                "Geofences", "geofences", ListCsv.geofences(_geofences.value), _geofences.value.size,
            )
        }
        if (out.rows == 0) {
            _snackbar.tryEmit("Nothing in this list to save")
            return null
        }
        val record = artifacts.writeCsvArtifact(out.title, out.base, out.csv, out.rows)
        return if (record == null) {
            _snackbar.tryEmit("Could not write ${out.title} CSV")
            null
        } else {
            _snackbar.tryEmit("${out.title} saved: ${record.name} (${out.rows} rows)")
            record.name
        }
    }

    /** Save the credentials the portal caught this session as a CSV artifact. */
    fun exportCredsArtifact(): String? {
        val creds = credsSeen.toList()
        if (creds.isEmpty()) {
            _snackbar.tryEmit("No credentials captured yet")
            return null
        }
        val record = artifacts.writeCsvArtifact(
            "Portal credentials (${creds.size})", "creds", ListCsv.creds(creds), creds.size,
        )
        if (record != null) artifacts.journal.record(
            JournalEntry.NOTE, "saved ${creds.size} credential(s) to ${record.name}",
        )
        return record?.name
    }

    /** One prepared CSV export (title, file base name, content, row count). */
    private data class CsvExport(val title: String, val base: String, val csv: String, val rows: Int)

    fun listArtifacts(): List<com.marauder.mobile.data.Artifact> = artifacts.store.list()

    fun artifact(name: String): com.marauder.mobile.data.Artifact? = artifacts.store.get(name)

    fun deleteArtifact(name: String) = artifacts.store.delete(name)

    fun renameArtifact(name: String, title: String) {
        artifacts.store.get(name)?.let { artifacts.store.upsert(it.record.copy(title = title)) }
    }

    /**
     * Extract hashcat-22000 hashes out of a capture (state is kept on the
     * artifact). The live scan list is passed as the SSID fallback so a capture
     * without a beacon can still be cracked.
     */
    fun analyzeArtifact(name: String): HashExtractResult? =
        artifacts.analyze(name, synchronized(essidsSeen) { HashMap(essidsSeen) })

    /** [analyzeArtifact] off the main thread: parsing a multi-megabyte pcap is not cheap. */
    suspend fun analyzeArtifactSuspending(name: String): HashExtractResult? =
        withContext(Dispatchers.IO) { analyzeArtifact(name) }

    /** Hash lines previously extracted for an artifact (empty when none). */
    fun hashLines(name: String): List<String> = artifacts.hashLines(name)

    /** Crack-ready state of an artifact: none | done | fail. */
    fun artifactHashState(name: String): String =
        artifacts.store.get(name)?.record?.hashState ?: ArtifactRecord.HASH_NONE

    fun artifactFile(name: String): java.io.File? = artifacts.store.get(name)?.file

    /** Where the library (captures, journals, reports, wordlists) lives on this phone. */
    fun artifactsFolder(): String = runCatching { artifacts.store.directory.absolutePath }.getOrDefault("?")

    // --- Wordlists -------------------------------------------------------------

    /** Wordlists kept on the phone: the built-in list plus SAF imports and downloads. */
    val wordlists: WordlistsRepository get() = app.wordlists

    fun listWordlists(): List<Wordlist> = wordlists.store.list()

    fun importWordlist(uri: android.net.Uri): Wordlist? = wordlists.importFrom(uri)

    fun deleteWordlist(fileName: String) = wordlists.store.delete(fileName)

    fun restoreBuiltInWordlist() = wordlists.restoreBuiltIn()

    /** Downloads a wordlist off the main thread; emits byte-level progress. */
    suspend fun downloadWordlist(
        url: String,
        onProgress: (done: Long, total: Long) -> Unit,
    ): Result<Wordlist> = withContext(Dispatchers.IO) {
        runCatching { wordlists.download(url, onProgress) }
    }

    // --- AP list polling (scan screen live updates) ----------------------------

    fun startApPolling() {
        if (apPollJob?.isActive == true) return
        apPollJob = viewModelScope.launch {
            while (isActive && usb.status.value == UsbSerialManager.Status.CONNECTED) {
                usb.send("jsonlist a")
                delay(2000)
            }
        }
    }

    fun stopApPolling() {
        apPollJob?.cancel()
        apPollJob = null
    }

    /** The AP with this firmware list index, or null once it left the list. */
    fun ap(index: Int): DeviceMessage.Ap? = _aps.value.firstOrNull { it.index == index }

    /** Stations the firmware has associated with the AP at this index. */
    fun stationsFor(index: Int): List<DeviceMessage.Sta> = _stations.value.filter { it.ap == index }

    // --- Location permission (requested from the live screen) ----------------

    fun hasLocationPermission(): Boolean = location.hasPermission()

    /** Called back after the runtime permission prompt: (re)start the GNSS for
     *  whatever phone-GPS activity is currently running. */
    fun onLocationPermissionResult(granted: Boolean) {
        if (granted) {
            if (wardriving || gpsData || gpsTracking || poiOpen) location.start()
        } else {
            _snackbar.tryEmit("Location permission denied — GPS features need it")
        }
    }

    // --- Phone GPS: data / NMEA / tracker / POI ------------------------------

    private fun startGpsConsole(nmea: Boolean) {
        gpsData = true
        val ok = location.start()
        appendConsole("> ${if (nmea) "nmea" else "gpsdata"} (phone GPS)", LineKind.INPUT)
        if (!ok) appendConsole("Grant the location permission and turn GPS on to see fixes.", LineKind.SYSTEM)
        liveJob?.cancel()
        liveJob = viewModelScope.launch {
            while (isActive) {
                val l = location.location.value
                when {
                    l == null -> {} // still waiting for a fix
                    nmea -> {
                        appendConsole(NmeaAssembler.gga(l), LineKind.OUTPUT)
                        appendConsole(NmeaAssembler.rmc(l), LineKind.OUTPUT)
                    }
                    else -> appendConsole(
                        "◈ ${"%.6f".format(l.lat)}, ${"%.6f".format(l.lon)} · " +
                            "alt ${"%.1f".format(l.altMeters)} m · ±${"%.0f".format(l.accuracyMeters)} m",
                        LineKind.OUTPUT,
                    )
                }
                delay(1500)
            }
        }
    }

    private fun startTracking() {
        gpsTracking = true
        location.start()
        val path = captureSink.begin("tracker", CaptureFrame.TYPE_GPX)
        captureSink.appendBytes(GpxAssembler.TRACK_HEADER.toByteArray(Charsets.UTF_8))
        _capture.value = CaptureUiState(active = true, path = path, kind = "gpx")
        appendConsole("> gpstracker (phone GPS)", LineKind.INPUT)
        liveJob?.cancel()
        liveJob = viewModelScope.launch {
            // One track point per fresh fix.
            location.location.collectLatest { l ->
                if (l != null && captureSink.isActive) {
                    captureSink.appendBytes(GpxAssembler.trackPoint(l).toByteArray(Charsets.UTF_8))
                    _capture.value = _capture.value.copy(bytes = captureSink.bytes, rows = _capture.value.rows + 1)
                }
            }
        }
    }

    private fun stopTracking() {
        gpsTracking = false
        liveJob?.cancel(); liveJob = null
        if (captureSink.isActive) {
            captureSink.appendBytes(GpxAssembler.TRACK_FOOTER.toByteArray(Charsets.UTF_8))
            endCapture()
        }
        maybeStopLocation()
        appendConsole("Tracker stopped", LineKind.SYSTEM)
    }

    /** POI marking uses its own file (independent of [captureSink]) so it can span
     *  screens: -s opens it, -m adds a waypoint, -e closes it. */
    private fun handlePoi(cmd: String) {
        location.start()
        when {
            cmd.contains("-e") -> closePoi()
            cmd.contains("-m") -> {
                openPoiIfNeeded()
                val l = location.location.value
                if (l == null) appendConsole("No GPS fix yet — POI not marked", LineKind.SYSTEM)
                else {
                    poiCount++
                    runCatching { poiOut?.write(GpxAssembler.waypoint(l, "POI $poiCount").toByteArray(Charsets.UTF_8)) }
                    appendConsole("POI #$poiCount marked at ${"%.6f".format(l.lat)}, ${"%.6f".format(l.lon)}", LineKind.SYSTEM)
                }
            }
            else -> { openPoiIfNeeded(); appendConsole("POI session started (phone GPS)", LineKind.INPUT) }
        }
    }

    private fun openPoiIfNeeded() {
        if (poiOut != null) return
        runCatching {
            val dir = File(app.getExternalFilesDir(null), "captures").apply { mkdirs() }
            var i = 0
            var f: File
            do { f = File(dir, "poi_$i.gpx"); i++ } while (f.exists())
            poiOut = BufferedOutputStream(FileOutputStream(f)).also {
                it.write(GpxAssembler.POI_HEADER.toByteArray(Charsets.UTF_8))
            }
            poiPath = f.absolutePath
            poiCount = 0
            poiOpen = true
        }
    }

    private fun closePoi() {
        val out = poiOut ?: run { appendConsole("No POI session open", LineKind.SYSTEM); return }
        runCatching {
            out.write(GpxAssembler.POI_FOOTER.toByteArray(Charsets.UTF_8))
            out.flush(); out.close()
        }
        appendConsole("POI saved ($poiCount points): ${poiPath}", LineKind.SYSTEM)
        _snackbar.tryEmit("POI saved: $poiPath")
        poiOut = null; poiPath = null; poiOpen = false
        maybeStopLocation()
    }

    /** Turn the GNSS off only when no phone-GPS activity still needs it. */
    private fun maybeStopLocation() {
        if (!wardriving && !gpsData && !gpsTracking && !poiOpen) location.stop()
    }

    // --- On-phone capture helpers --------------------------------------------

    /** On the first proto ≥ 2 handshake, enable saving to serial.
     *
     *  The line rate is opt-in from Settings, never silently raised: on the common
     *  CH340 USB-UART bridge a high rate is unreliable — the device switches fine
     *  but the bridge cannot sustain it, corrupting the link, and the device then
     *  speaks a rate the phone is not listening at until it is reset. So the app
     *  only applies a rate the user chose, waits for the board's `{"t":"baud"}`
     *  confirmation (sent at the OLD rate) before matching it, and reports plainly
     *  when that confirmation never arrives. Replugging the board always returns it
     *  to 115200. */
    private fun negotiateCapture(info: DeviceMessage.Info) {
        captureCapable = info.proto >= 2 || info.has("capstream")
        _activeLineRate.value = usb.baud
        if (!captureCapable || negotiated) return
        negotiated = true
        viewModelScope.launch {
            usb.send("settings -s SavePCAP enable")
            // A capture needs bytes, and 115200 is ~11 KB/s — the board's own ring
            // then sheds frames ({"t":"drop"}) and the pcap arrives with holes. The
            // line rate is therefore a user setting: applied only when they raised
            // it, and only trusted once the board confirms the switch.
            applyStoredLineRate()
        }
    }

    private fun endCapture() {
        val summary = captureSink.end()
        _capture.value = _capture.value.copy(
            active = false,
            path = summary?.path ?: _capture.value.path,
            bytes = summary?.bytes ?: _capture.value.bytes,
            missedFrames = summary?.missedFrames ?: _capture.value.missedFrames,
        )
        summary?.let {
            val registered = registerCapture(it, _activeMission.value)
            if (registered != null) autoAnalyzeCapture(registered)
            _snackbar.tryEmit("Capture saved: ${it.bytes} B → ${it.path}")
        }
    }

    /** Wardrive using the phone's GPS: run a continuous AP scan and write a
     *  WigleWiFi CSV, tagging each newly-seen AP with the phone's current fix. */
    private fun startWardrive(command: String) {
        wardriving = true
        wardriveSeen.clear()
        val located = location.start()
        // WigleWiFi content in a .log file — same as the official Marauder's
        // /wardrive_N.log on SD (rename to .csv before a WiGLE upload).
        val path = captureSink.beginFile("wardrive", "log")
        captureSink.appendBytes(WardriveAssembler.header(APP_RELEASE).toByteArray(Charsets.UTF_8))
        _capture.value = CaptureUiState(active = true, path = path, kind = "wardrive")
        if (!located) _snackbar.tryEmit("Location permission/GPS off — rows will log without a fix")

        appendConsole("> $command (phone GPS)", LineKind.INPUT)
        usb.send("scanall")
        apBuf.clear()
        _listLoading.value = ListType.ACCESS_POINTS
        liveJob?.cancel()
        liveJob = viewModelScope.launch {
            delay(500)
            while (isActive && usb.status.value == UsbSerialManager.Status.CONNECTED) {
                usb.send("jsonstatus")
                usb.send("jsonlist a")
                delay(1300)
            }
        }
    }

    private fun stopWardrive() {
        wardriving = false
        maybeStopLocation()
    }

    /** Append a WigleWiFi row for every AP seen for the first time this session. */
    private fun onWardriveAps(list: List<DeviceMessage.Ap>) {
        val loc = location.location.value
        var added = 0
        for (ap in list) {
            if (ap.bssid.isBlank()) continue
            if (wardriveSeen.add(ap.bssid)) {
                captureSink.appendBytes(WardriveAssembler.line(ap, loc).toByteArray(Charsets.UTF_8))
                added++
            }
        }
        if (added > 0) {
            _capture.value = _capture.value.copy(bytes = captureSink.bytes, rows = wardriveSeen.size)
        }
    }

    fun clearConsole() {
        _console.value = emptyList()
    }

    // --- Firmware flashing ---------------------------------------------------

    /** USB serial adapters currently on the bus, offered as flash targets. */
    fun availableFlashDevices(): List<UsbSerialManager.DeviceOption> = usb.availableDevices()

    /** Clear a finished (done/failed) flash result so the screen returns to idle. */
    fun resetFlashState() {
        if (_flash.value.inProgress) return
        _flash.value = FlashUiState()
    }

    // --- Evil Portal (host-supplied HTML page) -------------------------------

    /** Reset the Evil Portal flow — call when the screen opens. */
    fun resetEvilPortal() {
        portalJob?.cancel()
        _evilPortal.value = EvilPortalUiState()
    }

    /** Choose which scanned AP (by list index) the portal impersonates. */
    fun setPortalTargetAp(index: Int?) {
        _evilPortal.value = _evilPortal.value.copy(targetApIndex = index)
    }

    /**
     * Stream a phone-picked HTML page into the device's Evil Portal buffer so no
     * SD card is needed. Sends `evilportal -c sethtmlstr <len>`, waits for the
     * device's `{"t":"portal","state":"recv"}` reply, streams exactly <len> bytes,
     * then verifies the `{"t":"portal","state":"set"}` reply (byte count + CRC-32).
     */
    fun uploadPortalHtml(bytes: ByteArray, fileName: String) {
        if (bytes.isEmpty()) { _snackbar.tryEmit("Empty HTML file"); return }
        portalJob?.cancel()
        portalJob = viewModelScope.launch {
            _evilPortal.value = _evilPortal.value.copy(
                phase = EvilPortalUiState.Phase.Uploading,
                fileName = fileName,
                htmlBytes = bytes.size,
                message = "Uploading ${bytes.size} B…",
            )
            var recv: DeviceMessage.Portal? = null
            var set: DeviceMessage.Portal? = null
            // Hold the serial write lock across the whole handshake so a background
            // `jsonstatus` poll can't inject bytes into the raw payload (which would
            // corrupt it and fail the device's CRC check).
            usb.withWriteLock {
                coroutineScope {
                    // Start listening BEFORE sending so the reply can't be missed.
                    val recvWait = async { withTimeoutOrNull(3000) { portalEvents.first { it.state == "recv" } } }
                    appendConsole("> evilportal -c sethtmlstr ${bytes.size}", LineKind.INPUT)
                    usb.sendLineLocked("evilportal -c sethtmlstr ${bytes.size}")
                    recv = recvWait.await()
                    appendConsole(
                        recv?.let { "portal ▸ recv ok (device max ${it.max} B)" }
                            ?: "portal ▸ recv TIMEOUT — no reply in 3 s",
                        LineKind.SYSTEM,
                    )
                    // Send the payload unless the device said its buffer is too small.
                    if (recv?.max?.let { it in 1 until bytes.size } != true) {
                        val setWait = async { withTimeoutOrNull(8000) { portalEvents.first { it.state == "set" } } }
                        appendConsole("portal ▸ streaming ${bytes.size} B…", LineKind.SYSTEM)
                        usb.sendRawLocked(bytes)
                        set = setWait.await()
                        appendConsole(
                            set?.let { "portal ▸ set n=${it.bytes} crc=${it.crc} ok=${it.ok}" }
                                ?: "portal ▸ set TIMEOUT — no confirm in 8 s",
                            LineKind.SYSTEM,
                        )
                    } else {
                        appendConsole("portal ▸ skipped: ${bytes.size} B > device max ${recv?.max} B", LineKind.SYSTEM)
                    }
                }
            }

            val r = recv
            val s = set
            val localCrc = Crc32.compute(bytes, 0, bytes.size, ByteArray(0), 0)
            _evilPortal.value = when {
                r != null && r.max in 1 until bytes.size -> _evilPortal.value.copy(
                    phase = EvilPortalUiState.Phase.Error,
                    deviceMax = r.max,
                    message = "Page too large: ${bytes.size} B > device max ${r.max} B",
                )
                s == null -> _evilPortal.value.copy(
                    phase = EvilPortalUiState.Phase.Error,
                    message = "No confirmation from device — check the cable and retry",
                )
                s.ok && s.crc == localCrc -> _evilPortal.value.copy(
                    phase = EvilPortalUiState.Phase.Ready,
                    deviceMax = if (s.max > 0) s.max else _evilPortal.value.deviceMax,
                    message = "Page set on device — ${s.bytes} B, CRC verified",
                )
                s.ok -> _evilPortal.value.copy(
                    phase = EvilPortalUiState.Phase.Error,
                    message = "CRC mismatch (device ${s.crc}, phone $localCrc) — retry",
                )
                else -> _evilPortal.value.copy(
                    phase = EvilPortalUiState.Phase.Error,
                    message = "Device rejected the upload (${s.bytes}/${bytes.size} B) — retry",
                )
            }
        }
    }

    /** Start the portal on the chosen AP (the page must already be uploaded). */
    fun startEvilPortal() {
        val st = _evilPortal.value
        if (!st.htmlReady) { _snackbar.tryEmit("Upload an HTML page first"); return }
        st.targetApIndex?.let { runCommand("evilportal -c setap $it") }
        runCommand("evilportal -c start")
        _evilPortal.value = st.copy(phase = EvilPortalUiState.Phase.Running, creds = emptyList())
        liveJob?.cancel()
        liveJob = viewModelScope.launch {
            delay(500)
            while (isActive && usb.status.value == UsbSerialManager.Status.CONNECTED) {
                usb.send("jsonstatus")
                delay(1300)
            }
        }
    }

    /** Stop the running portal (mirrors Back / stopscan on the device). */
    fun stopEvilPortal() {
        liveJob?.cancel(); liveJob = null
        runCommand("stopscan")
        if (_evilPortal.value.phase == EvilPortalUiState.Phase.Running) {
            _evilPortal.value = _evilPortal.value.copy(phase = EvilPortalUiState.Phase.Ready)
        }
    }

    /**
     * Download the firmware for [profile] from the pinned GitHub release and flash it
     * to [option] over USB. Frees the normal serial session first (the port can only
     * be held once). Progress and the final result are published on [flash].
     */
    fun startFlash(option: UsbSerialManager.DeviceOption, profile: FlashProfile = Firmware.DEFAULT) {
        if (flashJob?.isActive == true) return
        val app = getApplication<Application>()
        flashJob = viewModelScope.launch(Dispatchers.IO) {
            val link = UsbFlashLink(app, option.driver)
            try {
                setFlash(FlashStage.CONNECT, 0f, "Preparing…")
                if (usb.status.value != UsbSerialManager.Status.DISCONNECTED) {
                    usb.disconnect()
                    delay(400)
                }

                val repo = FirmwareRepository()
                val sums = repo.checksums()
                val images = profile.parts.map { part ->
                    setFlash(FlashStage.DOWNLOAD, 0f, "Downloading ${part.assetName}")
                    val bytes = repo.download(part.assetName) { f ->
                        setFlash(FlashStage.DOWNLOAD, f, "Downloading ${part.assetName} · ${(f * 100).toInt()}%")
                    }
                    sums[part.assetName]?.let { repo.verifySha256(part.assetName, bytes, it) }
                    part.offset to bytes
                }

                setFlash(FlashStage.CONNECT, 0f, "Opening USB port…")
                link.open()
                EspFlasher(link).flash(images) { p -> setFlash(p.stage, p.fraction, p.message) }
            } catch (e: Exception) {
                setFlash(FlashStage.ERROR, _flash.value.fraction, e.message ?: "Flash failed")
                _snackbar.tryEmit("Flash failed: ${e.message}")
            } finally {
                runCatching { link.close() }
            }
        }
    }

    private fun setFlash(stage: FlashStage, fraction: Float, message: String) {
        val cur = _flash.value
        val log = if (stage != cur.stage || cur.log.isEmpty()) (cur.log + message).takeLast(40) else cur.log
        _flash.value = FlashUiState(stage, fraction, message, log)
    }

    // --- Incoming ------------------------------------------------------------
    private fun onLine(line: String) {
        when (val parsed = LineParser.parse(line)) {
            is ParsedLine.Console -> if (parsed.raw.isNotBlank()) {
                onConsoleLine(parsed.raw)
                appendConsole(parsed.raw, LineKind.OUTPUT)
            }
            is ParsedLine.Malformed -> appendConsole(parsed.raw, LineKind.OUTPUT)
            is ParsedLine.Structured -> handleMessage(parsed.message)
        }
    }

    private fun handleMessage(msg: DeviceMessage) {
        when (msg) {
            is DeviceMessage.Info -> {
                _info.value = msg
                appendConsole(
                    "◈ ${msg.board} · fw ${msg.fw} · proto ${msg.proto} · [${msg.caps.joinToString(", ")}]",
                    LineKind.SYSTEM,
                )
                closeJournalAndRegister()
                artifacts.journal.open(DeviceInfoForJournal(msg.board, msg.fw, msg.proto))
                negotiateCapture(msg)                // The first time a board reports in, make the user accept the
                // authorised-use notice before any command can be sent.
                if (!_termsAccepted.value) _termsVisible.value = true
            }
            is DeviceMessage.Status -> {
                _deviceStatus.value = msg
                maybeFinishMission(msg)
            }
            is DeviceMessage.JsonMode ->
                appendConsole("JSON mode ${if (msg.on) "enabled" else "disabled"}", LineKind.SYSTEM)
            is DeviceMessage.Baud -> {
                // The device confirmed the new rate (sent at the OLD rate) and has
                // switched; match it so the faster link is used from here on.
                usb.setBaud(msg.rate)
                _activeLineRate.value = msg.rate
                if (pendingBaud == msg.rate) {
                    pendingBaud = null
                    baudTimeout?.cancel()
                    _snackbar.tryEmit("Serial link is now ${msg.rate} baud")
                }
                appendConsole("Serial rate → ${msg.rate} baud", LineKind.SYSTEM)
            }
            is DeviceMessage.Drop -> {
                _capture.value = _capture.value.copy(
                    droppedPackets = _capture.value.droppedPackets + msg.n,
                )
                _activeMission.value?.let {
                    if (!it.done) _activeMission.value = it.copy(ringDrops = it.ringDrops + msg.n)
                }
            }
            is DeviceMessage.Ap -> apBuf.add(msg)
            is DeviceMessage.Sta -> staBuf.add(msg)
            is DeviceMessage.SsidRow -> ssidBuf.add(msg)
            is DeviceMessage.Ip -> ipBuf.add(msg)
            is DeviceMessage.Probe -> probeBuf.add(msg)
            is DeviceMessage.Airtag -> airtagBuf.add(msg)
            is DeviceMessage.Rid -> ridBuf.add(msg)
            is DeviceMessage.Fence -> fenceBuf.add(msg)
            is DeviceMessage.End -> commitList(msg.list)
            is DeviceMessage.Err -> {
                appendConsole("✗ ${msg.cmd} ${msg.arg}".trim(), LineKind.ERROR)
                artifacts.journal.record(
                    JournalEntry.ERROR, "device error: ${msg.cmd}",
                    mapOf("cmd" to msg.cmd, "arg" to msg.arg),
                )
                _snackbar.tryEmit("Device error: ${msg.cmd}")
            }
            is DeviceMessage.AnalyzerSample -> onSample(msg)
            is DeviceMessage.ChannelActivity -> onChannelActivity(msg)
            is DeviceMessage.FoxHunt -> _foxHunt.value = msg
            is DeviceMessage.Csi -> _csi.value = msg
            is DeviceMessage.Portal -> portalEvents.tryEmit(msg)
            is DeviceMessage.Cred -> {
                _evilPortal.value = _evilPortal.value.copy(
                    creds = _evilPortal.value.creds + msg,
                )
                artifacts.journal.record(
                    JournalEntry.CRED, "portal credential",
                    mapOf("user" to msg.user, "pass" to msg.pass),
                )
                credsSeen.add(msg)
                appendConsole("⚑ credential — ${msg.user} : ${msg.pass}", LineKind.OUTPUT)
            }
            is DeviceMessage.Unknown -> {}
        }
    }

    private fun commitList(listCode: String) {
        when (listCode) {
            "a" -> {
                _aps.value = apBuf.toList()
                rememberEssids(apBuf)
                apBuf.clear()
            }
            "s" -> { _ssids.value = ssidBuf.toList(); ssidBuf.clear() }
            "c" -> { _stations.value = staBuf.toList(); staBuf.clear() }
            "i" -> { _ips.value = ipBuf.toList(); ipBuf.clear() }
            "p" -> { _probes.value = probeBuf.toList(); probeBuf.clear() }
            "t" -> { _airtags.value = airtagBuf.toList(); airtagBuf.clear() }
            "d" -> { _drones.value = ridBuf.toList(); ridBuf.clear() }
            "g" -> { _geofences.value = fenceBuf.toList(); fenceBuf.clear() }
        }
        _listLoading.value = null
    }

    private fun onSample(s: DeviceMessage.AnalyzerSample) {
        val cur = _analyzer.value
        val next = (cur.samples + s.value).takeLast(MAX_SAMPLES)
        _analyzer.value = cur.copy(samples = next)
    }

    private fun onChannelActivity(c: DeviceMessage.ChannelActivity) {
        _analyzer.value = _analyzer.value.copy(
            channels = c.channels,
            values = c.values,
            page = c.page,
        )
    }

    // --- Session lifecycle ---------------------------------------------------
    private fun startSession() {
        sessionJob?.cancel()
        sessionJob = viewModelScope.launch {
            // A fresh connection may pulse the ESP32 auto-reset line; give it time
            // to finish booting, then handshake (twice, in case the first is lost).
            delay(350)
            usb.send("jsoninfo")
            delay(1300)
            if (!isActive) return@launch
            usb.send("jsoninfo")
            delay(200)
            usb.send("jsonstatus")
            while (isActive && usb.status.value == UsbSerialManager.Status.CONNECTED) {
                delay(2500)
                usb.send("jsonstatus")
            }
        }
    }

    private fun onDisconnected() {
        _info.value = null
        _deviceStatus.value = null
        _aps.value = emptyList()
        _stations.value = emptyList()
        _ssids.value = emptyList()
        _ips.value = emptyList()
        _probes.value = emptyList()
        _airtags.value = emptyList()
        _analyzer.value = AnalyzerState()
        _listLoading.value = null
        // Close any device-fed capture and reset per-connection negotiation. Phone
        // GPS activities (tracker/POI) are independent of the device link, so leave
        // them running; only drop the GNSS if nothing still needs it. Any partial
        // capture is still registered as an artifact — loss should not be silent.
        if (captureSink.isActive && !gpsTracking) endCapture()
        closeJournalAndRegister()
        _activeMission.value = null
        wardriving = false
        maybeStopLocation()
        negotiated = false
        captureCapable = false
        if (!gpsTracking) _capture.value = CaptureUiState()
    }

    // --- Helpers -------------------------------------------------------------
    private fun bufferFor(type: ListType): ArrayList<*> = when (type) {
        ListType.ACCESS_POINTS -> apBuf
        ListType.SSIDS -> ssidBuf
        ListType.STATIONS -> staBuf
        ListType.IPS -> ipBuf
        ListType.PROBES -> probeBuf
        ListType.AIRTAGS -> airtagBuf
        ListType.DRONES -> ridBuf
        ListType.GEOFENCES -> fenceBuf
    }

    private fun appendConsole(text: String, kind: LineKind) {
        val entry = ConsoleEntry(consoleSeq++, text, kind)
        _console.value = (_console.value + entry).takeLast(MAX_CONSOLE)
        journalConsole(text, kind)
    }

    /** Mirror the console into the session journal (commands and errors always kept). */
    private fun journalConsole(text: String, kind: LineKind) {
        when (kind) {
            LineKind.INPUT -> artifacts.journal.record(
                JournalEntry.COMMAND, text, mapOf("command" to text.removePrefix("> ").trim()),
            )
            LineKind.ERROR -> artifacts.journal.record(JournalEntry.ERROR, text)
            LineKind.SYSTEM -> artifacts.journal.record(JournalEntry.NOTE, text)
            LineKind.OUTPUT -> artifacts.journal.output(text)
        }
    }

    companion object {
        private const val MAX_CONSOLE = 800
        private const val MAX_SAMPLES = 120
        private const val MAX_ESSIDS_SEEN = 64

        /** What the board boots at; also what a replug always returns to. */
        private const val DEFAULT_LINE_RATE = 115200

        /** How long to wait for the firmware's `{"t":"baud"}` confirmation. */
        private const val BAUD_ACK_TIMEOUT_MS = 3000L

        /** Free heap (bytes) below which a streaming capture is stopped early. */
        private const val LOW_HEAP_BYTES = 40_000L

        private const val APP_RELEASE = "marauder-kiddy"
    }
}
