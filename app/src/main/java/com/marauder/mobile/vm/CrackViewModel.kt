package com.marauder.mobile.vm

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.marauder.mobile.MarauderApp
import com.marauder.mobile.crack.Backend
import com.marauder.mobile.crack.CrackConfig
import com.marauder.mobile.crack.CrackEngine
import com.marauder.mobile.crack.CrackEvent
import com.marauder.mobile.crack.MeasuredRate
import com.marauder.extractor.CrackCore
import com.marauder.extractor.HashInspection
import com.marauder.mobile.data.ArtifactRecord
import com.marauder.mobile.data.KeyManagement
import com.marauder.mobile.data.Wordlist
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/** Everything the crack screen shows about one attempt. */
data class CrackUiState(
    val targetName: String = "",
    val targetTitle: String = "",
    val hashLines: List<String> = emptyList(),
    val pmkid: Int = 0,
    val handshakes: Int = 0,
    val alreadyCracked: String? = null,

    val wordlists: List<Wordlist> = emptyList(),
    /** File names of the chosen wordlists, in the order they will be tried. */
    val selected: List<String> = emptyList(),

    val backend: Backend = Backend.AUTO,
    val benchRate: MeasuredRate? = null,
    val benching: Boolean = false,

    /**
     * What `AUTO` settled on for the current run, in words. Only set while a run (or a measurement)
     * resolved it, because reading the driver's verdict is GPU work that must not happen in a click
     * handler — which also means the app never states an engine it has not just checked.
     */
    val autoWhy: String? = null,

    val running: Boolean = false,
    val doneGuesses: Long = 0L,
    val totalGuesses: Long = 0L,

    /**
     * The stop was asked for and the engine is still finishing the unit it had already been handed
     * (a GPU batch is not interruptible from the UI). Reported rather than hidden, because the run
     * looks frozen while it happens.
     */
    val stopping: Boolean = false,

    /** This run ended because the user stopped it, not because the lists ran out. */
    val stopped: Boolean = false,

    /** Words the engine had read out of a wordlist and never hashed; see [CrackEvent.Finished]. */
    val discardedWords: Int = 0,
    val rate: Double = 0.0,
    val found: Map<Int, String> = emptyMap(),
    val exhausted: Boolean = false,
    val error: String? = null,

    /**
     * How many lines the cracker will actually verify (the rest are reported line by
     * line in [inspections]). A run over zero testable hashes can only spend time and
     * end in "not found", so it is not offered.
     */
    val testable: Int = 0,

    /**
     * What each extracted hash line really holds, with the reasons a line cannot
     * be cracked. This is the answer to "I tried the right password and it did
     * not match" — the line, not the password, is usually the problem.
     */
    val inspections: List<HashInspection> = emptyList(),

    /**
     * BSSIDs in this target that advertise WPA3-SAE only, plus the BSSID the capture
     * was aimed at. A 22000 line cannot be recovered from an SAE-only network (its
     * PMK is not PBKDF2-derived), so the screen warns before burning wordlist time.
     */
    val saeOnly: List<String> = emptyList(),
    val aimedBssid: String? = null,

    /**
     * Which cracker each backend choice really runs on this device, and why. The native
     * engine is used only when it loaded, agrees on the target-material protocol and passed
     * its known-answer self-test here; a GPU run additionally checks the graphics driver
     * before it spends wordlist time. When a back end is not available this says so,
     * instead of the UI quietly running something other than what it implies.
     */
    val engineReport: List<String> = emptyList(),
) {
    val canRun: Boolean get() = hashLines.isNotEmpty() && selected.isNotEmpty() && !running && testable > 0
    val progress: Float get() = if (totalGuesses <= 0) 0f else (doneGuesses.toFloat() / totalGuesses).coerceIn(0f, 1f)
    val totalWords: Long get() = wordlists.filter { it.fileName in selected }.sumOf { it.lines }
}

/**
 * Drives the built-in cracker through the [com.marauder.mobile.crack.CrackEngine]
 * contract: target hashes come from an artifact, wordlists from the wordlist
 * library, and every found password is written back onto the artifact so the
 * result survives the session.
 */
class CrackViewModel(application: Application) : AndroidViewModel(application) {

    private val app = application as MarauderApp

    /**
     * The engine a running session is actually using. `stop()` and `onCleared()` have to
     * reach that instance rather than whatever the backend selection says now — if the user
     * changes the backend while a run is going, stopping it must still stop the run, not
     * the engine they just switched to.
     */
    private var activeEngine: CrackEngine = app.engineFor(Backend.AUTO)

    private val _state = MutableStateFlow(CrackUiState())
    val state: StateFlow<CrackUiState> = _state.asStateFlow()

    private var runJob: Job? = null

    /** Backstop for [stop]: ends the collector only if the engine never reports its own end. */
    private var stopGrace: Job? = null
    private var pendingArtifact: String? = null

    /** Load the artifact's extracted hashes and the wordlist library. */
    fun open(artifactName: String) {
        pendingArtifact = artifactName
        val record = app.artifacts.store.get(artifactName)?.record
        val lines = app.artifacts.hashLines(artifactName)
        val wordlists = app.wordlists.store.list()
        _state.value = _state.value.copy(
            targetName = artifactName,
            targetTitle = record?.title?.ifBlank { artifactName } ?: artifactName,
            hashLines = lines,
            inspections = lines.map { CrackCore.inspect(it) },
            testable = lines.count { CrackCore.parse(it) != null },
            pmkid = record?.meta?.get("pmkid")?.toIntOrNull() ?: 0,
            handshakes = record?.meta?.get("handshakes")?.toIntOrNull() ?: 0,
            alreadyCracked = record?.meta?.get("cracked"),
            saeOnly = KeyManagement.saeOnly(record?.meta ?: emptyMap()),
            aimedBssid = record?.meta?.get(ArtifactRecord.TARGET_BSSID),
            engineReport = app.engineReport(_state.value.backend),
            wordlists = wordlists,
            selected = _state.value.selected.filter { name -> wordlists.any { it.fileName == name } }
                .ifEmpty { listOfNotNull(app.wordlists.preferredWordlist()?.fileName) },
        )
    }

    fun refreshWordlists() {
        val wordlists = app.wordlists.store.list()
        _state.value = _state.value.copy(
            wordlists = wordlists,
            selected = _state.value.selected.filter { name -> wordlists.any { it.fileName == name } },
        )
    }

    /** Tap to add / remove a wordlist; the order is the order they get tried in. */
    fun toggleWordlist(fileName: String) {
        val current = _state.value.selected
        _state.value = _state.value.copy(
            selected = if (fileName in current) current - fileName else current + fileName,
        )
    }

    fun setBackend(backend: Backend) {
        _state.value = _state.value.copy(
            backend = backend,
            engineReport = app.engineReport(backend),
        )
    }

    fun bench() {
        val s = _state.value
        if (s.benching) return
        _state.value = s.copy(benching = true, error = null)
        viewModelScope.launch {
            // Measuring the engine that will actually run, which for `AUTO` means resolving it first
            // — on a worker thread, because the answer comes from the graphics driver. A rate for an
            // engine the run would not have used is a number the ETA then cannot keep.
            val resolved = if (s.backend == Backend.AUTO) {
                val choice = withContext(Dispatchers.IO) { app.pickAuto() }
                _state.value = _state.value.copy(autoWhy = choice.why)
                choice.backend
            } else s.backend
            val engine = app.engineFor(resolved)
            activeEngine = engine
            val rate = runCatching { engine.bench() }.getOrNull()
            _state.value = _state.value.copy(
                benching = false,
                benchRate = rate,
                engineReport = app.engineReport(resolved),
                error = if (rate == null) "The $resolved engine cannot be measured on this device" else null,
            )
        }
    }

    fun start() {
        val s = _state.value
        if (!s.canRun) return
        val config = CrackConfig(
            hashLines = s.hashLines,
            wordlists = s.selected.map { app.wordlists.store.file(it) }.filter { it.isFile },
            backend = s.backend,
        )
        if (config.wordlists.isEmpty()) {
            _state.value = s.copy(error = "The selected wordlist files are gone")
            return
        }
        runJob?.cancel()
        _state.value = s.copy(
            running = true,
            doneGuesses = 0L,
            engineReport = app.engineReport(s.backend),
            // The engine counts words tried (one PBKDF2 per network per word), so the
            // denominator must be words too — otherwise the bar and the ETA lie.
            totalGuesses = s.totalWords,
            rate = 0.0,
            found = emptyMap(),
            exhausted = false,
            stopping = false,
            stopped = false,
            discardedWords = 0,
            error = null,
        )
        runJob = viewModelScope.launch {
            // `AUTO` is resolved here rather than in the click handler: reading what the graphics
            // driver can really do is real GPU work. The sentence it returns is kept, so the screen
            // can state which engine this run is using instead of implying it from the chip the user
            // happened to leave selected.
            val resolved = if (s.backend == Backend.AUTO) {
                val choice = withContext(Dispatchers.IO) { app.pickAuto() }
                _state.value = _state.value.copy(autoWhy = choice.why)
                choice.backend
            } else s.backend
            // Bound once per run: the flow below and stop() must talk to the same instance even
            // if the backend selection changes mid-run.
            val engine = app.engineFor(resolved)
            activeEngine = engine
            engine.run(config.copy(backend = resolved)).collect { event ->
                when (event) {
                    is CrackEvent.Progress -> _state.value = _state.value.copy(
                        doneGuesses = event.done,
                        totalGuesses = if (event.total > 0) event.total else _state.value.totalGuesses,
                        rate = event.rate,
                    )

                    is CrackEvent.Found -> {
                        _state.value = _state.value.copy(found = _state.value.found + (event.hashIndex to event.password))
                        pendingArtifact?.let { app.artifacts.markCracked(it, event.password) }
                    }

                    is CrackEvent.Finished -> {
                        stopGrace?.cancel()
                        stopGrace = null
                        _state.value = _state.value.copy(
                            running = false,
                            stopping = false,
                            exhausted = event.completed,
                            discardedWords = event.discardedWords,
                        )
                    }

                    is CrackEvent.Error -> _state.value = _state.value.copy(error = event.message, running = false)
                }
            }
        }
    }

    /**
     * Asks the running engine to stop, and then lets it finish reporting.
     *
     * A stop is noticed at a batch boundary — a GPU batch is the unit the driver was already handed —
     * so the run keeps working for a moment after the press, and the engine's `Finished` carries how
     * many words it had read and chose not to hash. Cancelling the collector here, as this function
     * used to do, threw that report away and left the screen holding a guess count whose meaning had
     * quietly changed. So the press only asks: the engine's own events end the run, and [stopGrace] is
     * the backstop for an engine that never reports at all.
     */
    fun stop() {
        val s = _state.value
        if (!s.running || s.stopping) return
        activeEngine.stop()
        _state.value = s.copy(stopping = true, stopped = true)
        stopGrace?.cancel()
        stopGrace = viewModelScope.launch {
            delay(STOP_GRACE_MS)
            if (_state.value.running) {
                runJob?.cancel()
                runJob = null
                _state.value = _state.value.copy(running = false, stopping = false)
            }
        }
    }

    /** Wordlist files as the engine will see them (for the summary line). */
    fun selectedFiles(): List<File> = _state.value.selected.map { app.wordlists.store.file(it) }

    private companion object {
        /**
         * How long a stopped run is allowed to take finishing the unit it was already handed. A GPU
         * batch is a driver round-trip, so a couple of seconds is ordinary; past this the app stops
         * waiting rather than reporting a run that is still going.
         */
        const val STOP_GRACE_MS = 8_000L
    }

    override fun onCleared() {
        activeEngine.stop()
        super.onCleared()
    }
}
