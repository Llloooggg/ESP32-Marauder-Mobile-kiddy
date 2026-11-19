package com.marauder.mobile.vm

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.marauder.mobile.MarauderApp
import com.marauder.mobile.crack.Backend
import com.marauder.mobile.crack.CrackConfig
import com.marauder.mobile.crack.CrackEvent
import com.marauder.extractor.CrackCore
import com.marauder.extractor.HashInspection
import com.marauder.mobile.data.ArtifactRecord
import com.marauder.mobile.data.KeyManagement
import com.marauder.mobile.data.Wordlist
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
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
    val benchRate: Long? = null,
    val benching: Boolean = false,

    val running: Boolean = false,
    val doneGuesses: Long = 0L,
    val totalGuesses: Long = 0L,
    val rate: Double = 0.0,
    val found: Map<Int, String> = emptyMap(),
    val exhausted: Boolean = false,
    val error: String? = null,

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
     * Which cracker this build is running. The native engine is used only when it
     * loaded, agrees on the target-material protocol and passed its known-answer
     * self-test on this device; when it did not, this says why, instead of the UI
     * quietly running a different engine than the one it implies.
     */
    val engineInfo: String = "",
) {
    val canRun: Boolean get() = hashLines.isNotEmpty() && selected.isNotEmpty() && !running
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
    private val engine get() = app.crackEngine

    private val _state = MutableStateFlow(CrackUiState())
    val state: StateFlow<CrackUiState> = _state.asStateFlow()

    private var runJob: Job? = null
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
            pmkid = record?.meta?.get("pmkid")?.toIntOrNull() ?: 0,
            handshakes = record?.meta?.get("handshakes")?.toIntOrNull() ?: 0,
            alreadyCracked = record?.meta?.get("cracked"),
            saeOnly = KeyManagement.saeOnly(record?.meta ?: emptyMap()),
            aimedBssid = record?.meta?.get(ArtifactRecord.TARGET_BSSID),
            engineInfo = app.crackEngineInfo,
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
        _state.value = _state.value.copy(backend = backend)
    }

    fun bench() {
        val s = _state.value
        if (s.benching) return
        _state.value = s.copy(benching = true, error = null)
        viewModelScope.launch {
            val rate = runCatching { engine.bench() }.getOrNull()
            _state.value = _state.value.copy(
                benching = false,
                benchRate = rate,
                error = if (rate == null) "No native cracker is linked into this build yet" else null,
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
            // The engine counts words tried (one PBKDF2 per network per word), so the
            // denominator must be words too — otherwise the bar and the ETA lie.
            totalGuesses = s.totalWords,
            rate = 0.0,
            found = emptyMap(),
            exhausted = false,
            error = null,
        )
        runJob = viewModelScope.launch {
            engine.run(config).collect { event ->
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

                    is CrackEvent.Finished -> _state.value = _state.value.copy(
                        running = false,
                        exhausted = event.completed,
                    )

                    is CrackEvent.Error -> _state.value = _state.value.copy(error = event.message, running = false)
                }
            }
        }
    }

    fun stop() {
        engine.stop()
        runJob?.cancel()
        runJob = null
        _state.value = _state.value.copy(running = false)
    }

    /** Wordlist files as the engine will see them (for the summary line). */
    fun selectedFiles(): List<File> = _state.value.selected.map { app.wordlists.store.file(it) }

    override fun onCleared() {
        engine.stop()
        super.onCleared()
    }
}
