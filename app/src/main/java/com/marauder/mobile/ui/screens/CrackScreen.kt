package com.marauder.mobile.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.marauder.mobile.crack.Backend
import com.marauder.mobile.crack.MeasuredRate
import com.marauder.mobile.data.KeyManagement
import com.marauder.mobile.data.Wordlist
import com.marauder.mobile.ui.components.SectionLabel
import com.marauder.mobile.ui.components.StatChip
import com.marauder.mobile.ui.theme.CatAttack
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.MarauderCyan
import com.marauder.mobile.ui.theme.MarauderTextDim
import com.marauder.mobile.ui.theme.Success
import com.marauder.mobile.ui.theme.Warning
import com.marauder.mobile.vm.CrackViewModel
import kotlin.math.roundToLong

/**
 * The cracker: target hashes come from an already-extracted capture, wordlists from
 * the library, and the run is driven through the engine contract (CPU today, GPU
 * when the native build offers it). Nothing here knows how the maths is done.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CrackScreen(
    artifactName: String,
    onBack: () -> Unit,
    onOpenWordlists: () -> Unit,
    cvm: CrackViewModel = viewModel(),
) {
    val state by cvm.state.collectAsState()
    LaunchedEffect(artifactName) { cvm.open(artifactName) }

    // A WPA3-SAE-only target cannot be recovered by mode 22000, so starting such a
    // run is a deliberate extra confirmation rather than a silent tap.
    var pendingSaeRun by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Crack") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
                actions = {
                    IconButton(onClick = {
                        cvm.refreshWordlists()
                        onOpenWordlists()
                    }) {
                        Icon(Icons.Filled.Storage, contentDescription = "Wordlists", tint = MarauderCyan)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
            )
        },
    ) { inner ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(inner),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item {
                TargetCard(
                    title = state.targetTitle,
                    pmkid = state.pmkid,
                    handshakes = state.handshakes,
                    lines = state.hashLines.size,
                    cracked = state.alreadyCracked ?: state.found.values.firstOrNull(),
                )
            }

            state.found.entries.sortedBy { it.key }.forEach { (index, password) ->
                item { FoundCard(index = index, password = password) }
            }

            state.error?.let { err ->
                item {
                    Text(err, style = MaterialTheme.typography.bodySmall, color = Danger)
                }
            }

            if (state.hashLines.isEmpty()) {
                item {
                    Text(
                        "This capture has no extracted hashes yet. Go back to the artifact and use Extract hashes first.",
                        style = MaterialTheme.typography.bodySmall,
                        color = Warning,
                    )
                }
            }

            item { SectionLabel("Wordlists (tried in this order)") }
            if (state.wordlists.isEmpty()) {
                item {
                    Text(
                        "No wordlists on the phone. Open Wordlists to import one or download the built-in list.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MarauderTextDim,
                    )
                }
            }
            itemsIndexed(state.wordlists, key = { _, it -> it.fileName }) { _, list ->
                WordlistPick(
                    list = list,
                    order = state.selected.indexOf(list.fileName).let { if (it < 0) null else it + 1 },
                    onToggle = { cvm.toggleWordlist(list.fileName) },
                )
            }

            if (state.inspections.isNotEmpty()) {
                item { SectionLabel("Hash under test") }
                state.inspections.forEach { insp ->
                    item {
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(
                                insp.label,
                                style = MaterialTheme.typography.labelMedium,
                                color = if (insp.crackable) MarauderCyan else Danger,
                            )
                            Text(
                                buildString {
                                    append("AP ${insp.ap} · client ${insp.sta}")
                                    if (insp.eapolBytes > 0) append(" · EAPOL ${insp.eapolBytes} B")
                                    if (insp.essidHex.isNotEmpty()) append(" · SSID bytes ${insp.essidHex}")
                                },
                                style = MaterialTheme.typography.labelSmall,
                                color = MarauderTextDim,
                            )
                            insp.notes.forEach {
                                Text(it, style = MaterialTheme.typography.labelSmall, color = MarauderTextDim)
                            }
                            insp.problems.forEach {
                                Text("• $it", style = MaterialTheme.typography.bodySmall, color = Danger)
                            }
                        }
                    }
                }
                if (state.inspections.none { it.crackable }) {
                    item {
                        Text(
                            "None of these records can be recovered from this capture — re-extract it (Extract hashes) " +
                                "after reconnecting the board, or capture again: the reasons are listed above.",
                            style = MaterialTheme.typography.bodySmall,
                            color = Warning,
                        )
                    }
                }
            }

            if (state.saeOnly.isNotEmpty()) {
                item { SectionLabel("WPA3-SAE inside this target") }
                item {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(
                            KeyManagement.explainSae(state.saeOnly, state.aimedBssid).orEmpty(),
                            style = MaterialTheme.typography.bodySmall,
                            color = Danger,
                        )
                        Text(
                            "SAE-only BSSID(s): " + state.saeOnly.joinToString(),
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = MarauderTextDim,
                        )
                    }
                }
            }

            item { SectionLabel("Backend") }
            item {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Backend.entries.forEach { backend ->
                            Choice(
                                label = backend.name,
                                hint = when (backend) {
                                    Backend.AUTO -> "graphics cores when the driver proves them"
                                    Backend.CPU -> "phone cores"
                                    Backend.GPU -> "graphics cores"
                                },
                                selected = state.backend == backend,
                                onClick = { cvm.setBackend(backend) },
                            )
                        }
                    }
                    // Which cracker each back end really is on this device. A run whose rate
                    // came from a different engine than the one selected here is a number
                    // nobody can interpret, and a GPU that the driver cannot prove correct is
                    // not a GPU at all, so both lines are stated rather than assumed.
                    state.engineReport.forEach { line ->
                        Text(
                            line,
                            style = MaterialTheme.typography.labelSmall,
                            color = MarauderTextDim,
                        )
                    }
                    // What AUTO actually settled on for this run, in the words the driver gate
                    // produced. Stated only once it has been asked, because before that the app would
                    // be naming an engine it has not checked.
                    state.autoWhy?.let { why ->
                        Text(
                            why,
                            style = MaterialTheme.typography.labelSmall,
                            color = MarauderCyan,
                        )
                    }
                }
            }

            item {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    RunButton(
                        running = state.running,
                        enabled = state.canRun || state.running,
                        onStart = {
                            if (state.saeOnly.isNotEmpty()) pendingSaeRun = true else cvm.start()
                        },
                        onStop = { cvm.stop() },
                        modifier = Modifier.weight(1.4f),
                    )
                    BenchButton(
                        rate = state.benchRate,
                        busy = state.benching,
                        onClick = { cvm.bench() },
                        modifier = Modifier.weight(1f),
                    )
                }
            }

            if (state.running || state.doneGuesses > 0) {
                item {
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            LinearProgressIndicator(
                                progress = { state.progress },
                                modifier = Modifier.fillMaxWidth().height(7.dp),
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                StatChip("TRIED", formatCount(state.doneGuesses), MarauderCyan)
                                StatChip(
                                    "RATE",
                                    if (state.rate > 0) "${formatCount(state.rate.roundToLong())} h/s" else "measuring…",
                                    Success,
                                )
                                StatChip(
                                    "ETA",
                                    // Only meaningful once a rate sample exists and there is
                                    // actually something left: "0s" reads like a bug.
                                    if (state.rate > 0 && state.totalGuesses > state.doneGuesses) {
                                        formatSeconds(((state.totalGuesses - state.doneGuesses) / state.rate).toLong())
                                    } else "—",
                                    MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            if (state.exhausted && state.found.isEmpty()) {
                                Text(
                                    "The wordlists were tried to the end without recovering this password. A bigger list, rules, or a weaker candidate is the usual next step.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Warning,
                                )
                            }
                        }
                    }
                }
            }

            item {
                Text(
                    "Cracking here means testing candidate passwords against the hashes you captured. Only do that for networks you own or have written permission to audit.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MarauderTextDim,
                )
            }
        }
    }

    if (pendingSaeRun) {
        AlertDialog(
            onDismissRequest = { pendingSaeRun = false },
            icon = { Icon(Icons.Filled.Stop, contentDescription = null, tint = Danger) },
            title = { Text("This run cannot succeed") },
            text = {
                Text(
                    (KeyManagement.explainSae(state.saeOnly, state.aimedBssid).orEmpty()) +
                        "\n\nRunning the wordlist anyway will spend the phone's time and report " +
                        "\"not found\" without the password ever having been testable.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    pendingSaeRun = false
                    cvm.start()
                }) { Text("Run anyway", color = Warning) }
            },
            dismissButton = { TextButton(onClick = { pendingSaeRun = false }) { Text("Stop here") } },
        )
    }
}

@Composable
private fun TargetCard(title: String, pmkid: Int, handshakes: Int, lines: Int, cracked: String?) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatChip("PMKID", pmkid.toString(), if (pmkid > 0) Success else MaterialTheme.colorScheme.onSurfaceVariant)
                StatChip("HANDSHAKES", handshakes.toString(), if (handshakes > 0) Success else MaterialTheme.colorScheme.onSurfaceVariant)
                StatChip("HASH LINES", lines.toString(), MarauderCyan)
            }
            if (!cracked.isNullOrBlank()) {
                Text(
                    "Recovered before: $cracked",
                    style = MaterialTheme.typography.bodyMedium,
                    color = Success,
                    fontWeight = FontWeight.Bold,
                )
            }
        }
    }
}

@Composable
private fun FoundCard(index: Int, password: String) {
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = Success.copy(alpha = 0.16f),
        border = BorderStroke(1.dp, Success),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Check, contentDescription = null, tint = Success, modifier = Modifier.size(24.dp))
            Column(Modifier.weight(1f).padding(start = 12.dp)) {
                Text("Password found", style = MaterialTheme.typography.labelMedium, color = Success)
                Text(
                    password,
                    style = MaterialTheme.typography.titleLarge,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.Bold,
                )
                Text("hash #${index + 1}", style = MaterialTheme.typography.labelSmall, color = MarauderTextDim)
            }
        }
    }
}

@Composable
private fun WordlistPick(list: Wordlist, order: Int?, onToggle: () -> Unit) {
    val selected = order != null
    Surface(
        onClick = onToggle,
        shape = RoundedCornerShape(12.dp),
        color = if (selected) MarauderCyan.copy(alpha = 0.12f) else MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, if (selected) MarauderCyan else MaterialTheme.colorScheme.outline),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(26.dp).clip(RoundedCornerShape(8.dp))
                    .background(if (selected) MarauderCyan.copy(alpha = 0.25f) else Color.Transparent),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    order?.toString() ?: "-",
                    style = MaterialTheme.typography.labelMedium,
                    color = if (selected) MarauderCyan else MarauderTextDim,
                    fontWeight = FontWeight.Bold,
                )
            }
            Column(Modifier.weight(1f).padding(start = 10.dp)) {
                Text(list.label, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    "${formatCount(list.lines)} guesses · ${formatSize(list.bytes)}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MarauderTextDim,
                )
            }
        }
    }
}

@Composable
private fun Choice(label: String, hint: String, selected: Boolean, onClick: () -> Unit) {
    val tint = if (selected) MarauderCyan else MaterialTheme.colorScheme.onSurfaceVariant
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(10.dp),
        color = tint.copy(alpha = if (selected) 0.16f else 0.06f),
    ) {
        Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
            Text(label, style = MaterialTheme.typography.labelLarge, color = tint, fontWeight = FontWeight.Bold)
            Text(hint, style = MaterialTheme.typography.labelSmall, color = MarauderTextDim)
        }
    }
}

@Composable
private fun RunButton(running: Boolean, enabled: Boolean, onStart: () -> Unit, onStop: () -> Unit, modifier: Modifier = Modifier) {
    val tint = if (running) Danger else CatAttack
    Surface(
        onClick = if (running) onStop else onStart,
        enabled = enabled,
        shape = RoundedCornerShape(13.dp),
        color = tint.copy(alpha = if (enabled) 0.16f else 0.05f),
        border = BorderStroke(1.dp, tint.copy(alpha = if (enabled) 0.5f else 0.15f)),
        modifier = modifier,
    ) {
        Row(Modifier.padding(vertical = 15.dp), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
            Icon(
                if (running) Icons.Filled.Stop else Icons.Filled.PlayArrow,
                contentDescription = null,
                tint = if (enabled) tint else MarauderTextDim,
                modifier = Modifier.size(20.dp),
            )
            Spacer(Modifier.width(7.dp))
            Text(
                if (running) "Stop" else "Start cracking",
                style = MaterialTheme.typography.titleMedium,
                color = if (enabled) tint else MarauderTextDim,
                fontWeight = FontWeight.Bold,
            )
        }
    }
}

@Composable
private fun BenchButton(rate: MeasuredRate?, busy: Boolean, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Surface(
        onClick = onClick,
        enabled = !busy,
        shape = RoundedCornerShape(13.dp),
        color = MarauderCyan.copy(alpha = 0.10f),
        modifier = modifier,
    ) {
        Column(Modifier.padding(vertical = 12.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                if (rate != null) Icons.Filled.Speed else Icons.Filled.Memory,
                contentDescription = null,
                tint = MarauderCyan,
                modifier = Modifier.size(18.dp),
            )
            Spacer(Modifier.height(5.dp))
            Text(
                when {
                    busy -> "Benching…"
                    rate != null -> "${formatCount(rate.guessesPerSecond)} h/s"
                    else -> "Run bench"
                },
                style = MaterialTheme.typography.labelLarge,
                color = MarauderCyan,
                fontWeight = FontWeight.SemiBold,
            )
            // The sample the rate came from is printed next to it: a throughput figure whose size is
            // invisible cannot be judged, and this one is what the ETA is extrapolated from.
            Text(
                rate?.let { "over ${it.samples} guesses" } ?: "engine check",
                style = MaterialTheme.typography.labelSmall,
                color = MarauderTextDim,
            )
        }
    }
}

private fun formatCount(value: Long): String = when {
    value >= 1_000_000_000 -> "%.2f B".format(value / 1_000_000_000.0)
    value >= 1_000_000 -> "%.2f M".format(value / 1_000_000.0)
    value >= 1_000 -> "%.1f k".format(value / 1_000.0)
    else -> value.toString()
}

private fun formatSeconds(seconds: Long): String = when {
    seconds >= 3600 -> "${seconds / 3600} h ${seconds % 3600 / 60} m"
    seconds >= 60 -> "${seconds / 60} m ${seconds % 60} s"
    else -> "$seconds s"
}
