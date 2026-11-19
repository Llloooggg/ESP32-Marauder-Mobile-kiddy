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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.marauder.mobile.data.CaptureOps
import com.marauder.mobile.data.LiveClassifier
import com.marauder.mobile.ui.components.ConnectionDot
import com.marauder.mobile.ui.components.LogPane
import com.marauder.mobile.ui.components.StatChip
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.MarauderCyan
import com.marauder.mobile.ui.theme.MarauderTextDim
import com.marauder.mobile.ui.theme.Success
import com.marauder.mobile.ui.theme.Warning
import com.marauder.mobile.vm.MarauderViewModel
import com.marauder.mobile.vm.Mission
import com.marauder.mobile.vm.MissionKind
import kotlinx.coroutines.delay

/**
 * The supervising view of one mission: counters for what the board is producing
 * (bytes streamed, EAPOL frames caught, transport gaps, firmware ring drops), the
 * live list it feeds if any, and its raw output. Leaving this screen does not stop
 * the mission — the Home card keeps it visible.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MissionScreen(
    missionId: Long,
    vm: MarauderViewModel,
    onBack: () -> Unit,
) {
    val mission by vm.activeMission.collectAsState()
    val capture by vm.capture.collectAsState()
    val console by vm.console.collectAsState()

    val m = mission
    val mark = remember(missionId) { vm.consoleMark() }
    var tab by remember { mutableIntStateOf(0) }

    var now by remember(missionId) { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(missionId) {
        while (true) {
            delay(1000)
            now = System.currentTimeMillis()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(m?.title ?: "Mission") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
                actions = {
                    if (m != null && !m.done) {
                        IconButton(onClick = { vm.stopMission() }) {
                            Icon(Icons.Filled.Stop, contentDescription = "Stop mission", tint = Danger)
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
            )
        },
    ) { inner ->
        if (m == null || m.id != missionId) {
            Box(Modifier.fillMaxSize().padding(inner), contentAlignment = Alignment.Center) {
                Text(
                    "This mission has ended.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MarauderTextDim,
                )
            }
            return@Scaffold
        }

        val spec = remember(m.command) { LiveClassifier.of(m.command) }
        val runSeconds = ((m.endedAt ?: now) - m.startedAt) / 1000
        val output = console.filter { it.id >= mark }
        val tabs = buildList {
            add("Run")
            if (spec.isList) add("Devices")
            add("Output")
        }

        Column(modifier = Modifier.fillMaxSize().padding(inner)) {

            MissionHeader(m, runSeconds)

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                if (!m.done) {
                    Surface(
                        onClick = { vm.stopMission() },
                        shape = RoundedCornerShape(11.dp),
                        color = Danger.copy(alpha = 0.15f),
                    ) {
                        Row(Modifier.padding(horizontal = 14.dp, vertical = 9.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.Stop, contentDescription = null, tint = Danger, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Stop", style = MaterialTheme.typography.labelLarge, color = Danger, fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
                m.artifactName?.let { name ->
                    Surface(
                        shape = RoundedCornerShape(11.dp),
                        color = Success.copy(alpha = 0.13f),
                    ) {
                        Row(Modifier.padding(horizontal = 14.dp, vertical = 9.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.Folder, contentDescription = null, tint = Success, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(name, style = MaterialTheme.typography.labelLarge, color = Success)
                        }
                    }
                }
            }

            TabRow(selectedTabIndex = tab.coerceAtMost(tabs.lastIndex), containerColor = MaterialTheme.colorScheme.background) {
                tabs.forEachIndexed { index, label ->
                    Tab(selected = tab == index, onClick = { tab = index }, text = { Text(label) })
                }
            }

            Box(Modifier.fillMaxSize()) {
                when (tab) {
                    0 -> MissionDetails(m, capture.bytes, capture.missedFrames, capture.droppedPackets)
                    1 -> if (spec.isList) ListContent(type = spec.list!!, vm = vm, showActions = false)
                          else LogPane(output)
                    else -> LogPane(output)
                }
            }
        }
    }
}

@Composable
private fun MissionHeader(m: Mission, seconds: Long) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = Modifier.fillMaxWidth().padding(16.dp),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                ConnectionDot(color = if (m.done) MarauderTextDim else MarauderCyan, pulsing = !m.done)
                Spacer(Modifier.width(8.dp))
                Text(
                    if (m.done) "Finished · $seconds s" else "Running · $seconds s",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
            Text(
                "$ ${m.command}",
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
                color = MarauderCyan,
            )
        }
    }
}

@Composable
private fun MissionDetails(
    m: Mission,
    bytes: Long,
    missedFrames: Long,
    droppedPackets: Long,
) {
    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatChip("EAPOL", m.eapolTotal.toString(), if (m.eapolTotal > 0) Success else Warning)
                // Which side of the handshake those frames came from. A run where only the target AP
                // transmits cannot end in a hash, whatever the EAPOL count says.
                if (m.eapolSide == CaptureOps.EapolSide.ACCESS_POINT) {
                    StatChip("EAPOL AP-ONLY", m.eapolTotal.toString(), Warning)
                }
                StatChip("STREAMED", "%.1f KB".format(bytes / 1024.0), MarauderCyan)
                StatChip("GAPS", missedFrames.toString(), if (missedFrames > 0) Warning else MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatChip("RING DROPS", droppedPackets.toString(), if (droppedPackets > 0) Danger else MaterialTheme.colorScheme.onSurfaceVariant)
                StatChip("KIND", m.kind.name, MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        if (m.eapol.isNotEmpty()) {
            item {
                Text("EAPOL frames caught", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
            }
            items(m.eapol.entries.sortedByDescending { it.value }, key = { it.key }) { entry ->
                // The MAC the firmware prints after "Received EAPOL:" is the frame's transmitter
                // (WiFiScan.cpp:10639-10643 reads addr2), so this row says who put the frame on the
                // air. The target access point sending hundreds of them means it is repeating itself
                // at a client that never answers - a capture that cannot end in a hash.
                val side = CaptureOps.eapolSide(entry.key, m.target?.bssid)
                val tint = when (side) {
                    CaptureOps.EapolSide.CLIENT -> Success
                    CaptureOps.EapolSide.ACCESS_POINT -> Warning
                    CaptureOps.EapolSide.UNKNOWN -> MaterialTheme.colorScheme.onSurfaceVariant
                }
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.surface,
                    border = BorderStroke(1.dp, tint.copy(alpha = 0.4f)),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(Modifier.padding(11.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(
                                entry.key,
                                style = MaterialTheme.typography.bodyMedium,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                            Text(
                                when (side) {
                                    CaptureOps.EapolSide.CLIENT -> "client side — the frames a handshake is missing without them"
                                    CaptureOps.EapolSide.ACCESS_POINT ->
                                        "the network this run is aimed at itself — repeating at a client that has not answered"
                                    CaptureOps.EapolSide.UNKNOWN -> "transmitter (this run is not pinned to one network)"
                                },
                                style = MaterialTheme.typography.labelSmall,
                                color = tint,
                            )
                        }
                        Box(
                            Modifier.clip(RoundedCornerShape(6.dp)).background(tint.copy(alpha = 0.15f))
                                .padding(horizontal = 8.dp, vertical = 3.dp),
                        ) {
                            Text("×${entry.value}", style = MaterialTheme.typography.labelMedium, color = tint)
                        }
                    }
                }
            }
            item {
                Text(
                    "Two frames from opposite sides (the access point's M1 and the client's M2), or a PMKID, " +
                        "are what cracking needs. Frames from one side only — however many of them there " +
                        "are — cannot be paired.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MarauderTextDim,
                )
            }
        } else if (m.streamsCapture) {
            item {
                Text(
                    if (m.done) "No EAPOL frame was reported by the firmware. Keep the capture running while a client reconnects, or use the active capture (it forces the reconnection)."
                    else "Waiting for a handshake. The board reports each EAPOL frame here as it lands.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MarauderTextDim,
                )
            }
        }

        if (m.kind == MissionKind.ATTACK) {
            item {
                Text(
                    "This attack sends frames continuously and writes no file — stop it when you have seen enough.",
                    style = MaterialTheme.typography.bodySmall,
                    color = Warning,
                )
            }
        }
    }
}
