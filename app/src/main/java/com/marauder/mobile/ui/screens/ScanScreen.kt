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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PermScanWifi
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.marauder.mobile.data.ListType
import com.marauder.mobile.data.Security
import com.marauder.mobile.protocol.DeviceMessage
import com.marauder.mobile.ui.components.EmptyState
import com.marauder.mobile.ui.components.StatChip
import com.marauder.mobile.ui.theme.CatWifi
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.MarauderCyan
import com.marauder.mobile.ui.theme.MarauderTextDim
import com.marauder.mobile.ui.theme.Success
import com.marauder.mobile.ui.theme.Warning
import com.marauder.mobile.vm.MarauderViewModel
import com.marauder.mobile.vm.MissionKind

/** How the AP list is ordered — the three things that decide which target to attack. */
enum class ApSort(val label: String) {
    SIGNAL("Signal"),
    CLIENTS("Clients"),
    PACKETS("Packets"),
    CHANNEL("Channel"),
}

/**
 * The target picker: starts `scanall`, keeps the AP list refreshing live while it
 * runs, and turns each network into a card you can open to capture a handshake.
 * Leaving the screen stops the polling but leaves a running scan untouched (the
 * mission card on Home keeps it visible).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(
    vm: MarauderViewModel,
    onBack: () -> Unit,
    onOpenAp: (Int) -> Unit,
    onOpenMission: (Long) -> Unit,
) {
    val aps by vm.aps.collectAsState()
    val mission by vm.activeMission.collectAsState()
    var query by rememberSaveable { mutableStateOf("") }
    var sort by rememberSaveable { mutableStateOf(ApSort.SIGNAL) }

    // Keep the firmware AP list fresh while this screen is on screen.
    LaunchedEffect(Unit) { vm.startApPolling() }
    DisposableEffect(Unit) {
        onDispose { vm.stopApPolling() }
    }

    val scanning = mission?.done == false && mission?.kind == MissionKind.SCAN
    val eapolByMac = mission?.eapol ?: emptyMap()

    val visible = remember(aps, query, sort, eapolByMac) {
        val q = query.trim().lowercase()
        aps.asSequence()
            .filter { q.isEmpty() || it.essid.lowercase().contains(q) || it.bssid.lowercase().contains(q) }
            .sortedWith(apComparator(sort).thenByDescending { it.eapolCount(eapolByMac) })
            .toList()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Scan · ${aps.size} AP") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
                actions = {
                    IconButton(onClick = { vm.refreshList(ListType.ACCESS_POINTS) }) {
                        Icon(Icons.Filled.Refresh, contentDescription = "Refresh", tint = MarauderCyan)
                    }
                    if (scanning) {
                        IconButton(onClick = { vm.stopMission() }) {
                            Icon(Icons.Filled.Stop, contentDescription = "Stop scan", tint = Danger)
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
        Column(modifier = Modifier.fillMaxSize().padding(inner)) {

            PrimaryButton(
                scanning = scanning,
                onStart = { vm.startMission("Scan networks", "scanall", MissionKind.SCAN) },
                onStop = { vm.stopMission() },
            )

            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
                singleLine = true,
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null, tint = MarauderTextDim) },
                placeholder = { Text("Filter by name or MAC", color = MarauderTextDim) },
            )

            Row(
                modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                ApSort.entries.forEach { option ->
                    SortChip(
                        label = option.label,
                        selected = sort == option,
                        onClick = { sort = option },
                    )
                }
            }

            mission?.takeIf { it.eapolTotal > 0 }?.let { m ->
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    StatChip("EAPOL", m.eapolTotal.toString(), Success)
                    Text(
                        "captured in ${m.title}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MarauderTextDim,
                    )
                }
            }

            Box(Modifier.fillMaxSize()) {
                if (visible.isEmpty()) {
                    EmptyState(
                        icon = Icons.Filled.PermScanWifi,
                        title = if (aps.isEmpty()) "No access points yet" else "Nothing matches",
                        subtitle = if (aps.isEmpty()) "Tap Scan and hold — the board hop-scans every channel." else "Clear the filter to see all networks.",
                        modifier = Modifier.align(Alignment.Center),
                    )
                } else {
                    LazyColumn(
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(visible, key = { it.index }) { ap ->
                            ApCard(
                                ap = ap,
                                eapol = ap.eapolCount(eapolByMac),
                                onClick = { onOpenAp(ap.index) },
                            )
                        }
                    }
                }
            }
        }
    }
}

/** The firmware reports EAPOL per MAC; the AP list keys it by BSSID. */
private fun DeviceMessage.Ap.eapolCount(byMac: Map<String, Int>): Int =
    byMac[bssid.lowercase()] ?: 0

/** AP ordering the target picker offers; signal is always the secondary key. */
private fun apComparator(sort: ApSort): Comparator<DeviceMessage.Ap> = when (sort) {
    ApSort.SIGNAL -> compareByDescending<DeviceMessage.Ap> { it.rssi }
    ApSort.CLIENTS -> compareByDescending<DeviceMessage.Ap> { it.stations }.thenByDescending { it.rssi }
    ApSort.PACKETS -> compareByDescending<DeviceMessage.Ap> { it.packets }.thenByDescending { it.rssi }
    ApSort.CHANNEL -> compareBy<DeviceMessage.Ap> { it.channel }.thenByDescending { it.rssi }
}

@Composable
private fun PrimaryButton(scanning: Boolean, onStart: () -> Unit, onStop: () -> Unit) {
    val tint = if (scanning) Danger else CatWifi
    Surface(
        onClick = if (scanning) onStop else onStart,
        shape = RoundedCornerShape(14.dp),
        color = tint.copy(alpha = 0.14f),
        border = BorderStroke(1.dp, tint.copy(alpha = 0.5f)),
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
    ) {
        Row(Modifier.padding(vertical = 16.dp), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
            Icon(if (scanning) Icons.Filled.Stop else Icons.Filled.PlayArrow, contentDescription = null, tint = tint, modifier = Modifier.size(22.dp))
            Spacer(Modifier.width(8.dp))
            Text(
                if (scanning) "Stop scan" else "Scan networks",
                style = MaterialTheme.typography.titleMedium,
                color = tint,
                fontWeight = FontWeight.Bold,
            )
        }
    }
}

@Composable
private fun SortChip(label: String, selected: Boolean, onClick: () -> Unit) {
    val color = if (selected) MarauderCyan else MaterialTheme.colorScheme.onSurfaceVariant
    Surface(onClick = onClick, shape = RoundedCornerShape(9.dp), color = color.copy(alpha = if (selected) 0.18f else 0.07f)) {
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = color,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
        )
    }
}

@Composable
private fun ApCard(ap: DeviceMessage.Ap, eapol: Int, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(13.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    ap.essid.ifBlank { "(hidden network)" },
                    style = MaterialTheme.typography.titleMedium,
                    color = if (ap.essid.isBlank()) MarauderTextDim else MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (eapol > 0) {
                    Icon(Icons.Filled.Key, contentDescription = "EAPOL captured", tint = Success, modifier = Modifier.size(17.dp))
                    Spacer(Modifier.width(3.dp))
                    Text("×$eapol", style = MaterialTheme.typography.labelSmall, color = Success)
                }
            }
            Text(
                ap.bssid,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MarauderTextDim,
            )
            Spacer(Modifier.size(8.dp))
            RssiBar(ap.rssi)
            Spacer(Modifier.size(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                Meta("CH ${ap.channel}")
                Text("${ap.rssi} dBm", style = MaterialTheme.typography.labelMedium, color = rssiColor(ap.rssi), fontWeight = FontWeight.SemiBold)
                Meta("${ap.stations} client${if (ap.stations == 1) "" else "s"}")
                if (ap.packets > 0) Meta("${ap.packets} pkt")
                Meta(Security.label(ap.sec))
                if (ap.wps) Meta("WPS", Warning)
                if (ap.selected) Meta("selected", MarauderCyan)
            }
        }
    }
}

@Composable
private fun RssiBar(rssi: Int) {
    val fraction = ((rssi + 100).coerceIn(0, 90)) / 90f
    Box(
        Modifier.fillMaxWidth().height(5.dp).clip(RoundedCornerShape(3.dp))
            .background(MaterialTheme.colorScheme.outline),
    ) {
        Box(
            Modifier.fillMaxWidth(fraction).height(5.dp).clip(RoundedCornerShape(3.dp))
                .background(rssiColor(rssi)),
        )
    }
}

@Composable
private fun Meta(text: String, color: Color = MarauderTextDim) {
    Text(text, style = MaterialTheme.typography.labelMedium, color = color)
}

private fun rssiColor(rssi: Int): Color = when {
    rssi >= -60 -> Success
    rssi >= -75 -> Warning
    else -> Danger
}
