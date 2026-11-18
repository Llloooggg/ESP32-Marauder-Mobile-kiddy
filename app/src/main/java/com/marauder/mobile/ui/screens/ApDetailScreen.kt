package com.marauder.mobile.ui.screens

import androidx.compose.foundation.BorderStroke
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
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Insights
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Sensors
import androidx.compose.material.icons.filled.SettingsInputAntenna
import androidx.compose.material.icons.filled.WifiTethering
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.marauder.mobile.data.AnalyzerKind
import com.marauder.mobile.data.ListType
import com.marauder.mobile.data.Security
import com.marauder.mobile.data.Tier
import com.marauder.mobile.protocol.DeviceMessage
import com.marauder.mobile.ui.components.EmptyState
import com.marauder.mobile.ui.components.PolicyDialog
import com.marauder.mobile.ui.components.SectionLabel
import com.marauder.mobile.ui.components.StatChip
import com.marauder.mobile.ui.theme.CatAttack
import com.marauder.mobile.ui.theme.CatSniffer
import com.marauder.mobile.ui.theme.CatWifi
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.MarauderCyan
import com.marauder.mobile.ui.theme.MarauderTextDim
import com.marauder.mobile.ui.theme.Success
import com.marauder.mobile.ui.theme.Warning
import com.marauder.mobile.vm.MarauderViewModel
import com.marauder.mobile.vm.MissionKind

/** One gated action the target screen can start against the selected AP. */
private data class TargetAction(
    val title: String,
    val subtitle: String,
    val icon: ImageVector,
    val tint: Color,
    val tier: Tier,
    val command: String,
    val note: String? = null,
    val requiresCap: String? = null,
    /** Mission to start (null = open a live/analyzer screen instead). */
    val mission: MissionKind? = null,
    /** Commands run before the main one (e.g. `select -a 3`). */
    val preCommands: List<String> = emptyList(),
    /** Opens the raw live screen: the firmware streams its own table/telemetry. */
    val liveTitle: String? = null,
    val analyzer: AnalyzerKind? = null,
)

/**
 * A single access point as an entity: everything the board knows about it, its
 * clients, and the policy-gated operations that turn it into a captured handshake.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ApDetailScreen(
    apIndex: Int,
    vm: MarauderViewModel,
    onBack: () -> Unit,
    onOpenMission: (Long) -> Unit,
    onOpenLive: (title: String, command: String) -> Unit,
    onOpenAnalyzer: (command: String, kind: AnalyzerKind) -> Unit,
) {
    val aps by vm.aps.collectAsState()
    val stations by vm.stations.collectAsState()
    val info by vm.info.collectAsState()
    val mission by vm.activeMission.collectAsState()

    val ap = aps.firstOrNull { it.index == apIndex }
    val clients = remember(stations, apIndex) { stations.filter { it.ap == apIndex } }

    LaunchedEffect(apIndex) {
        vm.refreshList(ListType.STATIONS)
        vm.refreshList(ListType.ACCESS_POINTS)
    }

    var pending by remember { mutableStateOf<TargetAction?>(null) }

    val actions = remember(apIndex, info, ap) {
        val select = "select -a $apIndex"
        val ch = ap?.channel ?: 0
        listOf(
            TargetAction(
                title = "Capture handshake / PMKID",
                subtitle = "sniffpmkid -d -l · sends deauth around this AP",
                icon = Icons.Filled.Key,
                tint = MarauderCyan,
                tier = Tier.MODERATE,
                command = "sniffpmkid -d -l",
                preCommands = listOf(select),
                mission = MissionKind.CAPTURE,
                note = "The board transmits deauthentication frames to force a re-authentication, then streams the WPA handshake (or a PMKID) into a pcap on this phone. Only do this to networks you own or may test.",
            ),
            TargetAction(
                title = "Listen for handshake (passive)",
                subtitle = "sniffpmkid -c $ch · no frames sent",
                icon = Icons.Filled.WifiTethering,
                tint = CatSniffer,
                tier = Tier.SAFE,
                // The firmware's passive PMKID sniff runs on one channel, so pin it to
                // this network's channel instead of hopping (-l would need a selection).
                command = "sniffpmkid -c $ch",
                mission = MissionKind.SNIFF,
            ),
            TargetAction(
                title = "Deauth flood (targeted)",
                subtitle = "attack -t deauth -c · DoS only, no pcap",
                icon = Icons.Filled.Bolt,
                tint = CatAttack,
                tier = Tier.MODERATE,
                command = "attack -t deauth -c",
                preCommands = listOf(select),
                mission = MissionKind.ATTACK,
                note = "This disconnects every client of this network repeatedly. It does not capture anything. Only run it against your own network.",
            ),
            TargetAction(
                title = "Fox hunt this AP",
                subtitle = "foxhunt -w $apIndex · signal direction finding",
                icon = Icons.Filled.SettingsInputAntenna,
                tint = CatSniffer,
                tier = Tier.SAFE,
                command = "foxhunt -w $apIndex",
                requiresCap = "foxhunt",
                liveTitle = "Fox Hunt",
            ),
            TargetAction(
                title = "CSI motion on this AP",
                subtitle = "csimotion start $apIndex · sense movement",
                icon = Icons.Filled.Sensors,
                tint = CatSniffer,
                tier = Tier.SAFE,
                command = "csimotion start $apIndex",
                requiresCap = "csi",
                liveTitle = "CSI Motion",
            ),
            TargetAction(
                title = "Channel occupancy",
                subtitle = "analyzer -t chan · see how busy this channel is",
                icon = Icons.Filled.Insights,
                tint = CatSniffer,
                tier = Tier.SAFE,
                command = "analyzer -t chan",
                analyzer = AnalyzerKind.CHANNEL,
            ),
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(ap?.essid?.ifBlank { "Hidden network" } ?: "Access point #$apIndex") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
            )
        },
    ) { inner ->
        if (ap == null) {
            Box(Modifier.fillMaxSize().padding(inner), contentAlignment = Alignment.Center) {
                EmptyState(
                    icon = Icons.Filled.Key,
                    title = "Not in the list anymore",
                    subtitle = "The firmware cleared or re-indexed its AP list. Scan again and pick the network.",
                )
            }
            return@Scaffold
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(inner),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item { ApHeader(ap) }

            if (Security.handshakable(ap.sec) && clients.isEmpty()) {
                item {
                    Hint(
                        "No clients associated yet. A handshake needs a client to re-authenticate; PMKID capture may still work if the AP hands out PMKIDs.",
                        Warning,
                    )
                }
            }
            if (Security.enterprise(ap.sec)) {
                item { Hint("Enterprise network: there is no PSK to crack. Evil Portal / karma are the credential-side tools.", Warning) }
            }
            if (ap.sec == 0) {
                item { Hint("Open network — no handshake or PMKID exists.", MarauderTextDim) }
            }

            item { SectionLabel("Actions") }
            items(actions.filter { it.requiresCap == null || info?.has(it.requiresCap) == true }) { action ->
                ActionCard(
                    action = action,
                    busy = mission?.done == false && mission?.kind == action.mission,
                    onClick = {
                        when {
                            action.tier == Tier.SAFE -> run(action, ap, vm, onOpenMission, onOpenLive, onOpenAnalyzer)
                            else -> pending = action
                        }
                    },
                )
            }

            item {
                SectionLabel(
                    "Clients · ${clients.size}",
                    modifier = Modifier.padding(top = 6.dp),
                )
            }
            if (clients.isEmpty()) {
                item {
                    Text(
                        "The board has not seen a station on this network. Run a scan (Scan AP/STA) while a device is connected to it.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MarauderTextDim,
                    )
                }
            } else {
                items(clients, key = { "${it.ap}-${it.index}" }) { sta ->
                    StationRow(sta, onSelect = { vm.runCommand("select -c ${sta.index}"); vm.refreshList(ListType.STATIONS) })
                }
            }
        }

        pending?.let { action ->
            PolicyDialog(
                title = action.title,
                command = action.command,
                tier = action.tier,
                note = action.note,
                onDismiss = { pending = null },
                onConfirm = {
                    pending = null
                    run(action, ap, vm, onOpenMission, onOpenLive, onOpenAnalyzer)
                },
            )
        }
    }
}

/** Fire an action: mission-backed commands go through the mission engine. */
private fun run(
    action: TargetAction,
    ap: DeviceMessage.Ap,
    vm: MarauderViewModel,
    onOpenMission: (Long) -> Unit,
    onOpenLive: (title: String, command: String) -> Unit,
    onOpenAnalyzer: (command: String, kind: AnalyzerKind) -> Unit,
) {
    when {
        action.analyzer != null -> onOpenAnalyzer(action.command, action.analyzer)
        action.liveTitle != null -> onOpenLive(action.liveTitle, action.command)
        action.mission != null -> {
            val title = "${ap.essid.ifBlank { ap.bssid }} · ${action.title}"
            if (vm.startMission(title, action.command, action.mission, action.preCommands)) {
                vm.activeMission.value?.let { onOpenMission(it.id) }
            }
        }
        else -> {
            action.preCommands.forEach { vm.runCommand(it) }
            vm.runCommand(action.command)
        }
    }
}

@Composable
private fun ApHeader(ap: DeviceMessage.Ap) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(
                ap.essid.ifBlank { "(hidden network)" },
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
                fontWeight = FontWeight.Bold,
            )
            Text(
                ap.bssid,
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
                color = MarauderTextDim,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatChip("CH", ap.channel.toString(), CatWifi)
                StatChip("RSSI", "${ap.rssi} dBm", if (ap.rssi >= -65) Success else if (ap.rssi >= -80) Warning else Danger)
                StatChip("SEC", Security.label(ap.sec), if (ap.sec == 0) Danger else Success)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatChip("CLIENTS", ap.stations.toString(), MarauderCyan)
                StatChip("PACKETS", ap.packets.toString(), MaterialTheme.colorScheme.onSurfaceVariant)
                if (ap.wps) StatChip("WPS", "on", Warning)
                if (ap.selected) StatChip("FIRMWARE", "selected", MarauderCyan)
            }
        }
    }
}

@Composable
private fun ActionCard(action: TargetAction, busy: Boolean, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(13.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(
            1.dp,
            when (action.tier) {
                Tier.SAFE -> MaterialTheme.colorScheme.outline
                Tier.MODERATE -> Warning.copy(alpha = 0.5f)
                Tier.HIGH -> Danger.copy(alpha = 0.5f)
            },
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(40.dp).padding(end = 0.dp),
                contentAlignment = Alignment.Center,
            ) {
                Icon(action.icon, contentDescription = null, tint = action.tint, modifier = Modifier.size(21.dp))
            }
            Column(Modifier.weight(1f).padding(start = 10.dp, end = 8.dp)) {
                Text(action.title, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
                Text(action.subtitle, style = MaterialTheme.typography.bodySmall, color = MarauderTextDim)
                Spacer(Modifier.size(4.dp))
                Text(
                    "$ ${action.command}",
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = if (busy) MarauderCyan else MarauderTextDim,
                )
            }
            when (action.tier) {
                Tier.SAFE -> Unit
                Tier.MODERATE -> Icon(Icons.Filled.LockOpen, contentDescription = "Requires confirmation", tint = Warning, modifier = Modifier.size(18.dp))
                Tier.HIGH -> Icon(Icons.Filled.Bolt, contentDescription = "High impact", tint = Danger, modifier = Modifier.size(18.dp))
            }
            if (busy) {
                Spacer(Modifier.width(6.dp))
                Icon(Icons.Filled.Check, contentDescription = "Running", tint = MarauderCyan, modifier = Modifier.size(18.dp))
            }
        }
    }
}

@Composable
private fun StationRow(sta: DeviceMessage.Sta, onSelect: () -> Unit) {
    Surface(
        onClick = onSelect,
        shape = RoundedCornerShape(11.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, if (sta.selected) MarauderCyan else MaterialTheme.colorScheme.outline),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(11.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(sta.mac, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurface)
                if (sta.packets > 0) Text("${sta.packets} packets", style = MaterialTheme.typography.labelSmall, color = MarauderTextDim)
            }
            Text(
                if (sta.selected) "SELECTED" else "SELECT",
                style = MaterialTheme.typography.labelSmall,
                color = if (sta.selected) MarauderCyan else MarauderTextDim,
                fontWeight = FontWeight.Bold,
            )
        }
    }
}

@Composable
private fun Hint(text: String, color: Color) {
    Surface(
        shape = RoundedCornerShape(11.dp),
        color = color.copy(alpha = 0.10f),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            text,
            style = MaterialTheme.typography.bodySmall,
            color = color,
            modifier = Modifier.padding(11.dp),
        )
    }
}
