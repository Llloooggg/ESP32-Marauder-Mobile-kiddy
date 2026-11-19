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
import androidx.compose.material3.OutlinedButton
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
import com.marauder.mobile.vm.MissionTarget
import com.marauder.mobile.vm.TargetPinState

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
    /** Route through the target lock: the board's selection is pinned to this BSSID
     *  and read back before the command is allowed to run. */
    val pinned: Boolean = false,
    /** Commands addressed by list slot (`foxhunt -w <slot>`): the slot is resolved
     *  from the board's current list at the moment of pressing, never carried over. */
    val slotPrefix: String? = null,
    /** Opens the raw live screen: the firmware streams its own table/telemetry. */
    val liveTitle: String? = null,
    val analyzer: AnalyzerKind? = null,
    /** Needs a known channel: `sniffpmkid -c 0` is not a channel, so the board would be
     *  left on whatever it last used instead of on this network's. */
    val requiresChannel: Boolean = false,
)

/**
 * A single access point as an entity: everything the board knows about it, its
 * clients, and the policy-gated operations that turn it into a captured handshake.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ApDetailScreen(
    apBssid: String,
    vm: MarauderViewModel,
    onBack: () -> Unit,
    onOpenMission: (Long) -> Unit,
    onOpenLive: (title: String, command: String) -> Unit,
    onOpenAnalyzer: (command: String, kind: AnalyzerKind) -> Unit,
) {
    val aps by vm.aps.collectAsState()
    val snapshotGen by vm.snapshotGen.collectAsState()
    val info by vm.info.collectAsState()
    val mission by vm.activeMission.collectAsState()
    val pin by vm.targetPin.collectAsState()

    // Identity is the BSSID, not the board's list slot: the firmware rebuilds that
    // list whenever it scans, so a slot carried across screens can end up naming a
    // different network. The slot is looked up fresh, for this BSSID, every time.
    val ap = aps.firstOrNull { it.bssid.equals(apBssid, ignoreCase = true) }
    val clients = remember(snapshotGen, apBssid) { vm.clientsOf(apBssid) }
    val clientsTrusted = vm.clientsTrusted

    LaunchedEffect(apBssid) {
        // AP list first, clients second: the client rows are attributed to the AP
        // list they were read against, so this order keeps that pairing provable.
        vm.refreshList(ListType.ACCESS_POINTS)
        vm.refreshList(ListType.STATIONS)
    }

    // A pinned action only starts after the board confirms the selection, so follow
    // the mission that appears for this BSSID rather than assume one started.
    var jumpedMission by remember { mutableStateOf(-1L) }
    LaunchedEffect(mission?.id) {
        val m = mission
        if (m != null && !m.done && m.target?.bssid.equals(apBssid, ignoreCase = true) && m.id != jumpedMission) {
            jumpedMission = m.id
            onOpenMission(m.id)
        }
    }

    val actions = remember(apBssid, info, ap) {
        val slot = ap?.bssid?.let { vm.slotOf(it) } ?: -1
        val ch = ap?.channel ?: 0
        listOf(
            TargetAction(
                title = "Capture handshake / PMKID",
                subtitle = "select by name, then sniffpmkid -d -l · only this network selected",
                icon = Icons.Filled.Key,
                tint = MarauderCyan,
                tier = Tier.MODERATE,
                command = "sniffpmkid -d -l",
                pinned = true,
                mission = MissionKind.CAPTURE,
                note = "The app first makes the board select this network alone and reads its list back to " +
                    "prove it; only then does the board transmit deauthentication frames to force a " +
                    "re-authentication and stream the WPA handshake (or a PMKID) into a pcap on this phone. " +
                    "Only do this to networks you own or may test.",
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
                requiresChannel = true,
                note = "No frames are sent. `-c $ch` only sets the channel once — the scan loop hops away 2 s later " +
                    "unless the board's ChanHop setting is off, so the app switches that setting off for this run " +
                    "and puts it back when it ends, and it deselects any network left selected by an earlier " +
                    "targeted run, because the sniffer otherwise drops every other AP's frames.",
            ),
            TargetAction(
                title = "Deauth flood (targeted)",
                subtitle = "select by name, then attack -t deauth -c · DoS only, no pcap",
                icon = Icons.Filled.Bolt,
                tint = CatAttack,
                tier = Tier.MODERATE,
                command = "attack -t deauth -c",
                pinned = true,
                mission = MissionKind.ATTACK,
                note = "This disconnects every client of this network repeatedly. The board attacks whatever is " +
                    "selected, so the app pins the selection to this access point and verifies it first. " +
                    "It does not capture anything. Only run it against your own network.",
            ),
            TargetAction(
                title = "Fox hunt this AP",
                subtitle = "foxhunt -w $slot · signal direction finding",
                icon = Icons.Filled.SettingsInputAntenna,
                tint = CatSniffer,
                tier = Tier.SAFE,
                command = "foxhunt -w $slot",
                slotPrefix = "foxhunt -w",
                requiresCap = "foxhunt",
                liveTitle = "Fox Hunt",
            ),
            TargetAction(
                title = "CSI motion on this AP",
                subtitle = "csimotion start $slot · sense movement",
                icon = Icons.Filled.Sensors,
                tint = CatSniffer,
                tier = Tier.SAFE,
                command = "csimotion start $slot",
                slotPrefix = "csimotion start",
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
                title = { Text(ap?.essid?.ifBlank { "Hidden network" } ?: apBssid) },
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
                    title = "The board no longer lists it",
                    subtitle = "$apBssid is not in the firmware's current scan list, so nothing can be aimed at " +
                        "it — an index would point at whichever network happens to sit there now. Run an AP scan " +
                        "and pick the network again.",
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
            item { PinCard(pin, apBssid) }

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
            if (Security.offersSae(ap.sec)) {
                item {
                    Hint(
                        "This network advertises WPA3-SAE. The firmware flags SAE as soon as that suite appears in " +
                            "the AKM list, which includes WPA2/WPA3 transition mode where a PSK fallback still " +
                            "exists — so the capture attempt is still worth doing. What decides whether the result " +
                            "is crackable is the extractor's per-network verdict in the capture library: an SAE-only " +
                            "network derives its PMK from the dragonfly exchange, and no wordlist can recover that.",
                        Warning,
                    )
                }
            }

            item { SectionLabel("Actions") }
            items(
                actions.filter {
                    (it.requiresCap == null || info?.has(it.requiresCap) == true) &&
                        (!it.requiresChannel || (ap.channel > 0))
                },
            ) { action ->
                ActionCard(
                    action = action,
                    busy = mission?.done == false && mission?.kind == action.mission,
                    onClick = { run(action, ap, vm, onOpenMission, onOpenLive, onOpenAnalyzer) },
                )
            }
            if (ap.channel <= 0) {
                item {
                    Hint(
                        "The board has not recorded a channel for this network, so the channel-pinned listens are " +
                            "hidden: `sniffpmkid -c 0` is not a channel, and the board would sit on whatever " +
                            "channel it last used while pretending to watch this one.",
                        Warning,
                    )
                }
            }

            item {
                SectionLabel(
                    "Clients · ${clients.size}",
                    modifier = Modifier.padding(top = 6.dp),
                )
            }
            if (!clientsTrusted && clients.isNotEmpty()) {
                item {
                    Hint(
                        "The board re-indexed its access-point list after these clients were read, so their " +
                            "network pairing is not provable right now. Re-read the lists before selecting one — " +
                            "a client selected by a stale index belongs to a different network.",
                        Danger,
                    )
                }
                item {
                    OutlinedButton(
                        onClick = {
                            vm.refreshList(ListType.ACCESS_POINTS)
                            vm.refreshList(ListType.STATIONS)
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Re-read AP and client lists") }
                }
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
                items(clients, key = { it.mac }) { sta ->
                    StationRow(sta, onSelect = { vm.selectClient(sta.mac) })
                }
            }
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
    val title = "${ap.essid.ifBlank { ap.bssid }} · ${action.title}"
    when {
        action.analyzer != null -> onOpenAnalyzer(action.command, action.analyzer)

        action.liveTitle != null -> {
            // Slot-addressed commands (`foxhunt -w N`, `csimotion start N`) get the slot
            // this network occupies right now; a null means the board forgot it and has
            // already told the user, so there is nothing to send.
            val command = action.slotPrefix?.let { vm.slotCommand(it, ap.bssid) ?: return } ?: action.command
            onOpenLive(action.liveTitle, command)
        }

        action.pinned && action.mission != null ->
            // The board's selection is pinned to this BSSID and read back first; the
            // mission starts inside that check, and only if the check agrees.
            vm.startPinnedMission(title, action.command, action.mission, ap.bssid)

        action.mission != null ->
            vm.startMission(
                title = title,
                command = action.command,
                kind = action.mission,
                target = MissionTarget(ap.essid, ap.bssid, ap.channel),
            )

        else -> vm.runCommand(action.command)
    }
}

/**
 * What the board has agreed about this target right now. The point of showing it is
 * that a targeted attack is a promise: the app says which BSSID the board confirmed
 * as selected, including when that confirmation covers more than one access point
 * (same SSID) or when it refused and nothing was transmitted.
 */
@Composable
private fun PinCard(pin: TargetPinState, apBssid: String) {
    if (pin.bssidForCard() == null || !pin.bssidForCard()!!.equals(apBssid, ignoreCase = true)) return
    when (pin) {
        TargetPinState.Idle -> Unit
        is TargetPinState.Pinning -> Hint(
            "Asking the board to select ${pin.essid.ifBlank { pin.bssid }} and nothing else, and reading its " +
                "list back — nothing is transmitted until that agrees.",
            MarauderCyan,
        )
        is TargetPinState.Pinned -> Hint(
            buildString {
                append("Board confirms selected: ${pin.selected.joinToString()}")
                if (pin.duplicates.isNotEmpty()) {
                    append(". ${pin.duplicates.size} more BSSID(s) carry this exact SSID and are selected with it: ")
                    append(pin.duplicates.joinToString())
                    append(" — the firmware cannot separate an SSID from its other access points.")
                }
                if (!pin.byEssid) {
                    append(" Addressed by list slot because this SSID cannot be used as a firmware filter.")
                }
            },
            if (pin.duplicates.isEmpty()) Success else Warning,
        )
        is TargetPinState.Refused -> Hint("Refused — ${pin.reason}", Danger)
    }
}

/** The BSSID a pin state is about, or null when it is not tied to one. */
private fun TargetPinState.bssidForCard(): String? = when (this) {
    is TargetPinState.Pinning -> bssid
    is TargetPinState.Pinned -> bssid
    is TargetPinState.Refused -> bssid
    TargetPinState.Idle -> null
}

@Composable
private fun ApHeader(ap: DeviceMessage.Ap) {    Surface(
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
                StatChip("SEC", Security.label(ap.sec), if (ap.sec == 0) Danger else if (Security.offersSae(ap.sec)) Warning else Success)
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
                // What the command really does stays on the card instead of hiding behind
                // a confirm button: the tap is the consent (given once at first launch), but
                // an icon and a label must never make a transmitter look harmless.
                action.note?.let {
                    Spacer(Modifier.size(4.dp))
                    Text(it, style = MaterialTheme.typography.labelSmall, color = MarauderTextDim)
                }
            }
            when (action.tier) {
                Tier.SAFE -> Unit
                Tier.MODERATE -> Icon(Icons.Filled.LockOpen, contentDescription = "Transmits frames", tint = Warning, modifier = Modifier.size(18.dp))
                Tier.HIGH -> Icon(Icons.Filled.Bolt, contentDescription = "Active interference", tint = Danger, modifier = Modifier.size(18.dp))
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
