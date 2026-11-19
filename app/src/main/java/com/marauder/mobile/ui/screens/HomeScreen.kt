package com.marauder.mobile.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.DeveloperBoard
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.filled.LinkOff
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.PermScanWifi
import androidx.compose.material.icons.filled.RestartAlt
import androidx.compose.material.icons.filled.Sensors
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.marauder.mobile.data.Catalog
import com.marauder.mobile.data.MenuAction
import com.marauder.mobile.data.MenuItem
import com.marauder.mobile.protocol.DeviceMessage
import com.marauder.mobile.ui.components.ConnectionDot
import com.marauder.mobile.ui.components.MenuCard
import com.marauder.mobile.ui.components.SectionLabel
import com.marauder.mobile.ui.components.StatChip
import com.marauder.mobile.ui.components.StatusPanel
import com.marauder.mobile.ui.theme.CatAttack
import com.marauder.mobile.ui.theme.CatDevice
import com.marauder.mobile.ui.theme.CatGps
import com.marauder.mobile.ui.theme.CatScanner
import com.marauder.mobile.ui.theme.CatSniffer
import com.marauder.mobile.ui.theme.CatWifi
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.MarauderCyan
import com.marauder.mobile.ui.theme.MarauderTextDim
import com.marauder.mobile.ui.theme.Success
import com.marauder.mobile.ui.theme.Warning
import com.marauder.mobile.usb.UsbSerialManager
import com.marauder.mobile.vm.MarauderViewModel
import com.marauder.mobile.vm.Mission
import com.marauder.mobile.vm.MissionKind
import kotlinx.coroutines.delay

/**
 * The product root once a board is attached: live board state, the mission the app
 * is supervising (if any), the primary flow entry points (Scan → capture) and the
 * firmware category grid that keeps every command reachable.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    vm: MarauderViewModel,
    onOpenScan: () -> Unit,
    onOpenArtifacts: () -> Unit,
    onOpenWordlists: () -> Unit,
    onOpenMission: (Long) -> Unit,
    onOpenMenu: (String) -> Unit,
    onOpenConsole: () -> Unit,
    onOpenFlash: () -> Unit,
    onOpenAbout: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenPosture: () -> Unit,
    onOpenCatalogItem: (MenuItem) -> Unit,
    onDisconnect: () -> Unit,
) {
    val connStatus by vm.status.collectAsState()
    val name by vm.connectedName.collectAsState()
    val devStatus by vm.deviceStatus.collectAsState()
    val info by vm.info.collectAsState()
    val mission by vm.activeMission.collectAsState()
    val darkTheme by vm.darkTheme.collectAsState()
    val labMode by vm.labMode.collectAsState()
    val connected = connStatus == UsbSerialManager.Status.CONNECTED

    // The Lab section is collapsed by default even when enabled: its entries transmit
    // on purpose, so reaching them is a deliberate extra step, not the default view.
    var labOpen by remember { mutableStateOf(false) }
    var pendingLab by remember { mutableStateOf<MenuItem?>(null) }
    val labItems = remember(info) { Catalog.highImpactItems(info?.caps) }

    // Category cards come from the same catalog the Advanced tree renders, so command
    // wiring, capability gating and tiers keep a single source of truth.
    val categories = remember(info) {
        Catalog.screens.getValue(Catalog.ROOT).itemsFor(info?.caps)
            .filter { it.action is MenuAction.Submenu }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Marauder Mobile Kiddy") },
                actions = {
                    IconButton(onClick = { vm.toggleTheme() }) {
                        Icon(
                            if (darkTheme) Icons.Filled.LightMode else Icons.Filled.DarkMode,
                            contentDescription = "Theme",
                            tint = MarauderCyan,
                        )
                    }
                    IconButton(onClick = onOpenSettings) {
                        Icon(
                            Icons.Filled.Settings,
                            contentDescription = "Settings",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    IconButton(onClick = onOpenAbout) {
                        Icon(Icons.Filled.Info, contentDescription = "About", tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    if (connected) {
                        IconButton(onClick = onDisconnect) {
                            Icon(Icons.Filled.LinkOff, contentDescription = "Disconnect", tint = Danger)
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
        LazyColumn(
            modifier = Modifier.fillMaxWidth().padding(inner),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item {
                StatusPanel(
                    connected = connected,
                    name = name,
                    status = devStatus,
                    onStop = { if (mission?.done == false) vm.stopMission() else vm.stopScan() },
                )
            }

            mission?.let { m ->
                item {
                    MissionCard(
                        mission = m,
                        onOpen = { onOpenMission(m.id) },
                        onStop = { vm.stopMission() },
                    )
                }
            }

            item { SectionLabel("Get things done", modifier = Modifier.padding(top = 6.dp)) }
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    BigAction(
                        label = "Scan networks",
                        hint = "scanall · list every access point, then pick a target",
                        icon = Icons.Filled.PermScanWifi,
                        tint = CatWifi,
                        onClick = onOpenScan,
                    )
                    BigAction(
                        label = "Capture handshake / PMKID",
                        hint = "sniffpmkid · open Scan to choose the network",
                        icon = Icons.Filled.Key,
                        tint = MarauderCyan,
                        onClick = onOpenScan,
                    )
                    BigAction(
                        label = "Capture library",
                        hint = "pcap · GPX · logs the app has already saved on this phone",
                        icon = Icons.Filled.Folder,
                        tint = CatSniffer,
                        onClick = onOpenArtifacts,
                    )
                    BigAction(
                        label = "Network posture",
                        hint = "join a network with the board · find its hosts · check open ports",
                        icon = Icons.Filled.Language,
                        tint = CatScanner,
                        onClick = onOpenPosture,
                    )
                }
            }

            item { SectionLabel("Board", modifier = Modifier.padding(top = 6.dp)) }
            item {
                BoardCard(
                    info = info,
                    onOpenFlash = onOpenFlash,
                    onReboot = { vm.runCommand("reboot") },
                )
            }

            item { SectionLabel("Toolbox", modifier = Modifier.padding(top = 6.dp)) }
            item {
                LazyVerticalGrid(
                    columns = GridCells.Fixed(2),
                    modifier = Modifier.fillMaxWidth().height(84.dp * ((categories.size + 1) / 2)),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    userScrollEnabled = false,
                ) {
                    items(categories, key = { it.title }) { item ->
                        MenuCard(
                            item = item,
                            onClick = {
                                val action = item.action
                                if (action is MenuAction.Submenu) onOpenMenu(action.id)
                            },
                        )
                    }
                }
            }

            if (labMode && labItems.isNotEmpty()) {
                    item {
                        Surface(
                            onClick = { labOpen = !labOpen },
                            shape = RoundedCornerShape(13.dp),
                            color = MaterialTheme.colorScheme.surface,
                            border = BorderStroke(1.dp, Danger.copy(alpha = 0.5f)),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Filled.Bolt, contentDescription = null, tint = Danger, modifier = Modifier.size(20.dp))
                                Column(Modifier.weight(1f).padding(start = 10.dp)) {
                                    Text(
                                        "Lab · active interference",
                                        style = MaterialTheme.typography.titleMedium,
                                        color = MaterialTheme.colorScheme.onSurface,
                                    )
                                    Text(
                                        "${labItems.size} command(s) that transmit on purpose · ${if (labOpen) "tap to collapse" else "tap to open"}",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MarauderTextDim,
                                    )
                                }
                                Icon(
                                    if (labOpen) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                                    contentDescription = if (labOpen) "Collapse" else "Expand",
                                    tint = MarauderTextDim,
                                )
                            }
                        }
                    }
                    if (labOpen) {
                        item {
                            Text(
                                "Everything here is in the firmware's own menu tree and is listed here because it " +
                                    "interferes with devices near you by design. Each entry still asks you to confirm, " +
                                    "and the command it runs is shown — nothing is sent silently, and nothing is " +
                                    "hidden behind a nicer name.",
                                style = MaterialTheme.typography.bodySmall,
                                color = Warning,
                            )
                        }
                        items(labItems, key = { it.title }) { item ->
                            MenuCard(
                                item = item,
                                onClick = {
                                    if (item.dangerous && item.action is MenuAction.Send) {
                                        pendingLab = item
                                    } else {
                                        onOpenCatalogItem(item)
                                    }
                                },
                            )
                        }
                    }
            }

            item {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    QuickTile("Console", Icons.Filled.Terminal, MarauderCyan, Modifier.weight(1f), onClick = onOpenConsole)
                    QuickTile("Flash firmware", Icons.Filled.SystemUpdate, CatDevice, Modifier.weight(1f), onClick = onOpenFlash)
                    QuickTile("Wordlists", Icons.Filled.Storage, CatSniffer, Modifier.weight(1f), onClick = onOpenWordlists)
                }
            }
        }
    }

    pendingLab?.let { item ->
        AlertDialog(
            onDismissRequest = { pendingLab = null },
            icon = { Icon(Icons.Filled.Bolt, contentDescription = null, tint = Danger) },
            title = { Text(item.title) },
            text = {
                Text(
                    buildString {
                        append(
                            "This transmits on purpose and affects devices near you. The app will not send it " +
                                "unless you confirm, and only against networks you are authorised to test.\n\n",
                        )
                        (item.action as? MenuAction.Send)?.let { append("$ ") }
                        (item.action as? MenuAction.Send)?.let { append(it.command) }
                    },
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    pendingLab = null
                    onOpenCatalogItem(item)
                }) { Text("Run it", color = Danger) }
            },
            dismissButton = { TextButton(onClick = { pendingLab = null }) { Text("Cancel") } },
        )
    }
}

// --- Active mission ----------------------------------------------------------

/** Card for the mission the app is currently supervising. */
@Composable
private fun MissionCard(mission: Mission, onOpen: () -> Unit, onStop: () -> Unit) {
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(mission.id) {
        while (true) {
            delay(1000)
            now = System.currentTimeMillis()
        }
    }
    val accent = missionColor(mission.kind)
    val elapsed = ((mission.endedAt ?: now) - mission.startedAt) / 1000

    Surface(
        onClick = onOpen,
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
        border = BorderStroke(1.dp, accent.copy(alpha = 0.5f)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier.size(38.dp).clip(RoundedCornerShape(10.dp))
                        .background(accent.copy(alpha = 0.14f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(missionIcon(mission.kind), contentDescription = null, tint = accent, modifier = Modifier.size(20.dp))
                }
                Column(Modifier.weight(1f).padding(start = 10.dp)) {
                    Text(mission.title, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
                    Text(
                        "$elapsed s · \$ ${mission.command}",
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = MarauderTextDim,
                    )
                }
                if (mission.done) {
                    StatChip("STATE", "finished", MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    ConnectionDot(color = accent, pulsing = true)
                }
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatChip(
                    "EAPOL",
                    mission.eapolTotal.toString(),
                    if (mission.eapolTotal > 0) Success else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (mission.kind == MissionKind.CAPTURE || mission.bytes > 0) {
                    StatChip("SAVED", "%.0f KB".format(mission.bytes / 1024.0), MarauderCyan)
                }
                if (mission.missedFrames > 0) StatChip("GAPS", mission.missedFrames.toString(), Warning)
                if (mission.ringDrops > 0) StatChip("DROPS", mission.ringDrops.toString(), Warning)
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ActionTile("Open", Icons.Filled.OpenInNew, MarauderCyan, onClick = onOpen)
                if (!mission.done) {
                    ActionTile("Stop", Icons.Filled.Stop, Danger, onClick = onStop)
                } else if (mission.artifactName != null) {
                    ActionTile("Saved capture", Icons.Filled.Folder, Success, onClick = onOpen)
                }
            }
        }
    }
}

// --- Board -------------------------------------------------------------------

/** Firmware identity + capability report, plus the two board-level actions. */
@Composable
private fun BoardCard(info: DeviceMessage.Info?, onOpenFlash: () -> Unit, onReboot: () -> Unit) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.DeveloperBoard, contentDescription = null, tint = CatDevice, modifier = Modifier.size(20.dp))
                Spacer(Modifier.size(8.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        info?.board?.ifBlank { "Unknown board" } ?: "Reading board…",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        info?.let { "firmware ${it.fw} · proto ${it.proto}" } ?: "waiting for jsoninfo",
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = MarauderTextDim,
                    )
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                when {
                    info == null -> Dim("—")
                    info.caps.isEmpty() -> Dim("no capabilities reported")
                    else -> info.caps.sorted().forEach { cap ->
                        Box(
                            Modifier.clip(RoundedCornerShape(6.dp))
                                .background(CatDevice.copy(alpha = 0.12f))
                                .padding(horizontal = 7.dp, vertical = 3.dp),
                        ) {
                            Text(cap, style = MaterialTheme.typography.labelSmall, color = CatDevice)
                        }
                    }
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ActionTile("Flash firmware", Icons.Filled.SystemUpdate, CatDevice, onClick = onOpenFlash)
                ActionTile("Reboot", Icons.Filled.RestartAlt, CatDevice, onClick = onReboot)
            }
        }
    }
}

// --- Small building blocks ---------------------------------------------------

@Composable
private fun BigAction(label: String, hint: String, icon: ImageVector, tint: Color, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(14.dp),
        color = tint.copy(alpha = 0.13f),
        border = BorderStroke(1.dp, tint.copy(alpha = 0.45f)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(42.dp).clip(RoundedCornerShape(11.dp)).background(tint.copy(alpha = 0.18f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(22.dp))
            }
            Column(Modifier.weight(1f).padding(start = 12.dp)) {
                Text(label, style = MaterialTheme.typography.titleMedium, color = tint, fontWeight = FontWeight.Bold)
                Text(hint, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun QuickTile(
    label: String,
    icon: ImageVector,
    tint: Color,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(12.dp),
        color = tint.copy(alpha = 0.12f),
        modifier = modifier,
    ) {
        Column(Modifier.padding(vertical = 12.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(20.dp))
            Spacer(Modifier.height(6.dp))
            Text(label, style = MaterialTheme.typography.labelMedium, color = tint, fontWeight = FontWeight.SemiBold)
        }
    }
}

@Composable
private fun ActionTile(label: String, icon: ImageVector, tint: Color, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(10.dp),
        color = tint.copy(alpha = 0.14f),
    ) {
        Row(Modifier.padding(horizontal = 12.dp, vertical = 7.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(15.dp))
            Spacer(Modifier.size(6.dp))
            Text(label, style = MaterialTheme.typography.labelLarge, color = tint, fontWeight = FontWeight.SemiBold)
        }
    }
}

@Composable
private fun Dim(text: String) {
    Text(text, style = MaterialTheme.typography.labelSmall, color = MarauderTextDim)
}

private fun missionIcon(kind: MissionKind): ImageVector = when (kind) {
    MissionKind.SCAN -> Icons.Filled.PermScanWifi
    MissionKind.SNIFF -> Icons.Filled.Sensors
    MissionKind.CAPTURE -> Icons.Filled.Key
    MissionKind.ATTACK -> Icons.Filled.Bolt
    MissionKind.WARDRIVE -> Icons.Filled.DeveloperBoard
    MissionKind.HUNT -> Icons.Filled.PermScanWifi
    MissionKind.PORTAL -> Icons.Filled.Bolt
    MissionKind.OTHER -> Icons.Filled.Terminal
}

private fun missionColor(kind: MissionKind): Color = when (kind) {
    MissionKind.CAPTURE -> MarauderCyan
    MissionKind.ATTACK, MissionKind.PORTAL -> CatAttack
    MissionKind.WARDRIVE -> CatGps
    MissionKind.SCAN, MissionKind.SNIFF, MissionKind.HUNT -> CatSniffer
    MissionKind.OTHER -> MarauderCyan
}
