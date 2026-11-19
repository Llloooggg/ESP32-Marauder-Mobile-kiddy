package com.marauder.mobile.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
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
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.marauder.mobile.data.FirmwareCommands
import com.marauder.mobile.data.ListType
import com.marauder.mobile.data.MenuAction
import com.marauder.mobile.data.Scenario
import com.marauder.mobile.data.ScenarioRun
import com.marauder.mobile.data.Scenarios
import com.marauder.mobile.protocol.DeviceMessage
import com.marauder.mobile.ui.components.SectionLabel
import com.marauder.mobile.ui.components.accentColor
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.MarauderCyan
import com.marauder.mobile.ui.theme.MarauderTextDim
import com.marauder.mobile.ui.theme.Success
import com.marauder.mobile.ui.theme.Warning
import com.marauder.mobile.usb.UsbSerialManager
import com.marauder.mobile.vm.MarauderViewModel

/**
 * The guided playbooks: whole jobs ("get the handshake and crack it") written out step by
 * step, each step next to the firmware command that performs it.
 *
 * Nothing here is a black box. A playbook shows its steps and the firmware line behind each
 * one before it runs, says what it produces afterwards, and when it addresses a single
 * network that network has to be picked from the board's current list — its slot and channel
 * are then read from that live list at the moment Run is pressed, never from an earlier scan.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScenariosScreen(
    vm: MarauderViewModel,
    onBack: () -> Unit,
    onNavigate: (MenuAction) -> Unit,
    onStarted: () -> Unit,
) {
    val info by vm.info.collectAsState()
    val aps by vm.aps.collectAsState()
    val link by vm.status.collectAsState()
    val connected = link == UsbSerialManager.Status.CONNECTED

    val visible = remember(info) { Scenarios.forCaps(info?.caps) }

    // The network a playbook should run against, per playbook, chosen from the live list.
    var picked by remember { mutableStateOf<Map<String, String>>(emptyMap()) }
    var picking by remember { mutableStateOf<Scenario?>(null) }
    var expanded by remember { mutableStateOf<Set<String>>(emptySet()) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Playbooks") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MarauderCyan,
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
                Text(
                    "Each playbook is a job, not a button: it shows the steps, the firmware " +
                        "command behind every step, and what you get at the end. A playbook that " +
                        "addresses one network takes that network's slot and channel from the " +
                        "board's current scan list when you press Run.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MarauderTextDim,
                )
            }

            if (visible.isEmpty()) {
                item {
                    Text(
                        "No playbook is available yet — connect a board and they appear.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MarauderTextDim,
                    )
                }
            }

            items(visible, key = { it.id }) { scenario ->
                val bssid = picked[scenario.id]
                ScenarioCard(
                    scenario = scenario,
                    connected = connected,
                    picked = bssid?.let { b -> aps.firstOrNull { it.bssid == b } },
                    open = scenario.id in expanded,
                    onToggleOpen = {
                        expanded = if (scenario.id in expanded) expanded - scenario.id else expanded + scenario.id
                    },
                    onPick = { picking = scenario },
                    onRun = {
                        if (scenario.run == ScenarioRun.NAVIGATE) {
                            scenario.navigate?.let(onNavigate)
                        } else if (vm.runScenario(scenario, bssid)) {
                            onStarted()
                        }
                    },
                )
            }

            item {
                SectionLabel("Every firmware verb, by hand")
                Text(
                    "The playbooks are shortcuts, not a wall. The menus under Home expose every " +
                        "command this firmware answers, including the ones that need an index from " +
                        "the board's own lists (`list -b`, the probe list, the IP list), and the " +
                        "console lets you send any of them yourself.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MarauderTextDim,
                )
                Spacer(Modifier.height(8.dp))
            }
        }
    }

    picking?.let { scenario ->
        ApPickerDialog(
            scenario = scenario,
            aps = aps,
            onDismiss = { picking = null },
            onPick = { ap ->
                picked = picked + (scenario.id to ap.bssid)
                picking = null
            },
            onRefresh = { vm.refreshList(ListType.ACCESS_POINTS) },
        )
    }
}

@Composable
private fun ScenarioCard(
    scenario: Scenario,
    connected: Boolean,
    picked: DeviceMessage.Ap?,
    open: Boolean,
    onToggleOpen: () -> Unit,
    onPick: () -> Unit,
    onRun: () -> Unit,
) {
    val accent = accentColor(scenario.accent)
    val needsTarget = Scenarios.needsTarget(scenario)
    val runnable = connected && (!needsTarget || picked != null)

    Surface(
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, accent.copy(alpha = 0.45f)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(scenario.icon, contentDescription = null, tint = accent, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(10.dp))
                Text(
                    scenario.title,
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f),
                )
                if (scenario.dangerous) {
                    Icon(Icons.Filled.Warning, contentDescription = "Transmits", tint = Danger, modifier = Modifier.size(16.dp))
                }
            }
            Spacer(Modifier.height(6.dp))
            Text(scenario.goal, style = MaterialTheme.typography.bodySmall, color = MarauderTextDim)

            if (needsTarget) {
                Spacer(Modifier.height(10.dp))
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    onClick = onPick,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(
                                if (picked == null) "No network picked" else picked.essid.ifBlank { picked.bssid },
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                picked?.let {
                                    // The live row, so what is shown is this scan's slot and channel.
                                    "slot ${it.index} · ch ${it.channel} · ${it.rssi} dBm · ${it.bssid}"
                                } ?: "pick it from the board's current scan list",
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = MarauderTextDim,
                            )
                        }
                        Text("Pick", color = MarauderCyan, style = MaterialTheme.typography.labelLarge)
                    }
                }
            }

            Spacer(Modifier.height(8.dp))
            TextButton(onClick = onToggleOpen) {
                Text(if (open) "Hide the steps" else "Show the ${scenario.steps.size} steps")
                Icon(
                    if (open) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                    contentDescription = null,
                )
            }
            if (open) {
                scenario.steps.forEachIndexed { i, step ->
                    Row(Modifier.padding(vertical = 3.dp)) {
                        Text(
                            "${i + 1}.",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = accent,
                        )
                        Spacer(Modifier.width(8.dp))
                        Column {
                            Text(step.label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface)
                            step.command?.let { cmd ->
                                Text(
                                    cmd.filledWith(scenario, picked),
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MarauderTextDim,
                                )
                            }
                        }
                    }
                }
                Spacer(Modifier.height(6.dp))
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = Success.copy(alpha = 0.10f),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(Modifier.padding(10.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.Check, contentDescription = null, tint = Success, modifier = Modifier.size(14.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("What you get", style = MaterialTheme.typography.labelLarge, color = Success)
                        }
                        Spacer(Modifier.height(4.dp))
                        Text(scenario.outcome, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface)
                    }
                }
            }

            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                val label = when (scenario.run) {
                    ScenarioRun.NAVIGATE -> "Open"
                    ScenarioRun.PINNED_MISSION -> "Run on the picked network"
                    ScenarioRun.MISSION -> "Run"
                }
                Button(
                    onClick = onRun,
                    enabled = runnable,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (scenario.dangerous) Danger else accent,
                        contentColor = Color.White,
                    ),
                ) { Text(label) }
                when {
                    !connected -> Text("connect a board", style = MaterialTheme.typography.bodySmall, color = Warning)
                    needsTarget && picked == null -> Text("pick a network", style = MaterialTheme.typography.bodySmall, color = Warning)
                    scenario.run == ScenarioRun.PINNED_MISSION -> Text(
                        "pinned by BSSID, selection read back first",
                        style = MaterialTheme.typography.bodySmall,
                        color = MarauderTextDim,
                    )
                }
            }
        }
    }
}

/**
 * A step's command with the picked network's live slot and channel filled in, so the line the
 * app would send is the line the user reads. Unresolved placeholders stay as placeholders:
 * blanking them out would hide the reason the app refuses to send the command.
 */
private fun String.filledWith(scenario: Scenario, picked: DeviceMessage.Ap?): String {
    if (Scenarios.placeholders(this).isEmpty()) return this
    val filled = Scenarios.instantiate(this, slot = picked?.index, channel = picked?.channel ?: 0)
    return if (Scenarios.placeholders(filled).isEmpty()) filled else this
}

@Composable
private fun ApPickerDialog(
    scenario: Scenario,
    aps: List<DeviceMessage.Ap>,
    onDismiss: () -> Unit,
    onPick: (DeviceMessage.Ap) -> Unit,
    onRefresh: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Pick the network for \"${scenario.title}\"") },
        text = {
            Column {
                Text(
                    "The slot and channel come from the board's current list, so the command runs " +
                        "against the network that is really in front of the radio right now.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MarauderTextDim,
                )
                Spacer(Modifier.height(8.dp))
                if (aps.isEmpty()) {
                    Text(
                        "The board's list is empty. Run `${FirmwareCommands.SCAN_ALL}` first, then reopen this picker.",
                        style = MaterialTheme.typography.bodySmall,
                        color = Warning,
                    )
                } else {
                    TextButton(onClick = onRefresh) {
                        Text("Refresh the list (`${FirmwareCommands.JSON_LIST} a`)")
                    }
                    LazyColumn(
                        modifier = Modifier.fillMaxWidth().height(280.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        items(aps, key = { it.bssid }) { ap ->
                            Surface(
                                shape = RoundedCornerShape(8.dp),
                                color = MaterialTheme.colorScheme.surfaceVariant,
                                onClick = { onPick(ap) },
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Row(Modifier.padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
                                    Column(Modifier.weight(1f)) {
                                        Text(
                                            ap.essid.ifBlank { "(hidden)" },
                                            style = MaterialTheme.typography.bodyMedium,
                                            color = MaterialTheme.colorScheme.onSurface,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                        Text(
                                            "slot ${ap.index} · ch ${ap.channel} · ${ap.rssi} dBm · ${ap.bssid}",
                                            style = MaterialTheme.typography.bodySmall,
                                            fontFamily = FontFamily.Monospace,
                                            color = MarauderTextDim,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}
