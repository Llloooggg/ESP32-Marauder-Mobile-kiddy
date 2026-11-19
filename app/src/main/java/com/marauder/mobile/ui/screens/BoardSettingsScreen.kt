package com.marauder.mobile.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.RestartAlt
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.marauder.mobile.data.BoardSetting
import com.marauder.mobile.data.FirmwareCommands
import com.marauder.mobile.ui.components.SectionLabel
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.MarauderCyan
import com.marauder.mobile.ui.theme.MarauderTextDim
import com.marauder.mobile.ui.theme.Warning
import com.marauder.mobile.usb.UsbSerialManager
import com.marauder.mobile.vm.MarauderViewModel

/**
 * The board's own settings, read from the device (`settings`) and written back through
 * `settings -s <name> enable|disable`.
 *
 * What the screen shows is exactly what the firmware is willing to say: the device prints
 * its client password as `[redacted]`, and it only accepts writes for boolean settings, so
 * the string settings are read-only here rather than a field that looks editable. Every
 * switch is confirmed by reading the dump back — a change the board did not apply is
 * reported as failed instead of left shown as the state the app asked for.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BoardSettingsScreen(
    vm: MarauderViewModel,
    onBack: () -> Unit,
) {
    val settings by vm.boardSettings.collectAsState()
    val busy by vm.boardSettingsBusy.collectAsState()
    val error by vm.boardSettingsError.collectAsState()
    val link by vm.status.collectAsState()
    val connected = link == UsbSerialManager.Status.CONNECTED
    var confirmReset by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) { if (connected) vm.requestBoardSettings() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Board settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
                actions = {
                    IconButton(onClick = { vm.requestBoardSettings() }, enabled = connected && !busy) {
                        Icon(Icons.Filled.Refresh, contentDescription = "Read again")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MarauderCyan,
                ),
            )
        },
    ) { inner ->
        Column(Modifier.fillMaxSize().padding(inner).padding(horizontal = 16.dp)) {
            Text(
                "These are the board's switches, not the app's. `ChanHop` decides whether a scan " +
                    "hops channels, `SavePCAP`/`ForcePMKID`/`EPDeauth` change what a capture collects. " +
                    "Every change is read back before it is called done.",
                style = MaterialTheme.typography.bodySmall,
                color = MarauderTextDim,
            )
            Spacer(Modifier.height(10.dp))

            if (busy) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), color = MarauderCyan, strokeWidth = 2.dp)
                    Text("Reading the board's settings…", style = MaterialTheme.typography.bodySmall)
                }
            }
            error?.let {
                Text("✗ $it", style = MaterialTheme.typography.bodySmall, color = Danger)
            }
            if (settings.isEmpty() && !busy) {
                Spacer(Modifier.height(12.dp))
                Text(
                    if (connected) "Nothing read yet — pull to refresh above." else "Connect a board to read its settings.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MarauderTextDim,
                )
            }

            LazyColumn(Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(settings, key = { it.name }) { s ->
                    SettingRow(s, enabled = connected && !busy, onToggle = { want -> vm.setBoardSetting(s, want) })
                }
                item {
                    Spacer(Modifier.height(8.dp))
                    SectionLabel("Danger zone")
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = Danger.copy(alpha = 0.10f),
                        border = BorderStroke(1.dp, Danger.copy(alpha = 0.5f)),
                        modifier = Modifier.fillMaxWidth(),
                        onClick = { confirmReset = true },
                    ) {
                        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.RestartAlt, contentDescription = null, tint = Danger, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(10.dp))
                            Column(Modifier.weight(1f)) {
                                Text("Reset every setting", color = Danger, fontWeight = FontWeight.SemiBold,
                                    style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    "`${FirmwareCommands.settingsReset()}` — puts the board back to its factory settings, " +
                                        "including the saved client network.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MarauderTextDim,
                                )
                            }
                        }
                    }
                    Spacer(Modifier.height(16.dp))
                }
            }
        }
    }

    if (confirmReset) {
        AlertDialog(
            onDismissRequest = { confirmReset = false },
            title = { Text("Reset every board setting?") },
            text = {
                Text("The firmware rewrites its own settings file. Saved client credentials and the " +
                    "capture switches all go back to the defaults, and this cannot be undone from the app.")
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmReset = false
                    vm.runCommand(FirmwareCommands.settingsReset())
                    vm.requestBoardSettings()
                }) { Text("Reset", color = Danger) }
            },
            dismissButton = { TextButton(onClick = { confirmReset = false }) { Text("Keep them") } },
        )
    }
}

@Composable
private fun SettingRow(setting: BoardSetting, enabled: Boolean, onToggle: (Boolean) -> Unit) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(horizontal = 12.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(setting.name, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    when {
                        setting.redacted -> "${setting.type} · value hidden by the board itself"
                        setting.editable -> "${setting.type} · `${FirmwareCommands.settingsSet(setting.name, !setting.enabled)}`"
                        else -> "${setting.type} · the firmware has no write for this one"
                    },
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = if (setting.editable) MarauderTextDim else Warning,
                )
                if (!setting.editable && !setting.redacted && setting.value.isNotBlank()) {
                    Text(
                        "value: ${setting.value}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MarauderTextDim,
                    )
                }
            }
            if (setting.editable) {
                Switch(checked = setting.enabled, onCheckedChange = onToggle, enabled = enabled)
            } else {
                Box(Modifier.width(52.dp)) {
                    Text(
                        if (setting.redacted) "•••" else setting.value.ifBlank { "—" },
                        style = MaterialTheme.typography.labelMedium,
                        fontFamily = FontFamily.Monospace,
                        color = MarauderTextDim,
                    )
                }
            }
        }
    }
}
