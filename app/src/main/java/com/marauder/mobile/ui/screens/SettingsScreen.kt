package com.marauder.mobile.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.marauder.mobile.BuildConfig
import com.marauder.mobile.data.LineRateOption
import com.marauder.mobile.ui.components.SectionLabel
import com.marauder.mobile.ui.components.StatChip
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.MarauderCyan
import com.marauder.mobile.ui.theme.MarauderTextDim
import com.marauder.mobile.ui.theme.Success
import com.marauder.mobile.ui.theme.Warning
import com.marauder.mobile.usb.UsbSerialManager
import com.marauder.mobile.vm.MarauderViewModel

/**
 * App settings: whether captures are analysed automatically, the USB-serial line
 * rate the board is asked for, and the honest capture-integrity counters (frames lost on the link, packets the board's ring dropped) that
 * explain why a pcap can come up short.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    vm: MarauderViewModel,
    onBack: () -> Unit,
    onOpenWordlists: () -> Unit,
    onOpenAbout: () -> Unit,
) {
    val autoAnalyze by vm.autoAnalyze.collectAsState()
    val lineRate by vm.lineRate.collectAsState()
    val activeRate by vm.activeLineRate.collectAsState()
    val capture by vm.capture.collectAsState()
    val linkStatus by vm.status.collectAsState()
    val connected = linkStatus == UsbSerialManager.Status.CONNECTED

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MarauderCyan,
                ),
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            SectionLabel("What this build is")
            SettingCard {
                Text(
                    "Marauder Mobile Kiddy v${BuildConfig.VERSION_NAME} · package ${BuildConfig.APPLICATION_ID}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    "Installs beside the upstream app; each keeps its own library. Move files with Share / Export copy.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MarauderTextDim,
                )
                Text(
                    "Library folder: ${vm.artifactsFolder()}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MarauderTextDim,
                )
            }

            SectionLabel("Capture handling")
            SwitchRow(
                title = "Analyse captures automatically",
                hint = "extract hashes when a capture closes",
                checked = autoAnalyze,
                onToggle = vm::setAutoAnalyze,
            )

            SectionLabel("USB serial link")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatChip(
                    "LINE RATE NOW",
                    if (activeRate > 0) "$activeRate baud" else "not connected",
                    if (activeRate > 460_800) Success else MarauderCyan,
                )
                StatChip("SETTLED ASK", LineRateOption.label(lineRate), MarauderTextDim)
            }
            SettingCard {
                Text(
                    "The board boots at 115200; a replug returns it there. Only a rate the board confirms is used.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MarauderTextDim,
                )
                Text(
                    "CH340 bridges often cannot hold 921600. If the console turns to garbage, unplug and replug the board.",
                    style = MaterialTheme.typography.bodySmall,
                    color = Warning,
                )
            }
            LineRateOption.OPTIONS.forEach { option ->
                RateRow(
                    option = option,
                    selected = lineRate == option.rate,
                    enabled = connected,
                    onSelect = { vm.setLineRate(option.rate) },
                )
            }
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(Icons.Filled.Refresh, contentDescription = null, tint = MarauderTextDim, modifier = Modifier.size(18.dp))
                Text(
                    "Ask for the selected rate again",
                    style = MaterialTheme.typography.labelSmall,
                    color = MarauderTextDim,
                )
                Spacer(Modifier.width(4.dp))
                Text(
                    "(applied on connect too)",
                    style = MaterialTheme.typography.labelSmall,
                    color = MarauderTextDim,
                )
            }

            SectionLabel("Capture integrity")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatChip(
                    "LINK GAPS",
                    capture.missedFrames.toString(),
                    if (capture.missedFrames > 0) Danger else Success,
                )
                StatChip(
                    "BOARD DROPS",
                    capture.droppedPackets.toString(),
                    if (capture.droppedPackets > 0) Danger else Success,
                )
                StatChip("CAPTURE BYTES", formatBytes(capture.bytes), MarauderCyan)
            }
            SettingCard {
                Text(
                    "LINK GAPS = frames the serial link dropped before they reached the phone. The reader resyncs after " +
                        "a hole; the artifact says how many bytes were skipped.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MarauderTextDim,
                )
                Text(
                    "BOARD DROPS = frames the board itself could not keep. Only a higher line rate or a quieter channel " +
                        "changes that.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MarauderTextDim,
                )
                if (capture.missedFrames > 0 || capture.droppedPackets > 0) {
                    Text(
                        "A capture with loss can still hold a complete handshake: a zero result here means " +
                            "\"incomplete capture\", not \"no handshake\".",
                        style = MaterialTheme.typography.bodySmall,
                        color = Warning,
                    )
                }
            }

            SectionLabel("Data")
            SettingCard {
                TextRow("Wordlists", "built-in list plus your imports and downloads", onClick = onOpenWordlists)
                TextRow("About, licence and terms", "authorised-use notice, sources", onClick = onOpenAbout)
            }
            Spacer(Modifier.size(18.dp))
        }
    }
}

@Composable
private fun SettingCard(content: @Composable () -> Unit) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) { content() }
    }
}

@Composable
private fun SwitchRow(
    title: String,
    hint: String,
    checked: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        color = MaterialTheme.colorScheme.surface,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            Modifier.padding(13.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(hint, style = MaterialTheme.typography.bodySmall, color = MarauderTextDim)
            }
            Switch(checked = checked, onCheckedChange = onToggle)
        }
    }
}

@Composable
private fun RateRow(
    option: LineRateOption,
    selected: Boolean,
    enabled: Boolean,
    onSelect: () -> Unit,
) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, if (selected) MarauderCyan else MaterialTheme.colorScheme.outlineVariant),
        color = if (selected) MaterialTheme.colorScheme.surfaceVariant else MaterialTheme.colorScheme.surface,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled, onClick = onSelect),
    ) {
        Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    option.label,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = if (selected) MarauderCyan else MaterialTheme.colorScheme.onSurface,
                )
                if (selected) Text("applied", style = MaterialTheme.typography.labelSmall, color = MarauderCyan)
            }
            Text(option.hint, style = MaterialTheme.typography.bodySmall, color = MarauderTextDim)
        }
    }
}

@Composable
private fun TextRow(title: String, hint: String, onClick: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(title, style = MaterialTheme.typography.titleMedium, color = MarauderCyan)
        Text(hint, style = MaterialTheme.typography.labelSmall, color = MarauderTextDim)
    }
}

private fun formatBytes(bytes: Long): String = when {
    bytes >= 1_000_000 -> "${bytes / 1_000_000} MB"
    bytes >= 1_000 -> "${bytes / 1_000} KB"
    else -> "$bytes B"
}
