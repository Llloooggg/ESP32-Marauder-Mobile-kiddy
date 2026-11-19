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
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.MyLocation
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.TableChart
import androidx.compose.material.icons.filled.TextSnippet
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.marauder.mobile.data.Artifact
import com.marauder.mobile.data.ArtifactRecord
import com.marauder.mobile.data.CaptureDiagnosis
import com.marauder.mobile.ui.shareFile
import com.marauder.mobile.ui.components.EmptyState
import com.marauder.mobile.ui.components.StatChip
import com.marauder.mobile.ui.theme.CatGps
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.MarauderCyan
import com.marauder.mobile.ui.theme.MarauderTextDim
import com.marauder.mobile.ui.theme.Success
import com.marauder.mobile.ui.theme.Warning
import com.marauder.mobile.vm.MarauderViewModel
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The capture library: every pcap / GPX / CSV / log the app has produced, with the
 * extraction state of each. This is where a finished mission becomes a reusable
 * artifact (share it, analyse it, crack it).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ArtifactsScreen(
    vm: MarauderViewModel,
    onBack: () -> Unit,
    onOpenArtifact: (String) -> Unit,
    onOpenWordlists: () -> Unit,
) {
    var items by remember { mutableStateOf<List<Artifact>>(emptyList()) }
    LaunchedEffect(Unit) { items = vm.listArtifacts() }

    // Session report: build (md + zip of journals/captures/hashes) then hand it to
    // another app. Building reads the whole library, so it runs off the UI thread.
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var building by remember { mutableStateOf(false) }
    val doExport: () -> Unit = {
        if (!building) {
            building = true
            vm.queueMessage("Building session report…")
            scope.launch {
                val file = vm.exportReport()
                building = false
                if (file == null) {
                    vm.queueMessage("Could not build the report")
                } else {
                    items = vm.listArtifacts()
                    if (!shareFile(context, file)) vm.queueMessage("Report saved: ${file.name}")
                }
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                // The name has to match what the entry point on Home is called, or the person looks
                // for a thing the screen never claims to be.
                title = { Text("Capture library · ${items.size}") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
                actions = {
                    IconButton(onClick = doExport) {
                        Icon(Icons.Filled.Description, contentDescription = "Export report", tint = MarauderCyan)
                    }
                    IconButton(onClick = onOpenWordlists) {
                        Icon(Icons.Filled.Storage, contentDescription = "Wordlists", tint = MarauderCyan)
                    }
                    IconButton(onClick = { items = vm.listArtifacts() }) {
                        Icon(Icons.Filled.Refresh, contentDescription = "Refresh", tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
            )
        },
    ) { inner ->
        Box(Modifier.fillMaxSize().padding(inner)) {
            if (items.isEmpty()) {
                EmptyState(
                    icon = Icons.Filled.SaveAlt,
                    title = "No captures yet",
                    subtitle = "Run a capture (Scan → pick a network → Capture handshake) and its pcap lands here.",
                    modifier = Modifier.align(Alignment.Center),
                )
            } else {
                LazyColumn(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(items, key = { it.record.name }) { artifact ->
                        ArtifactRow(artifact) { onOpenArtifact(artifact.record.name) }
                    }
                }
            }
        }
    }
}

@Composable
private fun ArtifactRow(artifact: Artifact, onClick: () -> Unit) {
    val record = artifact.record
    val (icon, tint) = kindVisual(record.kind)
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(13.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(26.dp))
            Column(Modifier.weight(1f).padding(start = 12.dp)) {
                Text(
                    record.title.ifBlank { record.name },
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.size(2.dp))
                Text(
                    "${formatDate(record.createdAt)} · ${formatSize(artifact.file.length())} · ${record.kind.uppercase(Locale.US)}",
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = MarauderTextDim,
                )
                Spacer(Modifier.size(6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (record.kind.equals("pcap", ignoreCase = true)) {
                        // Only a capture can be left un-analysed. A session log or a journal is not
                        // something hashes come out of, and a chip saying "NOT ANALYSED" on it reads
                        // as work left undone when there is none to do.
                        HashStateChip(record)
                    }
                    record.meta["eapolFrames"]?.let { StatChip("EAPOL", it, Success) }
                    // EAPOL that only the access point transmitted — the client never answered, so there
                    // is no handshake and no wordlist can produce one. That belongs on the row.
                    if (CaptureDiagnosis.eapolOnlyFromAp(record.meta)) {
                        StatChip("AP-ONLY EAPOL", record.meta[CaptureDiagnosis.META_EAPOL_TOTAL] ?: "", Warning)
                    }
                    record.meta["missedFrames"]?.let { StatChip("GAPS", it, Warning) }
                }
            }
        }
    }
}

@Composable
private fun HashStateChip(record: ArtifactRecord) {
    when (record.hashState) {
        ArtifactRecord.HASH_DONE -> {
            val lines = record.meta["hashLines"] ?: "?"
            StatChip("HASHES", lines, Success)
        }
        ArtifactRecord.HASH_FAIL -> StatChip("NO HASHES", "", Danger)
        else -> StatChip("NOT ANALYSED", "", MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

private fun kindVisual(kind: String): Pair<ImageVector, Color> = when (kind.lowercase(Locale.US)) {
    "pcap" -> Icons.Filled.Key to MarauderCyan
    "gpx" -> Icons.Filled.MyLocation to CatGps
    "csv" -> Icons.Filled.TableChart to Success
    "log" -> Icons.Filled.TextSnippet to MarauderTextDim
    else -> Icons.Filled.Description to MarauderTextDim
}

fun formatDate(ms: Long): String =
    SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date(ms))

fun formatSize(bytes: Long): String = when {
    bytes >= 1_000_000 -> "%.1f MB".format(bytes / 1_000_000.0)
    bytes >= 1_000 -> "%.0f KB".format(bytes / 1_000.0)
    else -> "$bytes B"
}
