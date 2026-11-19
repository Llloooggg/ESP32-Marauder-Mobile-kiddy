package com.marauder.mobile.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DriveFileMove
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.unit.dp
import com.marauder.mobile.data.Artifact
import com.marauder.mobile.data.ArtifactRecord
import com.marauder.mobile.data.CaptureAttribution
import com.marauder.mobile.data.CaptureDiagnosis
import com.marauder.mobile.data.KeyManagement
import com.marauder.mobile.ui.copyToDocument
import com.marauder.mobile.ui.components.SectionLabel
import com.marauder.mobile.ui.components.StatChip
import com.marauder.mobile.ui.shareFile
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.MarauderCyan
import com.marauder.mobile.ui.theme.MarauderTextDim
import com.marauder.mobile.ui.theme.Success
import com.marauder.mobile.ui.theme.Warning
import com.marauder.mobile.vm.MarauderViewModel
import kotlinx.coroutines.launch
import java.util.Locale

/**
 * One artifact: what it is, where it came from, and what can be done with it —
 * extract crack-ready hashes, crack it, share it, copy it out, or delete it.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ArtifactDetailScreen(
    artifactName: String,
    vm: MarauderViewModel,
    onBack: () -> Unit,
    onOpenCrack: (String) -> Unit,
) {
    val context = LocalContext.current
    val ioScope = rememberCoroutineScope()
    var artifact by remember(artifactName) { mutableStateOf(vm.artifact(artifactName)) }
    var showDelete by remember { mutableStateOf(false) }
    var renameFrom by remember { mutableStateOf<String?>(null) }
    var analysing by remember { mutableStateOf(false) }

    fun reload() { artifact = vm.artifact(artifactName) }

    val export = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val file = artifact?.file
        if (uri != null && file != null) {
            val ok = copyToDocument(context, file, uri)
            vm.queueMessage(if (ok) "Exported a copy of ${file.name}" else "Could not write the copy")
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(artifact?.record?.title?.ifBlank { artifactName } ?: artifactName) },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
                actions = {
                    IconButton(onClick = { renameFrom = artifactName }) {
                        Icon(Icons.Filled.Edit, contentDescription = "Rename", tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    IconButton(onClick = { showDelete = true }) {
                        Icon(Icons.Filled.Delete, contentDescription = "Delete", tint = Danger)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
            )
        },
    ) { inner ->
        val record = artifact?.record
        if (record == null) {
            Column(
                Modifier.fillMaxSize().padding(inner).padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text("This artifact is gone.", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
                Spacer(Modifier.height(8.dp))
                Text("Its file was removed from the captures folder.", style = MaterialTheme.typography.bodySmall, color = MarauderTextDim)
            }
            return@Scaffold
        }

        val file = artifact!!.file
        val cracked = record.meta["cracked"]
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatChip("KIND", record.kind.uppercase(Locale.US), MarauderCyan)
                StatChip("SIZE", formatSize(file.length()), MaterialTheme.colorScheme.onSurfaceVariant)
                StatChip("CREATED", formatDate(record.createdAt), MaterialTheme.colorScheme.onSurfaceVariant)
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                when (record.hashState) {
                    ArtifactRecord.HASH_DONE -> StatChip(
                        "HASHES",
                        "pmkid ${record.meta["pmkid"] ?: 0} · M2 ${record.meta["handshakes"] ?: 0}",
                        Success,
                    )
                    ArtifactRecord.HASH_FAIL -> StatChip("NO USABLE HASHES", record.note, Danger)
                    else -> StatChip("HASHES", "not analysed", Warning)
                }
                if (!cracked.isNullOrBlank()) StatChip("CRACKED", cracked, Success)
            }

            // The reason this screen was opened, above the fold. It used to sit under a full screen of
            // internal counters, so the thing a person came for - "crack this" - was below the scroll
            // and the raw provenance was not.
            SectionLabel("What to do with it")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Big(
                    label = if (analysing) "Analysing…" else "Extract hashes",
                    icon = Icons.Filled.Analytics,
                    tint = MarauderCyan,
                    modifier = Modifier.weight(1f),
                ) {
                    analysing = true
                    ioScope.launch {
                        val result = vm.analyzeArtifactSuspending(artifactName)
                        analysing = false
                        reload()
                        when {
                            result == null -> vm.queueMessage("The hash extractor is not wired into this build yet")
                            !result.usable -> vm.queueMessage(result.note ?: "No PMKID or WPA handshake in this capture")
                            else -> vm.queueMessage("${result.hashLines.size} hash line(s) ready — PMKID ${result.pmkidCount}, handshakes ${result.handshakeSets}")
                        }
                    }
                }
                val canCrack = record.hashState == ArtifactRecord.HASH_DONE
                Big(
                    label = "Crack",
                    icon = Icons.Filled.VpnKey,
                    tint = if (canCrack) Success else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f),
                    enabled = canCrack,
                ) { onOpenCrack(artifactName) }
            }

            // The BSSID the operation was pinned to vs the BSSIDs the credential
            // material in this file belongs to. They can differ — the board hears every
            // network on the channel — and when they do, that has to be stated here
            // rather than discovered by cross-reading MACs.
            val aimed = record.meta[ArtifactRecord.TARGET_BSSID]
            val capturedNetworks = (record.meta["networks"] ?: "").split(' ').filter { it.isNotBlank() }
            val attribution = remember(record.meta) { CaptureAttribution.verdict(aimed, capturedNetworks) }
            when (attribution) {
                CaptureAttribution.Verdict.Match -> StatChip("AIMED AT", aimed.orEmpty(), Success)
                is CaptureAttribution.Verdict.Mismatch -> {
                    SectionLabel("This capture does not hold the network you aimed at")
                    Text(
                        CaptureAttribution.explain(attribution).orEmpty(),
                        style = MaterialTheme.typography.bodySmall,
                        color = Danger,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        StatChip("AIMED AT", attribution.aimed, MarauderTextDim)
                        StatChip("CAPTURED", attribution.captured.joinToString().ifEmpty { "—" }, Danger)
                    }
                }
                else -> Unit
            }

            // Whether a cracker can work on this file at all is decided by the network's
            // key management, so it is stated next to the counts rather than left to be
            // inferred: an SAE-only (WPA3) network has no password hash in here.
            val kmVerdicts = remember(record.meta) { KeyManagement.verdicts(record.meta) }
            val saeOnly = remember(record.meta) { KeyManagement.saeOnly(record.meta) }
            if (kmVerdicts.isNotEmpty()) {
                SectionLabel("Key management · what a cracker can do with it")
                Surface(
                    shape = RoundedCornerShape(11.dp),
                    color = MaterialTheme.colorScheme.surface,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        kmVerdicts.forEach { v ->
                            Column {
                                Text(
                                    v.bssid,
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = if (v.saeOnly) Danger else MarauderCyan,
                                )
                                Text(
                                    v.label,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = if (v.saeOnly) Danger else MaterialTheme.colorScheme.onSurface,
                                )
                            }
                        }
                        val frames = record.meta[KeyManagement.SAE_FRAMES]?.toIntOrNull() ?: 0
                        if (frames > 0) {
                            Text(
                                "$frames SAE authentication frame(s) in this capture — that is the WPA3 dragonfly " +
                                    "exchange on air, independent of what the beacons claim.",
                                style = MaterialTheme.typography.labelSmall,
                                color = MarauderTextDim,
                            )
                        }
                    }
                }
            }
            KeyManagement.explainSae(saeOnly, aimed)?.let { why ->
                SectionLabel("Offline cracking does not apply here")
                Text(why, style = MaterialTheme.typography.bodySmall, color = Danger)
            }

            SectionLabel("What this file holds")
            Text(
                when (record.kind.lowercase(Locale.US)) {
                    "pcap" -> "802.11 frames the board captured (association, handshake, data). Extracting hashes turns it into something a cracker can work on."
                    "gpx" -> "A GPS track of a walk or drive, with the points the board logged."
                    "csv" -> "Wardrive rows: network, BSSID, channel, signal and position — importable into Wigle-format tools."
                    else -> "A text log written while the board was working."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MarauderTextDim,
            )

            if (record.hashState == ArtifactRecord.HASH_FAIL && record.note.isNotBlank()) {
                SectionLabel("Why nothing is crackable")
                Text(
                    record.note,
                    style = MaterialTheme.typography.bodySmall,
                    color = Danger,
                )
                Text(
                    "EAPOL frames on the board's console is not the same thing as a crackable credential: " +
                        "the four-way handshake needs the AP's message (M1, or M3 as a fallback) AND the client's " +
                        "M2, plus the network's SSID. The counts above say which of those the capture is missing.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MarauderTextDim,
                )
                // The case no cracker can be configured out of, said in as many words.
                if (CaptureDiagnosis.eapolOnlyFromAp(record.meta)) {
                    Text(
                        "and this file is short of the one side no tool can supply: every EAPOL frame in it came " +
                            "from the access point" +
                            (record.meta[CaptureDiagnosis.META_EAPOL_RETRIED]?.let { r ->
                                if (r != "0") " ($r of them retransmissions, the Retry bit set — it was repeating " +
                                    "itself at a client that never answered)" else ""
                            }.orEmpty()) +
                            ". There is no client frame here to pair with, so no wordlist, no GPU and no longer " +
                            "capture of the same silent client can produce a hash. What would change it is a " +
                            "client that actually transmits on this band.",
                        style = MaterialTheme.typography.bodySmall,
                        color = Warning,
                    )
                }
            }

            if (record.meta.isNotEmpty()) {
                // The raw table is this app's own bookkeeping. It is worth keeping - it is how a
                // capture is argued about later - but a screen of internal keys buries the facts that
                // decide what to do next. So the few that decide it are said plainly, and the rest is
                // one tap away rather than removed: hiding evidence is not our call to make silently.
                SectionLabel("Provenance")
                val frames = record.meta["frames"]
                val eapol = record.meta["eapolFrames"]
                val fromAp = record.meta["eapol_ap"]
                val fromClient = record.meta["eapol_client"]
                val how = record.meta["command"]
                val summary = buildList {
                    frames?.let { add("$it frames") }
                    if (eapol != null) {
                        add(
                            "$eapol EAPOL" +
                                if (fromAp != null && fromClient != null) " ($fromAp from the AP, $fromClient from the client)" else ""
                        )
                    }
                    how?.let { add("captured with: $it") }
                }
                if (summary.isNotEmpty()) {
                    Text(
                        summary.joinToString(" · "),
                        style = MaterialTheme.typography.bodySmall,
                        color = MarauderTextDim,
                    )
                }
                var showRaw by remember(artifactName) { mutableStateOf(false) }
                TextButton(onClick = { showRaw = !showRaw }) {
                    Text(if (showRaw) "Hide the raw fields" else "Show the raw fields")
                }
                if (showRaw) {
                    Surface(
                        shape = RoundedCornerShape(11.dp),
                        color = MaterialTheme.colorScheme.surface,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            val essids = record.meta.keys.count { it.startsWith(ArtifactRecord.SSID_META) }
                            record.meta.toSortedMap().forEach { (key, value) ->
                                if (key == "path" || key.startsWith(ArtifactRecord.SSID_META)) return@forEach
                                Row {
                                    Text(
                                        key,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MarauderTextDim,
                                        modifier = Modifier.padding(end = 8.dp),
                                    )
                                    Text(
                                        value,
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        color = MaterialTheme.colorScheme.onSurface,
                                    )
                                }
                            }
                            if (essids > 0) {
                                Row {
                                    Text(
                                        "ssids",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MarauderTextDim,
                                        modifier = Modifier.padding(end = 8.dp),
                                    )
                                    Text(
                                        "$essids kept from the scan list (used as the crack salt when the capture has no beacon)",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MarauderTextDim,
                                    )
                                }
                            }
                        }
                    }
                }
            }

            // File chores, deliberately below the job the capture was opened for.
            SectionLabel("Keep the file")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Big(
                    label = "Share",
                    icon = Icons.Filled.Share,
                    tint = Success,
                    modifier = Modifier.weight(1f),
                ) {
                    if (!shareFile(context, file)) vm.queueMessage("This file cannot be shared")
                }
                Big(
                    label = "Export copy",
                    icon = Icons.Filled.DriveFileMove,
                    tint = Success,
                    modifier = Modifier.weight(1f),
                ) { export.launch(file.name) }
                Big(
                    label = "Delete",
                    icon = Icons.Filled.Delete,
                    tint = Danger,
                    modifier = Modifier.weight(1f),
                ) { showDelete = true }
            }

            Text(
                "Captures live in the app's own folder (${file.parent ?: "captures"}). Use Export copy to put one somewhere you can open it with other apps.",
                style = MaterialTheme.typography.labelSmall,
                color = MarauderTextDim,
            )
        }

        if (showDelete) {
            AlertDialog(
                onDismissRequest = { showDelete = false },
                title = { Text("Delete this artifact?") },
                text = { Text("The file and its library entry are removed from the phone. This cannot be undone.") },
                confirmButton = {
                    TextButton(onClick = {
                        vm.deleteArtifact(artifactName)
                        showDelete = false
                        onBack()
                    }) { Text("DELETE", color = Danger) }
                },
                dismissButton = { TextButton(onClick = { showDelete = false }) { Text("KEEP") } },
            )
        }

        renameFrom?.let {
            var text by remember { mutableStateOf(record.title.ifBlank { record.name }) }
            AlertDialog(
                onDismissRequest = { renameFrom = null },
                title = { Text("Rename artifact") },
                text = {
                    Column {
                        Text(
                            "The file keeps its name (${record.name}); only the library label changes.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MarauderTextDim,
                        )
                        Spacer(Modifier.height(6.dp))
                        OutlinedTextField(value = text, onValueChange = { text = it }, singleLine = true, label = { Text("Title") })
                    }
                },
                confirmButton = {
                    TextButton(onClick = {
                        vm.renameArtifact(artifactName, text.trim())
                        renameFrom = null
                        reload()
                    }) { Text("SAVE", color = MarauderCyan) }
                },
                dismissButton = { TextButton(onClick = { renameFrom = null }) { Text("CANCEL") } },
            )
        }
    }
}

@Composable
private fun Big(
    label: String,
    icon: ImageVector,
    tint: Color,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    val alpha = if (enabled) 0.13f else 0.05f
    Surface(
        onClick = onClick,
        enabled = enabled,
        shape = RoundedCornerShape(12.dp),
        color = tint.copy(alpha = alpha),
        border = BorderStroke(1.dp, tint.copy(alpha = if (enabled) 0.45f else 0.15f)),
        modifier = modifier,
    ) {
        Column(Modifier.padding(vertical = 13.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(icon, contentDescription = null, tint = if (enabled) tint else MarauderTextDim, modifier = Modifier.size(20.dp))
            Spacer(Modifier.height(5.dp))
            Text(
                label,
                style = MaterialTheme.typography.labelMedium,
                color = if (enabled) tint else MarauderTextDim,
                fontWeight = FontWeight.SemiBold,
            )
        }
    }
}
