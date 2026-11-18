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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.marauder.mobile.data.Wordlist
import com.marauder.mobile.ui.components.SectionLabel
import com.marauder.mobile.ui.components.StatChip
import com.marauder.mobile.ui.theme.CatSniffer
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.MarauderCyan
import com.marauder.mobile.ui.theme.MarauderTextDim
import com.marauder.mobile.ui.theme.Success
import com.marauder.mobile.vm.MarauderViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The cracker's ammunition: the list shipped inside the APK, files picked with the
 * system picker, and plain-text lists downloaded from a direct URL.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WordlistsScreen(
    vm: MarauderViewModel,
    onBack: () -> Unit,
) {
    var items by remember { mutableStateOf<List<Wordlist>>(emptyList()) }
    var url by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf<String?>(null) }
    var doneBytes by remember { mutableLongStateOf(0L) }
    var totalBytes by remember { mutableLongStateOf(0L) }
    var notice by remember { mutableStateOf<Pair<String, Boolean>?>(null) }
    val scope = rememberCoroutineScope()

    fun reload() { items = vm.listWordlists() }
    LaunchedEffect(Unit) { reload() }

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        busy = "Importing…"
        scope.launch {
            val imported = withContext(Dispatchers.IO) { runCatching { vm.importWordlist(uri) } }
            busy = null
            val w = imported.getOrNull()
            notice = if (w != null) "Imported ${w.fileName} (${w.lines} guesses)" to true
            else "Could not import that file" to false
            reload()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Wordlists · ${items.size}") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
                actions = {
                    IconButton(onClick = { pick.launch(arrayOf("text/plain", "text/*", "application/octet-stream")) }) {
                        Icon(Icons.Filled.FileDownload, contentDescription = "Import from storage", tint = MarauderCyan)
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
            modifier = Modifier.fillMaxSize().padding(inner),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item {
                Text(
                    "One guess per line. The cracker walks the selected lists in order — a small list first is usually faster for weak passwords.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MarauderTextDim,
                )
            }

            item {
                SectionLabel("Download a list")
            }
            item {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    OutlinedTextField(
                        value = url,
                        onValueChange = { url = it },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        placeholder = { Text("https://…/wordlist.txt", color = MarauderTextDim) },
                        label = { Text("Direct link to a plain-text wordlist") },
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        ActionTile(
                            label = if (busy != null) "Working…" else "Download",
                            icon = Icons.Filled.Download,
                            tint = MarauderCyan,
                            enabled = busy == null && url.isNotBlank(),
                            modifier = Modifier.weight(1f),
                        ) {
                            busy = "Downloading…"
                            doneBytes = 0L
                            totalBytes = 0L
                            scope.launch {
                                val result = vm.downloadWordlist(url) { done, total ->
                                    doneBytes = done
                                    totalBytes = total
                                }
                                busy = null
                                result
                                    .onSuccess {
                                        notice = "Downloaded ${it.fileName} (${it.lines} guesses)" to true
                                        url = ""
                                    }
                                    .onFailure { notice = (it.message ?: "Download failed") to false }
                                reload()
                            }
                        }
                        if (items.none { it.builtin }) {
                            ActionTile(
                                label = "Restore built-in",
                                icon = Icons.Filled.Restore,
                                tint = Success,
                                modifier = Modifier.weight(1f),
                            ) {
                                scope.launch(Dispatchers.IO) {
                                    vm.restoreBuiltInWordlist()
                                    withContext(Dispatchers.Main) { reload() }
                                }
                            }
                        }
                    }
                    if (busy != null) {
                        if (totalBytes > 0) {
                            LinearProgressIndicator(
                                progress = { (doneBytes.toFloat() / totalBytes.toFloat()).coerceIn(0f, 1f) },
                                modifier = Modifier.fillMaxWidth(),
                            )
                            Text(
                                "${formatSize(doneBytes)} of ${formatSize(totalBytes)}",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace,
                                color = MarauderTextDim,
                            )
                        } else {
                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                            Text(busy ?: "", style = MaterialTheme.typography.labelSmall, color = MarauderTextDim)
                        }
                    }
                    notice?.let { (text, ok) ->
                        Text(text, style = MaterialTheme.typography.labelMedium, color = if (ok) Success else Danger)
                    }
                }
            }

            item { SectionLabel("On this phone") }
            if (items.isEmpty()) {
                item {
                    Text(
                        "No wordlists yet. The built-in list should appear any second now — if it does not, use Restore built-in or import a file.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MarauderTextDim,
                    )
                }
            }
            items(items, key = { it.fileName }) { list ->
                WordlistRow(
                    list = list,
                    onDelete = {
                        vm.deleteWordlist(list.fileName)
                        reload()
                    },
                )
            }
        }
    }
}

@Composable
private fun WordlistRow(list: Wordlist, onDelete: () -> Unit) {
    Surface(
        shape = RoundedCornerShape(13.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Storage, contentDescription = null, tint = CatSniffer, modifier = Modifier.size(24.dp))
            Column(Modifier.weight(1f).padding(start = 12.dp)) {
                Text(
                    list.label,
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = if (list.builtin) FontWeight.Bold else FontWeight.Normal,
                )
                Spacer(Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    StatChip("GUESSES", list.lines.toString(), MarauderCyan)
                    StatChip("SIZE", formatSize(list.bytes), MaterialTheme.colorScheme.onSurfaceVariant)
                    if (list.builtin) StatChip("BUILT-IN", "", Success)
                }
            }
            IconButton(onClick = onDelete) {
                Icon(Icons.Filled.Delete, contentDescription = "Delete", tint = Danger)
            }
        }
    }
}

@Composable
private fun ActionTile(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    tint: androidx.compose.ui.graphics.Color,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    Surface(
        onClick = onClick,
        enabled = enabled,
        shape = RoundedCornerShape(11.dp),
        color = tint.copy(alpha = if (enabled) 0.14f else 0.05f),
        modifier = modifier,
    ) {
        Row(Modifier.padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = if (enabled) tint else MarauderTextDim, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(6.dp))
            Text(label, style = MaterialTheme.typography.labelLarge, color = if (enabled) tint else MarauderTextDim, fontWeight = FontWeight.SemiBold)
        }
    }
}
