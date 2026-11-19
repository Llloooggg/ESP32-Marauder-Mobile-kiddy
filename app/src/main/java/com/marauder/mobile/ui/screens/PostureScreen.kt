package com.marauder.mobile.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.marauder.mobile.data.ListType
import com.marauder.mobile.ui.components.EmptyState
import com.marauder.mobile.ui.components.SectionLabel
import com.marauder.mobile.ui.components.StatChip
import com.marauder.mobile.ui.theme.CatAttack
import com.marauder.mobile.ui.theme.CatScanner
import com.marauder.mobile.ui.theme.CatWifi
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.MarauderCyan
import com.marauder.mobile.ui.theme.MarauderTextDim
import com.marauder.mobile.ui.theme.Success
import com.marauder.mobile.ui.theme.Warning
import com.marauder.mobile.usb.UsbSerialManager
import com.marauder.mobile.vm.MarauderViewModel

/**
 * Network posture: what the board can do once it is *on* a network instead of only
 * listening to one — associate with it (`join`), find the other hosts on that segment
 * (`pingscan` / `arpscan`), then look at what a specific host exposes (`portscan`).
 *
 * Two honesty points the screen states out loud, because both are easy to get wrong:
 *  * `join` and `portscan -t` address **list slots**, so the app resolves them from the
 *    BSSID / IP at press time rather than carrying a number across screens;
 *  * the firmware does not report its association state over JSON at all, so the only
 *    evidence that a join worked is the board's own console text and whether the host
 *    list starts filling up. The app will not claim "connected" when it cannot know.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PostureScreen(
    vm: MarauderViewModel,
    onBack: () -> Unit,
    onOpenLive: (title: String, command: String) -> Unit,
    onOpenScan: () -> Unit,
) {
    val aps by vm.aps.collectAsState()
    val ips by vm.ips.collectAsState()
    val devStatus by vm.deviceStatus.collectAsState()
    val connStatus by vm.status.collectAsState()
    val connected = connStatus == UsbSerialManager.Status.CONNECTED

    var chosenBssid by remember { mutableStateOf<String?>(null) }
    var password by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        vm.refreshList(ListType.ACCESS_POINTS)
        vm.refreshList(ListType.IPS)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Network posture") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
                actions = {
                    IconButton(onClick = {
                        vm.refreshList(ListType.ACCESS_POINTS)
                        vm.refreshList(ListType.IPS)
                    }) {
                        Icon(Icons.Filled.Refresh, contentDescription = "Refresh lists", tint = MarauderCyan)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
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
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    StatChip(
                        "HOSTS",
                        (devStatus?.ips ?: ips.size).toString(),
                        if (ips.isNotEmpty()) Success else MarauderTextDim,
                    )
                    StatChip("NETWORKS", aps.size.toString(), CatWifi)
                    StatChip(
                        "BOARD",
                        if (devStatus?.running == true) "busy" else if (connected) "idle" else "offline",
                        if (!connected) Danger else if (devStatus?.running == true) Warning else Success,
                    )
                }
            }

            item {
                Text(
                    "Everything below is for networks you are authorised to test. The board associates with one " +
                        "network and then works that segment — it does not become a way to reach other networks.",
                    style = MaterialTheme.typography.bodySmall,
                    color = Warning,
                )
            }

            // --- 1 · associate the board -----------------------------------------
            item { SectionLabel("1 · Let the board join a network") }
            if (aps.isEmpty()) {
                item {
                    EmptyState(
                        icon = Icons.Filled.Wifi,
                        title = "No networks in the board's list",
                        subtitle = "Run a network scan first — join picks the SSID from that list.",
                    )
                }
                item {
                    OutlinedButton(onClick = onOpenScan, modifier = Modifier.fillMaxWidth()) { Text("Open scan") }
                }
            } else {
                item {
                    Surface(
                        shape = RoundedCornerShape(14.dp),
                        color = MaterialTheme.colorScheme.surface,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                "Pick the network. The app addresses it by BSSID and resolves the firmware's list " +
                                    "slot at the moment you press Join — that is where the wrong-network mistakes " +
                                    "usually come from.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MarauderTextDim,
                            )
                            Column(
                                Modifier.heightIn(max = 210.dp).verticalScroll(rememberScrollState()),
                                verticalArrangement = Arrangement.spacedBy(6.dp),
                            ) {
                                aps.forEach { ap ->
                                    val sel = chosenBssid.equals(ap.bssid, ignoreCase = true)
                                    Surface(
                                        shape = RoundedCornerShape(10.dp),
                                        color = if (sel) MaterialTheme.colorScheme.primary.copy(alpha = 0.14f)
                        else MaterialTheme.colorScheme.surfaceVariant,
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable { chosenBssid = if (sel) null else ap.bssid },
                                    ) {
                                        Row(Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
                                            Icon(
                                                Icons.Filled.Router,
                                                contentDescription = null,
                                                tint = if (sel) MarauderCyan else MarauderTextDim,
                                                modifier = Modifier.size(20.dp),
                                            )
                                            Column(Modifier.weight(1f).padding(horizontal = 10.dp)) {
                                                Text(
                                                    ap.essid.ifBlank { "(hidden)" },
                                                    style = MaterialTheme.typography.titleSmall,
                                                    fontWeight = FontWeight.SemiBold,
                                                    color = MaterialTheme.colorScheme.onSurface,
                                                )
                                                Text(
                                                    "${ap.bssid} · ch ${ap.channel} · ${ap.rssi} dBm",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    fontFamily = FontFamily.Monospace,
                                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                            OutlinedTextField(
                                value = password,
                                onValueChange = { password = it },
                                label = { Text("Password") },
                                singleLine = true,
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                                visualTransformation = PasswordVisualTransformation(),
                                modifier = Modifier.fillMaxWidth(),
                            )
                            Text(
                                "The password is sent to the board to associate with; it is not stored by the app " +
                                    "and never written to the journal. If it contains characters this firmware " +
                                    "cannot quote, the app refuses instead of sending a broken password.",
                                style = MaterialTheme.typography.labelSmall,
                                color = MarauderTextDim,
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(
                                    onClick = {
                                        aps.firstOrNull { it.bssid.equals(chosenBssid, ignoreCase = true) }
                                            ?.let { vm.joinNetwork(it.bssid, password) }
                                    },
                                    enabled = connected && chosenBssid != null && password.isNotEmpty(),
                                    modifier = Modifier.weight(1f),
                                ) { Text("Join with the board") }
                                OutlinedButton(
                                    onClick = { vm.joinSavedNetwork() },
                                    enabled = connected,
                                ) { Text("Use saved") }
                            }
                            Text(
                                "Joining takes the board off the channel it was monitoring and makes it a client of " +
                                    "that network. The app addresses the network by BSSID and resolves the firmware's " +
                                    "list slot for it at the moment the command is sent.",
                                style = MaterialTheme.typography.labelSmall,
                                color = MarauderTextDim,
                            )
                        }
                    }
                }
            }

            // --- 2 · discover the segment ----------------------------------------
            item { SectionLabel("2 · Find the hosts on that segment", modifier = Modifier.padding(top = 8.dp)) }
            item {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    PostureTile("Ping sweep", "pingscan", Modifier.weight(1f)) {
                        onOpenLive("Ping sweep", "pingscan")
                    }
                    PostureTile("ARP scan", "arpscan", Modifier.weight(1f)) {
                        onOpenLive("ARP scan", "arpscan")
                    }
                }
            }
            item {
                PostureTile("ARP scan, full sweep", "arpscan -f", Modifier.fillMaxWidth()) {
                    onOpenLive("ARP scan (full)", "arpscan -f")
                }
            }
            item {
                Text(
                    "These need the board to be on the same segment as the targets: ARP only works on the L2 " +
                        "network it is associated with, and a ping sweep of a network it is not on finds nothing. " +
                        "The firmware does not report its association state over JSON, so the console text and the " +
                        "host count are the evidence that the join actually worked.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MarauderTextDim,
                )
            }

            // --- 3 · the hosts -----------------------------------------------------
            item {
                SectionLabel("Hosts the board found · ${ips.size}", modifier = Modifier.padding(top = 8.dp))
            }
            if (ips.isEmpty()) {
                item {
                    Text(
                        "No hosts yet. Run a ping or ARP scan above — the board lists what it saw, and this list is " +
                            "what port scan addresses.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MarauderTextDim,
                    )
                }
            } else {
                items(ips, key = { it.ip }) { host ->
                    Surface(
                        shape = RoundedCornerShape(11.dp),
                        color = MaterialTheme.colorScheme.surface,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Row(Modifier.padding(horizontal = 12.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.Language, contentDescription = null, tint = CatScanner, modifier = Modifier.size(18.dp))
                            Text(
                                host.ip,
                                style = MaterialTheme.typography.bodyMedium,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.weight(1f).padding(start = 10.dp),
                            )
                            TextButton(onClick = {
                                val cmd = vm.hostScanCommand(host.ip) ?: return@TextButton
                                onOpenLive("Port scan ${host.ip}", cmd)
                            }) { Text("PORTS", color = MarauderCyan) }
                        }
                    }
                }
            }

            item { SectionLabel("Port scan by service", modifier = Modifier.padding(top = 8.dp)) }
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        "`portscan -s <service>` walks the host list looking for one service instead of probing a " +
                            "single host — useful when the interesting thing is not a host but an open door.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MarauderTextDim,
                    )
                    SERVICE_SCANS.chunked(4).forEach { row ->
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            row.forEach { svc ->
                                OutlinedButton(
                                    onClick = { onOpenLive("Service scan $svc", "portscan -s $svc") },
                                    enabled = connected,
                                    modifier = Modifier.weight(1f),
                                ) { Text(svc, style = MaterialTheme.typography.labelSmall) }
                            }
                            repeat(4 - row.size) { Spacer(Modifier.weight(1f).width(0.dp)) }
                        }
                    }
                }
            }

            item {
                Spacer(Modifier.size(16.dp))
            }
        }
    }
}

private val SERVICE_SCANS = listOf("ssh", "telnet", "dns", "http", "smtp", "https", "rdp")

@Composable
private fun PostureTile(label: String, command: String, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, CatScanner.copy(alpha = 0.45f)),
        modifier = modifier,
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Search, contentDescription = null, tint = CatScanner, modifier = Modifier.size(18.dp))
            Column(Modifier.padding(start = 10.dp)) {
                Text(label, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    "$ $command",
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = MarauderTextDim,
                )
            }
        }
    }
}
