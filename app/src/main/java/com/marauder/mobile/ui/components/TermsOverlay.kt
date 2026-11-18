package com.marauder.mobile.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Gavel
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.MarauderCyan
import com.marauder.mobile.ui.theme.Warning

/**
 * The authorised-use gate. Shown full-screen the first time a board reports in and
 * never dismissed by tapping away: the user either accepts (and may then send
 * commands) or leaves the app. Legal cover matters for a tool that deauthenticates
 * networks and spams Bluetooth devices.
 */
@Composable
fun TermsOverlay(onAccept: () -> Unit, onExit: () -> Unit) {
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background,
    ) {
        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.Gavel, contentDescription = null, tint = Warning, modifier = Modifier.size(28.dp))
                Spacer(Modifier.size(10.dp))
                Text(
                    "Before you send a single command",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }

            Bullet(
                "This app drives hardware that transmits on radio channels: deauthentication floods, PMKID capture with forced reconnects, beacon and Bluetooth spam, evil portals.",
                Warning,
            )
            Bullet(
                "Use it only against networks, devices and drones you own, or that you have explicit written permission to test. Everything else is illegal in most countries, including passive capture of other people's traffic.",
                Danger,
            )
            Bullet(
                "The firmware and this app come without warranty. You are responsible for what your transmissions do, and for what the captured data contains.",
                MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Bullet(
                "Captured handshakes and PMKIDs can reveal a Wi-Fi password when cracked. Storing or cracking someone else's is a crime even if you never connect to their network.",
                Danger,
            )
            Bullet(
                "Keep captures you did not create yourself out of this app: delete them, and delete anything you export once the audit is done.",
                MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(Modifier.height(8.dp))
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    "By tapping Accept you confirm you have the right to test whatever this phone transmits against, and that you accept the risk of doing it wrong.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    "The notice can be shown again from the About screen.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MarauderCyan,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                TextButton(onClick = onExit) { Text("LEAVE", color = MaterialTheme.colorScheme.onSurfaceVariant) }
                TextButton(onClick = onAccept) { Text("ACCEPT", color = MarauderCyan) }
            }
        }
    }
}

@Composable
private fun Bullet(text: String, color: androidx.compose.ui.graphics.Color) {
    Row {
        Text("•", style = MaterialTheme.typography.bodyMedium, color = color, modifier = Modifier.padding(end = 8.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
    }
}
