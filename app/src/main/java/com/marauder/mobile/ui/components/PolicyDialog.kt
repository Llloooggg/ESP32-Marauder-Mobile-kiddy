package com.marauder.mobile.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.marauder.mobile.data.Tier
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.Warning

/**
 * The policy gate for firmware commands, friction scaled to [Tier]:
 *  - SAFE: no dialog at all (callers only raise one for MODERATE/HIGH).
 *  - MODERATE: one confirm that shows the exact command.
 *  - HIGH: two-step — an explicit acknowledgement checkbox unlocks the Run button.
 * Every message reminds the user that active RF belongs to their own gear.
 */
@Composable
fun PolicyDialog(
    title: String,
    command: String,
    tier: Tier,
    note: String? = null,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    var acknowledged by remember { mutableStateOf(false) }
    val high = tier == Tier.HIGH
    val accent = if (high) Danger else Warning

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title, color = MaterialTheme.colorScheme.onSurface) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "$ $command",
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    text = note ?: "This transmits on radio channels. Use it only against networks and devices you own or have written permission to test.",
                    style = MaterialTheme.typography.bodySmall,
                    color = accent,
                )
                if (high) {
                    Spacer(Modifier.height(4.dp))
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Checkbox(checked = acknowledged, onCheckedChange = { acknowledged = it })
                        Text(
                            "I take responsibility for the interference this causes",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = onConfirm,
                enabled = !high || acknowledged,
            ) { Text(if (high) "RUN" else "CONFIRM", color = accent) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("CANCEL") }
        },
    )
}

/** Small pill naming a policy tier, shown next to gated actions. */
@Composable
fun TierChip(tier: Tier, modifier: Modifier = Modifier) {
    val (label, color) = when (tier) {
        Tier.SAFE -> "SAFE" to MaterialTheme.colorScheme.onSurfaceVariant
        Tier.MODERATE -> "ACTIVE RF" to Warning
        Tier.HIGH -> "INTERFERENCE" to Danger
    }
    Text(
        text = label,
        style = MaterialTheme.typography.labelSmall,
        color = color,
        modifier = modifier.padding(horizontal = 4.dp),
    )
}
