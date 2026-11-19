package com.marauder.mobile.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.marauder.mobile.data.MenuAction
import com.marauder.mobile.data.MenuItem
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.MarauderTextDim

/**
 * Prompt for the one argument a firmware command needs.
 *
 * The command is shown before it is sent, so the number or text being passed is visible
 * rather than implied, and an entry the catalog marks dangerous says so here. Nothing goes
 * out until Send is pressed.
 */
@Composable
fun ArgDialog(
    item: MenuItem,
    onDismiss: () -> Unit,
    onSend: (String) -> Unit,
) {
    val action = item.action as? MenuAction.Arg ?: return
    var value by rememberSaveable { mutableStateOf("") }
    val ready = value.isNotBlank()

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(item.title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(action.hint, style = MaterialTheme.typography.bodyMedium)
                OutlinedTextField(
                    value = value,
                    onValueChange = { value = it },
                    label = { Text("value") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        "${action.base} ${value.ifBlank { "…" }}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(10.dp),
                    )
                }
                if (action.example.isNotBlank()) {
                    Text(
                        "example: ${action.base} ${action.example}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MarauderTextDim,
                    )
                }
                if (item.dangerous) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Icon(Icons.Filled.Warning, contentDescription = null, tint = Danger)
                        Text("This transmits on the radio", style = MaterialTheme.typography.bodySmall, color = Danger)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onSend(value.trim()) }, enabled = ready) { Text("Send") }
        },
        dismissButton = {
            Column(horizontalAlignment = Alignment.End) {
                TextButton(onClick = onDismiss) { Text("Cancel") }
                if (action.example.isNotBlank()) {
                    TextButton(onClick = { value = action.example }) { Text("Use example") }
                }
            }
        },
    )
}
