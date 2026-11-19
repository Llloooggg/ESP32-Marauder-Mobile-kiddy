package com.marauder.mobile.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Usb
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.marauder.mobile.ui.components.EmptyState

/**
 * Shown in place of a screen that asks the board something, while the link is down.
 *
 * It replaces an older behaviour that read as a fault: tapping a tab and being moved to another screen,
 * which then had no way back. Saying what is missing where the person already is keeps the navigation
 * intact and answers the question they actually asked.
 *
 * The wording stays to one line: this is a signpost, not an explanation.
 */
@Composable
internal fun NoBoardState(
    heading: String,
    connecting: Boolean,
    onBack: () -> Unit,
    onOpenConnect: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
            }
            Text(
                text = heading,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }

        Spacer(Modifier.height(32.dp))
        EmptyState(
            icon = Icons.Filled.Usb,
            title = if (connecting) "Opening the port…" else "No board connected",
            subtitle = if (connecting) "this screen needs the link" else "this screen asks the board something",
        )
        if (!connecting) {
            Spacer(Modifier.height(16.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
            ) {
                Button(onClick = onOpenConnect) { Text("Connect a board") }
            }
        }
    }
}
