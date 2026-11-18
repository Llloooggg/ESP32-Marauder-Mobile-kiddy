package com.marauder.mobile.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.marauder.mobile.ui.theme.Danger
import com.marauder.mobile.ui.theme.MarauderCyan
import com.marauder.mobile.ui.theme.MarauderTextDim
import com.marauder.mobile.vm.ConsoleEntry
import com.marauder.mobile.vm.LineKind

/**
 * Scrolling firmware console output (auto-follows the tail). Used by the mission
 * screen and any other view that wants to show what the board is saying.
 */
@Composable
fun LogPane(entries: List<ConsoleEntry>, modifier: Modifier = Modifier, emptyHint: String = "Waiting for the device to respond.") {
    if (entries.isEmpty()) {
        Box(modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            EmptyState(
                icon = Icons.Filled.Terminal,
                title = "Running…",
                subtitle = emptyHint,
            )
        }
        return
    }
    val listState = rememberLazyListState()
    LaunchedEffect(entries.size) {
        if (entries.isNotEmpty()) listState.animateScrollToItem(entries.lastIndex)
    }
    LazyColumn(
        state = listState,
        modifier = modifier.fillMaxWidth().padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(1.dp),
    ) {
        items(entries, key = { it.id }) { entry ->
            val color: Color = when (entry.kind) {
                LineKind.INPUT -> MarauderCyan
                LineKind.OUTPUT -> MaterialTheme.colorScheme.onSurface
                LineKind.SYSTEM -> MarauderTextDim
                LineKind.ERROR -> Danger
            }
            Text(
                text = entry.text,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = color,
            )
        }
    }
}
