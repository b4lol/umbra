package org.umbra.android

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import uniffi.umbra_native.privacyBriefTor

/**
 * Chat with one paired peer. Outbound goes to [peer]; inbound is UNATTRIBUTED (one shared feed,
 * exactly like the terminal client) because the transport carries no reliable sender identity.
 */
@Composable
fun ChatScreen(peer: String, onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val status = SessionModel.status
    val lines = SessionModel.lines
    val listState = rememberLazyListState()
    val ready = status is SessionStatus.Ready

    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) listState.animateScrollToItem(lines.size - 1)
    }

    Column(modifier = Modifier.fillMaxSize().padding(24.dp)) {
        Row(modifier = Modifier.fillMaxWidth()) {
            OutlinedButton(onClick = onBack) { Text("Back") }
            Text(peer, style = MaterialTheme.typography.headlineSmall, modifier = Modifier.padding(start = 16.dp))
        }
        LazyColumn(state = listState, modifier = Modifier.weight(1f).padding(top = 12.dp)) {
            items(lines) { line -> Text(line, modifier = Modifier.padding(vertical = 4.dp)) }
        }
        Text(
            "Incoming messages are not attributed to a peer.",
            style = MaterialTheme.typography.bodySmall,
        )
        if (!ready) {
            Text(
                when (status) {
                    is SessionStatus.Failed -> "Tor failed: ${status.message}"
                    else -> "Waiting for Tor to connect…"
                },
                color = MaterialTheme.colorScheme.error,
            )
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            label = { Text("Message") },
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
        Button(
            enabled = ready && text.isNotBlank(),
            modifier = Modifier.padding(top = 8.dp),
            onClick = {
                val message = text
                error = null
                scope.launch {
                    ffi { AppCore.controller.sendMessage(peer, message) }
                        .onSuccess {
                            SessionModel.addLocal("→ $peer: $message")
                            text = ""
                        }
                        .onFailure { error = it.userMessage("Send failed") }
                }
            },
        ) { Text("Send") }
        Text(
            privacyBriefTor(),
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 8.dp),
        )
    }
}
