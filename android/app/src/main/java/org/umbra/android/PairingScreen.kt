package org.umbra.android

import android.content.Intent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

/** Peer record names: the same charset Rust enforces (`[A-Za-z0-9_-]+`); Rust remains the authority. */
private val NAME_RE = Regex("^[A-Za-z0-9_-]+$")

/**
 * Two halves: (1) share OUR payload out through the Android share sheet (it is public
 * key material — safe to share; too large for one QR, ~8.7 KB base64url), (2) paste the
 * PEER's payload, compare the 6-digit SAS out of band, and only then save.
 * Nothing is persisted before the operator confirms the SAS. The peer needs OUR onion
 * address too — share it from the home screen once Tor is ready.
 */
@Composable
fun PairingScreen(onDone: (saved: Boolean) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var name by remember { mutableStateOf("") }
    var onion by remember { mutableStateOf("") }
    var peerPayload by remember { mutableStateOf(E2eHooks.peerPayload ?: "") }
    var sas by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
    ) {
        Text("Pair a peer", style = MaterialTheme.typography.headlineSmall)

        Text("1. Send them your payload", modifier = Modifier.padding(top = 16.dp))
        Button(
            enabled = !busy,
            onClick = {
                scope.launch {
                    ffi { AppCore.controller.pairingPayload() }
                        .onSuccess { payload ->
                            val send = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_TEXT, payload)
                            }
                            context.startActivity(Intent.createChooser(send, "Share pairing payload"))
                        }
                        .onFailure { error = it.userMessage("Could not build payload") }
                }
            },
        ) { Text("Share my payload") }

        Text("2. Paste theirs", modifier = Modifier.padding(top = 16.dp))
        OutlinedTextField(
            value = name,
            onValueChange = { name = it; sas = null },
            label = { Text("Peer name") },
            singleLine = true,
            enabled = !busy && sas == null,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = peerPayload,
            onValueChange = { peerPayload = it.trim(); sas = null },
            label = { Text("Peer payload") },
            enabled = !busy && sas == null,
            minLines = 3,
            maxLines = 6,
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
        OutlinedTextField(
            value = onion,
            onValueChange = { onion = it.trim() },
            label = { Text("Peer .onion address (optional)") },
            singleLine = true,
            enabled = !busy && sas == null,
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
        Button(
            enabled = !busy && sas == null && NAME_RE.matches(name) && peerPayload.isNotEmpty(),
            modifier = Modifier.padding(top = 8.dp),
            onClick = {
                busy = true
                error = null
                scope.launch {
                    val result = ffi { AppCore.controller.importPeerPayload(peerPayload) }
                    busy = false
                    result.onSuccess { sas = it }.onFailure { error = it.userMessage("Invalid payload") }
                }
            },
        ) { Text("Check payload") }

        sas?.let { code ->
            Text("3. Compare this code with your peer", modifier = Modifier.padding(top = 16.dp))
            Text(code, style = MaterialTheme.typography.displayMedium)
            Text("Read it out to them over a channel you trust (in person or a call). Only save if it matches.")
            Button(
                enabled = !busy,
                modifier = Modifier.padding(top = 8.dp),
                onClick = {
                    busy = true
                    scope.launch {
                        val result = ffi { AppCore.controller.confirmPeer(name, peerPayload, onion.ifEmpty { null }) }
                        busy = false
                        result.onSuccess { onDone(true) }.onFailure { error = it.userMessage("Could not save peer") }
                    }
                },
            ) { Text("Codes match — save peer") }
        }

        error?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp)) }
        OutlinedButton(onClick = { onDone(false) }, modifier = Modifier.padding(top = 16.dp)) { Text("Cancel") }
    }
}
