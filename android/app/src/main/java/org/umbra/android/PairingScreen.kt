package org.umbra.android

import android.content.Intent
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.launch
import androidx.compose.foundation.layout.padding
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.umbra.android.ui.*

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

    PScreen(title = "Pair a peer", onBack = { onDone(false) }) {
        PGroupLabel("1. SEND THEM YOUR PAYLOAD")
        PButton("Share my payload", kind = PKind.Tonal, enabled = !busy) {
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
        }

        PGroupLabel("2. PASTE THEIRS")
        PField(name, { name = it; sas = null }, "Peer name", enabled = !busy && sas == null)
        PField(peerPayload, { peerPayload = it.trim(); sas = null }, "Peer payload", Modifier.padding(top = 8.dp), enabled = !busy && sas == null, singleLine = false, minLines = 3, maxLines = 6)
        PField(onion, { onion = it.trim() }, "Peer .onion address (optional)", Modifier.padding(top = 8.dp), enabled = !busy && sas == null)
        PButton(
            "Check payload",
            Modifier.padding(top = 8.dp),
            enabled = !busy && sas == null && NAME_RE.matches(name) && peerPayload.isNotEmpty(),
        ) {
            busy = true
            error = null
            scope.launch {
                val result = ffi { AppCore.controller.importPeerPayload(peerPayload) }
                busy = false
                result.onSuccess { sas = it }.onFailure { error = it.userMessage("Invalid payload") }
            }
        }

        sas?.let { code ->
            PGroupLabel("3. COMPARE THIS CODE WITH YOUR PEER")
            PCard {
                CanvasText(groupSas(code), TextStyle(fontSize = 44.sp, fontFamily = FontFamily.Monospace), Penumbra.colors.ink)
            }
            PText("Read it out to them over a channel you trust (in person or a call). Only save if it matches.", Modifier.padding(vertical = 8.dp, horizontal = 6.dp), style = PStyle.Caption)
            PButton("Codes match — save peer", enabled = !busy) {
                busy = true
                scope.launch {
                    val result = ffi { AppCore.controller.confirmPeer(name, peerPayload, onion.ifEmpty { null }) }
                    busy = false
                    result.onSuccess { onDone(true) }.onFailure { error = it.userMessage("Could not save peer") }
                }
            }
        }

        error?.let { PText(it, Modifier.padding(top = 8.dp), style = PStyle.Caption, color = Penumbra.colors.err) }
        PButton("Cancel", Modifier.padding(top = 16.dp), kind = PKind.Ghost) { onDone(false) }
    }
}
