package org.umbra.android

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import org.umbra.android.ui.PButton
import org.umbra.android.ui.PCard
import org.umbra.android.ui.PGroup
import org.umbra.android.ui.PGroupLabel
import org.umbra.android.ui.PKind
import org.umbra.android.ui.PNote
import org.umbra.android.ui.PRow
import org.umbra.android.ui.PScreen
import org.umbra.android.ui.PStyle
import org.umbra.android.ui.PSwitch
import org.umbra.android.ui.PText
import org.umbra.android.ui.Penumbra
import uniffi.umbra_native.privacyBriefTor

@Composable
fun HomeScreen(
    peersVersion: Int,
    onPair: () -> Unit,
    onOpenChat: (String) -> Unit,
    onSettings: () -> Unit,
    onLock: () -> Unit,
) {
    val context = LocalContext.current
    var background by remember { mutableStateOf(BackgroundPrefs.enabled(context)) }
    var notificationsDenied by remember { mutableStateOf(false) }
    val notificationPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        notificationsDenied = !granted
    }
    var peers by remember { mutableStateOf<List<String>?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(peersVersion) {
        ffi { AppCore.controller.listPeers() }
            .onSuccess { peers = it; error = null }
            .onFailure { error = it.userMessage("Could not list peers") }
    }

    PScreen(title = "Peers") {
        when (val status = SessionModel.status) {
            is SessionStatus.Idle -> {}
            is SessionStatus.Bootstrapping ->
                PCard { PText("Connecting to Tor… this can take a few minutes.", style = PStyle.Caption) }
            is SessionStatus.Ready -> PCard {
                PText("Tor ready. Your address:", style = PStyle.Caption)
                PText(status.address, Modifier.padding(vertical = 6.dp), style = PStyle.Caption, color = Penumbra.colors.ink, mono = true)
                PButton("Share my address", kind = PKind.Tonal) {
                    val send = Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_TEXT, status.address)
                    }
                    context.startActivity(Intent.createChooser(send, "Share my onion address"))
                }
            }
            is SessionStatus.Failed ->
                PCard { PText("Tor failed: ${status.message}", style = PStyle.Caption, color = Penumbra.colors.err) }
        }

        PGroupLabel("BACKGROUND")
        PGroup {
            row {
                PRow(
                    "Keep receiving in the background",
                    summary = "While on, Umbra stays unlocked in memory (it locks itself after 12 h off-screen). " +
                        "If Android or your phone's battery manager stops Umbra, you must unlock again.",
                    trailing = {
                        PSwitch(background, { on ->
                            background = on
                            BackgroundPrefs.set(context, on)
                            if (on) {
                                if (android.os.Build.VERSION.SDK_INT >= 33) {
                                    notificationPermission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                                }
                                SessionService.start(context)
                            } else {
                                SessionService.stop(context)
                            }
                        })
                    },
                )
            }
        }
        if (notificationsDenied) {
            PText(
                "Notifications are blocked: Umbra keeps running but will not show its status or new-message alerts.",
                Modifier.padding(top = 8.dp, start = 6.dp),
                style = PStyle.Caption,
                color = Penumbra.colors.err,
            )
        }
        error?.let { PText(it, Modifier.padding(top = 8.dp, start = 6.dp), style = PStyle.Caption, color = Penumbra.colors.err) }

        PGroupLabel("PEERS")
        val list = peers
        if (list == null) {
            PCard { PText("Loading…", style = PStyle.Caption) }
        } else if (list.isEmpty()) {
            PCard { PText("No peers paired yet.", style = PStyle.Caption) }
        } else {
            PGroup {
                list.forEach { name -> row { PRow(name, onClick = { onOpenChat(name) }) } }
            }
        }

        Spacer(Modifier.height(16.dp))
        PButton("Pair a peer", onClick = onPair)
        Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PButton("Appearance", kind = PKind.Tonal, modifier = Modifier.weight(1f), onClick = onSettings)
            PButton("Lock", kind = PKind.Ghost, modifier = Modifier.weight(1f), onClick = onLock)
        }
        Spacer(Modifier.height(12.dp))
        PNote(privacyBriefTor())
    }
}
