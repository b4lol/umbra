package org.umbra.android

import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.umbra.android.ui.CanvasText
import org.umbra.android.ui.MessageStyle
import org.umbra.android.ui.PButton
import org.umbra.android.ui.PField
import org.umbra.android.ui.PNote
import org.umbra.android.ui.PScreen
import org.umbra.android.ui.PStyle
import org.umbra.android.ui.PText
import org.umbra.android.ui.Penumbra
import org.umbra.android.ui.shapeFor
import uniffi.umbra_native.privacyBriefTor

private const val REVEAL_MILLIS = 5_000L
private const val MASK = "••••••••"

/**
 * Chat with one paired peer. Outbound goes to [peer]; inbound is UNATTRIBUTED (one shared feed,
 * exactly like the terminal client) because the transport carries no reliable sender identity.
 * Every feed line is drawn on a Canvas (ANDROID.md §4).
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
    var revealed by remember { mutableStateOf<Int?>(null) }

    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) listState.scrollToItem(lines.size - 1)
    }
    LaunchedEffect(revealed) {
        if (revealed != null) {
            delay(REVEAL_MILLIS)
            revealed = null
        }
    }

    PScreen(
        title = peer,
        onBack = onBack,
        scroll = false,
        bottomBar = {
            Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                PText("Incoming messages are not attributed to a peer.", style = PStyle.Caption)
                if (!ready) {
                    PText(
                        when (status) {
                            is SessionStatus.Failed -> "Tor failed: ${status.message}"
                            else -> "Waiting for Tor to connect…"
                        },
                        style = PStyle.Caption,
                        color = Penumbra.colors.err,
                    )
                }
                error?.let { PText(it, style = PStyle.Caption, color = Penumbra.colors.err) }
                PField(text, { text = it }, "Message", singleLine = false, maxLines = 4)
                PButton("Send", enabled = ready && text.isNotBlank()) {
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
                }
                PNote(privacyBriefTor())
            }
        },
    ) {
        LazyColumn(state = listState, modifier = Modifier.weight(1f).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            itemsIndexed(lines) { index, line ->
                FeedRow(parseFeedLine(line), revealed = revealed == index, onReveal = { revealed = index })
            }
        }
    }
}

@Composable
private fun FeedRow(item: FeedItem, revealed: Boolean, onReveal: () -> Unit) {
    val colors = Penumbra.colors
    val config = Penumbra.metrics.config
    val font = Penumbra.metrics.font
    val isMessage = item.kind == FeedKind.IN || item.kind == FeedKind.OUT
    val masked = config.tapToReveal && isMessage && !revealed
    val shown = if (masked) MASK else item.body
    val time = if (config.showTimes) item.time else null
    val tapModifier = if (masked) Modifier.pointerInput(Unit) { detectTapGestures { onReveal() } } else Modifier

    when {
        config.messages == MessageStyle.TERMINAL -> {
            val marker = when (item.kind) { FeedKind.IN -> "←"; FeedKind.OUT -> "→"; FeedKind.ERROR -> "!"; FeedKind.SYSTEM -> "·" }
            CanvasText(
                "${time?.plus(" ") ?: ""}$marker $shown",
                TextStyle(fontSize = 13.sp, fontFamily = FontFamily.Monospace),
                when (item.kind) { FeedKind.IN -> colors.ink; FeedKind.OUT -> colors.acc; FeedKind.ERROR -> colors.err; FeedKind.SYSTEM -> colors.mut },
                tapModifier.fillMaxWidth(),
            )
        }
        !isMessage -> Column(Modifier.fillMaxWidth().padding(vertical = 2.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            CanvasText(
                shown,
                TextStyle(fontSize = 12.5.sp, fontFamily = font),
                if (item.kind == FeedKind.ERROR) colors.err else colors.mut,
            )
            if (time != null) PText(time, style = PStyle.Caption)
        }
        config.messages == MessageStyle.FLAT -> Column(
            Modifier.fillMaxWidth().padding(vertical = 2.dp),
            horizontalAlignment = if (item.kind == FeedKind.IN) Alignment.Start else Alignment.End,
        ) {
            CanvasText(shown, TextStyle(fontSize = 15.sp, lineHeight = 21.sp, fontFamily = font), if (item.kind == FeedKind.IN) colors.ink else colors.acc, tapModifier)
            if (time != null) PText(time, style = PStyle.Caption)
        }
        else -> {
            val incoming = item.kind == FeedKind.IN
            Box(Modifier.fillMaxWidth(), contentAlignment = if (incoming) Alignment.CenterStart else Alignment.CenterEnd) {
                Column(
                    Modifier
                        .padding(start = if (incoming) 0.dp else 48.dp, end = if (incoming) 48.dp else 0.dp)
                        .clip(shapeFor(config.corner, config.radiusDp, .8f))
                        .background(if (incoming) colors.card else colors.acc)
                        .padding(horizontal = 14.dp, vertical = 10.dp),
                ) {
                    CanvasText(shown, TextStyle(fontSize = 15.sp, lineHeight = 21.sp, fontFamily = font), if (incoming) colors.ink else colors.accInk, tapModifier)
                    if (time != null) PText(time, style = PStyle.Caption, color = if (incoming) colors.mut else colors.accInk)
                }
            }
        }
    }
}
