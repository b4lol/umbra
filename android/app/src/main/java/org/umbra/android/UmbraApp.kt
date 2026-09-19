package org.umbra.android

import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue

sealed interface Route {
    data object Gate : Route
    data object Home : Route
    data object Pairing : Route
    data class Chat(val peer: String) : Route
}

@Composable
fun UmbraApp() {
    var route by remember { mutableStateOf<Route>(Route.Gate) }
    val scope = rememberCoroutineScope()
    // Bumped after a peer is saved so HomeScreen re-reads the list.
    var peersVersion by remember { mutableStateOf(0) }

    BackHandler(enabled = route == Route.Pairing || route is Route.Chat) { route = Route.Home }

    when (route) {
        Route.Gate -> GateScreen(onUnlocked = {
            SessionModel.start(scope)
            route = Route.Home
        })
        Route.Home -> HomeScreen(
            peersVersion = peersVersion,
            onPair = { route = Route.Pairing },
            onOpenChat = { peer -> route = Route.Chat(peer) },
            onLock = {
                SessionModel.stop()
                AppCore.controller.triggerPanicWipe()
                route = Route.Gate
            },
        )
        is Route.Chat -> ChatScreen(peer = (route as Route.Chat).peer, onBack = { route = Route.Home })
        Route.Pairing -> PairingScreen(
            onDone = { saved ->
                if (saved) peersVersion++
                route = Route.Home
            },
        )
    }
}
