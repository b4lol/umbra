package org.umbra.android

import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalContext
import androidx.compose.runtime.setValue

sealed interface Route {
    data object Gate : Route
    data object Home : Route
    data object Pairing : Route
    data class Chat(val peer: String) : Route
}

@Composable
fun UmbraApp() {
    val context = LocalContext.current
    // The identity's state lives in the process (AppState), not in this Activity: a recreated
    // Activity (rotation, system reclaim) must come back to Home while the identity is unlocked.
    var route by remember { mutableStateOf<Route>(if (AppState.unlocked) Route.Home else Route.Gate) }
    LaunchedEffect(AppState.unlocked) { if (!AppState.unlocked) route = Route.Gate }
    // Bumped after a peer is saved so HomeScreen re-reads the list.
    var peersVersion by remember { mutableStateOf(0) }

    BackHandler(enabled = route == Route.Pairing || route is Route.Chat) { route = Route.Home }

    when (route) {
        Route.Gate -> GateScreen(onUnlocked = {
            AppState.unlocked = true
            SessionModel.start()
            if (BackgroundPrefs.enabled(context)) SessionService.start(context)
            route = Route.Home
        })
        Route.Home -> HomeScreen(
            peersVersion = peersVersion,
            onPair = { route = Route.Pairing },
            onOpenChat = { peer -> route = Route.Chat(peer) },
            onLock = {
                AppCore.lock(context)
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
