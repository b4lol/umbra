package org.umbra.android

import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue

sealed interface Route {
    data object Gate : Route
    data object Home : Route
    data object Pairing : Route
}

@Composable
fun UmbraApp() {
    var route by remember { mutableStateOf<Route>(Route.Gate) }
    // Bumped after a peer is saved so HomeScreen re-reads the list.
    var peersVersion by remember { mutableStateOf(0) }

    BackHandler(enabled = route == Route.Pairing) { route = Route.Home }

    when (route) {
        Route.Gate -> GateScreen(onUnlocked = { route = Route.Home })
        Route.Home -> HomeScreen(
            peersVersion = peersVersion,
            onPair = { route = Route.Pairing },
            onLock = {
                AppCore.controller.triggerPanicWipe()
                route = Route.Gate
            },
        )
        Route.Pairing -> PairingScreen(
            onDone = { saved ->
                if (saved) peersVersion++
                route = Route.Home
            },
        )
    }
}
