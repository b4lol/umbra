package org.umbra.android

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.Modifier
import org.umbra.android.ui.Penumbra
import org.umbra.android.ui.PenumbraTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // TODO B.4: FLAG_SECURE on every window, set before any content exists.
        // Blocks screenshots/recents thumbnails; does NOT stop a rooted/instrumented
        // device (ADR-016 / Phase 3 anti-bypass work).
        // BuildConfig.ALLOW_INSECURE_WINDOW is true only in a debug build made with
        // -PumbraInsecureE2E (on-device UI automation); never in normal or release builds.
        if (BuildConfig.ALLOW_INSECURE_WINDOW) {
            E2eHooks.peerPayload = intent.getStringExtra("e2e_peer_payload")
        } else {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        setContent {
            PenumbraTheme {
                Box(Modifier.fillMaxSize().background(Penumbra.colors.bg)) { UmbraApp() }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        AppState.uiShown()
        AppCore.onUiShown()
        Notifications.clearMessageAlert(this)
    }

    override fun onStop() {
        super.onStop()
        AppState.uiHidden()
        if (!AppState.uiVisible) AppCore.onUiHidden()
    }
}
