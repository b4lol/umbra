package org.umbra.android

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // TODO B.4: FLAG_SECURE on every window, set before any content exists.
        // Blocks screenshots/recents thumbnails; does NOT stop a rooted/instrumented
        // device (ADR-016 / Phase 3 anti-bypass work).
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) { UmbraApp() }
            }
        }
    }
}
