package org.umbra.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import uniffi.umbra_native.LiveController

/**
 * Walking-skeleton entry point (TODO B.4 Phase 1). Hosts a single Compose
 * screen whose sole purpose is to prove the whole Kotlin -> UniFFI glue ->
 * libumbra_native.so -> real Rust core -> back call path works end to end,
 * before any real app functionality is built on top of it.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    SmokeTestScreen()
                }
            }
        }
    }
}

@Composable
fun SmokeTestScreen() {
    var status by remember { mutableStateOf("Rust core not reached yet") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(text = status)
        Button(onClick = {
            status = try {
                // Deliberately the simplest possible real FFI call: no
                // arguments, no return value, cannot fail on a fresh,
                // unlocked-nothing-yet controller. Exists purely to prove
                // the Kotlin -> JNI-via-UniFFI -> Rust call path works.
                val controller = LiveController.newFfi()
                controller.triggerPanicWipe()
                "Rust core reached ✓"
            } catch (t: Throwable) {
                "FFI call failed: ${t.message}"
            }
        }) {
            Text("Call into Rust core")
        }
    }
}
