package org.umbra.android.ui

import androidx.compose.runtime.Composable

@Composable
fun SettingsScreen(onBack: () -> Unit) {
    PScreen(title = "Appearance", onBack = onBack) {
        PNote("Appearance settings are coming in the next step.")
    }
}
