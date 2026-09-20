package org.umbra.android

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

/** Process-scoped truth about the session; the Activity-local `route` is NOT allowed to be the source. */
object AppState {
    /** True from a successful create/unlock until Lock (mirrors the identity resident in Rust). */
    var unlocked by mutableStateOf(false)

    private var visibleActivities by mutableIntStateOf(0)
    val uiVisible: Boolean get() = visibleActivities > 0

    fun uiShown() {
        visibleActivities += 1
    }

    fun uiHidden() {
        visibleActivities = (visibleActivities - 1).coerceAtLeast(0)
    }
}

/** The opt-in switch, persisted app-privately. */
object BackgroundPrefs {
    private const val FILE = "umbra_prefs"
    private const val KEY = "background_receiving"

    fun enabled(context: Context): Boolean =
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).getBoolean(KEY, false)

    fun set(context: Context, value: Boolean) =
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().putBoolean(KEY, value).apply()
}

/** Bounds how long an unlocked identity may stay resident with no UI on screen. */
object BackgroundPolicy {
    const val MAX_BACKGROUND_MS: Long = 12L * 60 * 60 * 1000

    fun shouldAutoLock(hiddenSinceMs: Long?, nowMs: Long, maxMs: Long = MAX_BACKGROUND_MS): Boolean =
        hiddenSinceMs != null && nowMs >= hiddenSinceMs && nowMs - hiddenSinceMs >= maxMs
}
