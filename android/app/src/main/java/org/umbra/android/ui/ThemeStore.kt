package org.umbra.android.ui

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

/** Theme persistence: app-private SharedPreferences; nothing security-relevant ever lives here. */
object ThemeStore {
    private const val FILE = "umbra_theme"
    private var appContext: Context? = null

    var config by mutableStateOf(ThemeConfig.DEFAULT)
        private set

    fun init(context: Context) {
        appContext = context.applicationContext
        val prefs = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        config = ThemeConfig.decode(prefs.all.mapValues { (_, v) -> v as? String })
    }

    fun update(transform: (ThemeConfig) -> ThemeConfig) {
        // Re-clamp through the untrusted-input path so no caller can store an out-of-range value.
        val next = ThemeConfig.decode(transform(config).encode())
        config = next
        appContext?.getSharedPreferences(FILE, Context.MODE_PRIVATE)?.edit()?.apply {
            next.encode().forEach { (k, v) -> putString(k, v) }
        }?.apply()
    }

    fun reset() = update { ThemeConfig.DEFAULT }
}
