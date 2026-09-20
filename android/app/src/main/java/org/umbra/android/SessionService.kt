package org.umbra.android

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat

/**
 * Exists only to keep the process alive and visible to the user while the Tor session runs.
 * The session itself is process-scoped (AppCore); this class holds no session state.
 * START_NOT_STICKY: after an OS kill the identity is gone and needs the passphrase, so a
 * silent restart would be a lie.
 */
class SessionService : Service() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_LOCK) {
            AppCore.lock(this)
            stopSelf()
            return START_NOT_STICKY
        }
        val type = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
        ServiceCompat.startForeground(this, Notifications.ID_STATUS, Notifications.status(this), type)
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        const val ACTION_LOCK = "org.umbra.android.action.LOCK"

        /** Call only from the visible Activity (Android 12+ forbids starting one from the background). */
        fun start(context: Context) =
            ContextCompat.startForegroundService(context, Intent(context, SessionService::class.java))

        fun stop(context: Context) {
            context.stopService(Intent(context, SessionService::class.java))
        }
    }
}
