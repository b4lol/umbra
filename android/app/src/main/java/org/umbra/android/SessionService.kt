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
        // A killed foreground service can be restarted by the OS in a FRESH process where no identity
        // is unlocked: showing "connected" there would be a lie. Only a live, unlocked session may
        // hold the foreground notification (found on the phone after HyperOS's OneKeyClean killed us).
        if (!AppState.unlocked) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (BuildConfig.ALLOW_INSECURE_WINDOW && java.io.File(filesDir, "e2e_wakelock").exists()) holdWakeLock()
        val type = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
        ServiceCompat.startForeground(this, Notifications.ID_STATUS, Notifications.status(this), type)
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // Experiment mechanism (Phase 3 Task 4): a partial wake lock, enabled ONLY in E2E builds by
    // creating files/e2e_wakelock, so wake-lock vs no-wake-lock can be compared without reinstalling.
    private var wakeLock: android.os.PowerManager.WakeLock? = null

    private fun holdWakeLock() {
        if (wakeLock?.isHeld == true) return
        val power = getSystemService(android.os.PowerManager::class.java)
        wakeLock = power.newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK, "umbra:session").apply { acquire() }
    }

    override fun onDestroy() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
        super.onDestroy()
    }

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
