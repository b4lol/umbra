package org.umbra.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

/** Generic, lock-screen-secret notifications only: never message text, never a peer name. */
object Notifications {
    private const val CHANNEL_STATUS = "session_status"
    private const val CHANNEL_MESSAGE = "new_message"
    const val ID_STATUS = 1
    private const val ID_MESSAGE = 2

    fun createChannels(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_STATUS, "Background connection", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Shown while Umbra keeps its Tor connection open in the background"
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_SECRET
            },
        )
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_MESSAGE, "New messages", NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = "A generic alert when a message arrives; never shows its content"
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_SECRET
            },
        )
    }

    private fun openApp(context: Context): PendingIntent = PendingIntent.getActivity(
        context,
        0,
        Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    /** The persistent foreground-service notification, with a Lock action. */
    fun status(context: Context): Notification {
        val lock = PendingIntent.getService(
            context,
            1,
            Intent(context, SessionService::class.java).setAction(SessionService.ACTION_LOCK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(context, CHANNEL_STATUS)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle("Umbra is connected")
            .setContentText("Receiving in the background. Lock to stop.")
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(openApp(context))
            .addAction(android.R.drawable.ic_lock_lock, "Lock", lock)
            .build()
    }

    /** A content-free "something arrived" alert; a no-op when notifications are blocked. */
    fun newMessage(context: Context) {
        if (!NotificationManagerCompat.from(context).areNotificationsEnabled()) return
        val notification = NotificationCompat.Builder(context, CHANNEL_MESSAGE)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle("Umbra")
            .setContentText("New message")
            .setAutoCancel(true)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(openApp(context))
            .build()
        @Suppress("MissingPermission") // guarded by areNotificationsEnabled() above
        NotificationManagerCompat.from(context).notify(ID_MESSAGE, notification)
    }

    fun clearMessageAlert(context: Context) = NotificationManagerCompat.from(context).cancel(ID_MESSAGE)
}
