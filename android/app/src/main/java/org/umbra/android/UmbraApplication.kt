package org.umbra.android

import android.app.Application

class UmbraApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        AppCore.appContext = applicationContext
        Notifications.createChannels(this)
    }
}
