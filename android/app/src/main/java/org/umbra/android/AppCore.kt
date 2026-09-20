package org.umbra.android

import android.content.Context
import android.os.SystemClock
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.umbra_native.FfiControllerException
import uniffi.umbra_native.LiveController

/** Process-scoped Rust core. The unlocked session lives in Rust RAM behind this one controller. */
object AppCore {
    val controller: LiveController by lazy { LiveController.newFfi() }

    /** Set once by [UmbraApplication]; process-scoped, so holding it is not a leak. */
    lateinit var appContext: Context

    private var autoLockJob: Job? = null
    private val mainScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    /** The ONE teardown path: Lock button, notification action, auto-lock. Main thread. */
    fun lock(context: Context) {
        autoLockJob?.cancel()
        autoLockJob = null
        SessionModel.stop()
        controller.triggerPanicWipe()
        AppState.unlocked = false
        Notifications.clearMessageAlert(context)
        SessionService.stop(context)
    }

    /** Called when the last Activity leaves the screen while unlocked: arm the bounded background window. */
    fun onUiHidden() {
        if (!AppState.unlocked || !BackgroundPrefs.enabled(appContext)) return
        val hiddenSince = SystemClock.elapsedRealtime()
        autoLockJob?.cancel()
        autoLockJob = mainScope.launch {
            delay(BackgroundPolicy.MAX_BACKGROUND_MS)
            if (BackgroundPolicy.shouldAutoLock(hiddenSince, SystemClock.elapsedRealtime()) && !AppState.uiVisible) {
                lock(appContext)
            }
        }
    }

    fun onUiShown() {
        autoLockJob?.cancel()
        autoLockJob = null
    }

    /** App-private keystore location; the peers directory is derived by Rust as a sibling `peers/`. */
    fun keystoreFile(context: Context): File = File(context.filesDir, "keystore.bin")
}

/**
 * Runs a blocking Rust call off the main thread (Argon2id at 256 MiB takes seconds) and
 * captures any failure, including UniFFI's FfiControllerException, as a Result.
 */
suspend fun <T> ffi(block: () -> T): Result<T> =
    withContext(Dispatchers.Default) { runCatching(block) }

/** The real message from a failed FFI call (UniFFI's own `message` is a debug string like `v1=...`). */
fun Throwable.userMessage(fallback: String): String =
    (this as? FfiControllerException.Failed)?.v1 ?: message ?: fallback

/**
 * Test-only prefill for on-device UI automation. Populated by MainActivity ONLY when
 * BuildConfig.ALLOW_INSECURE_WINDOW is true (a debug build made with -PumbraInsecureE2E);
 * always null in normal and release builds.
 */
object E2eHooks {
    var peerPayload: String? = null
}
