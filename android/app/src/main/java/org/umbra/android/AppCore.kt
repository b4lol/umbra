package org.umbra.android

import android.content.Context
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.umbra_native.FfiControllerException
import uniffi.umbra_native.LiveController

/** Process-scoped Rust core. The unlocked session lives in Rust RAM behind this one controller. */
object AppCore {
    val controller: LiveController by lazy { LiveController.newFfi() }

    /** Set once by [UmbraApplication]; process-scoped, so holding it is not a leak. */
    lateinit var appContext: Context

    /** Placeholder until the single teardown path lands (this task only proves the service). */
    fun lock(context: Context) {
        SessionService.stop(context)
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
