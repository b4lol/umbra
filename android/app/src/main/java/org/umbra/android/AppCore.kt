package org.umbra.android

import android.content.Context
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.umbra_native.LiveController

/** Process-scoped Rust core. The unlocked session lives in Rust RAM behind this one controller. */
object AppCore {
    val controller: LiveController by lazy { LiveController.newFfi() }

    /** App-private keystore location; the peers directory is derived by Rust as a sibling `peers/`. */
    fun keystoreFile(context: Context): File = File(context.filesDir, "keystore.bin")
}

/**
 * Runs a blocking Rust call off the main thread (Argon2id at 256 MiB takes seconds) and
 * captures any failure, including UniFFI's FfiControllerException, as a Result.
 */
suspend fun <T> ffi(block: () -> T): Result<T> =
    withContext(Dispatchers.Default) { runCatching(block) }
