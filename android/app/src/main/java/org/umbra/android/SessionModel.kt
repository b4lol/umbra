package org.umbra.android

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.umbra_native.SessionEvent

/** Fixed-size line log (matches the TUI's MAX_LOG_LINES bounded-memory rule). */
class BoundedLog(private val max: Int) {
    private val lines = ArrayDeque<String>()

    fun add(line: String) {
        if (lines.size == max) lines.removeFirst()
        lines.addLast(line)
    }

    fun snapshot(): List<String> = lines.toList()
}

sealed interface SessionStatus {
    data object Idle : SessionStatus
    data object Bootstrapping : SessionStatus
    data class Ready(val address: String) : SessionStatus
    data class Failed(val message: String) : SessionStatus
}

/** Feed bound, matching the TUI's MAX_LOG_LINES. */
private const val MAX_LOG_LINES = 400

/** Nickname of our onion service (Arti validates: letters/digits). Fixed: it names the persistent key. */
private const val ONION_NICKNAME = "umbraphone"

/**
 * Process-scoped view of the Tor session: status + a bounded message feed. Inbound text is
 * UNATTRIBUTED (the transport carries no reliable sender), so it lives in one shared feed.
 * "accepted" means Tor's stream took the frames — NOT that the peer received them.
 */
object SessionModel {
    var status by mutableStateOf<SessionStatus>(SessionStatus.Idle)
        private set
    var lines by mutableStateOf<List<String>>(emptyList())
        private set

    private var log = BoundedLog(MAX_LOG_LINES)
    private var job: Job? = null

    fun start(scope: CoroutineScope) {
        if (job != null) return
        status = SessionStatus.Bootstrapping
        job = scope.launch(Dispatchers.IO) {
            val started = runCatching { AppCore.controller.startSession(ONION_NICKNAME) }
            started.exceptionOrNull()?.let {
                post { status = SessionStatus.Failed(it.userMessage("Could not start Tor")) }
                return@launch
            }
            while (isActive) {
                val event = runCatching { AppCore.controller.nextEvent(500UL) }.getOrNull() ?: continue
                post { apply(event) }
            }
        }
    }

    /** Stops polling and the Rust session; also clears the feed (it holds plaintext). */
    fun stop() {
        job?.cancel()
        job = null
        runCatching { AppCore.controller.stopSession() }
        status = SessionStatus.Idle
        log = BoundedLog(MAX_LOG_LINES)
        lines = emptyList()
    }

    fun addLocal(line: String) = add(line)

    private suspend fun post(block: () -> Unit) = withContext(Dispatchers.Main) { block() }

    private fun add(line: String) {
        log.add(line)
        lines = log.snapshot()
    }

    private fun apply(event: SessionEvent) {
        when (event) {
            is SessionEvent.Bootstrapping -> status = SessionStatus.Bootstrapping
            is SessionEvent.Ready -> status = SessionStatus.Ready(event.address)
            is SessionEvent.Inbound -> add("← ${event.text}")
            is SessionEvent.Sent ->
                add("✓ accepted by Tor for ${event.peer} (${event.bytes} bytes; not a delivery receipt)")
            is SessionEvent.SendError -> add("✗ send to ${event.peer} failed: ${event.message}")
            is SessionEvent.SessionError -> add("! ${event.message}")
            is SessionEvent.Fatal -> status = SessionStatus.Failed(event.message)
        }
    }
}
