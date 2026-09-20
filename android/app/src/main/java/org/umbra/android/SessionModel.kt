package org.umbra.android

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
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

private val FEED_TIME = java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss")

/** Local receive/send time prefix for one feed line (also the measuring instrument for background tests). */
fun formatFeedLine(epochMillis: Long, zone: java.time.ZoneId, text: String): String =
    "${java.time.Instant.ofEpochMilli(epochMillis).atZone(zone).format(FEED_TIME)} $text"

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

    /** Owned by the process, NOT by an Activity: a recreated Activity must not stop the polling. */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    fun start() {
        if (job?.isActive == true) return
        status = SessionStatus.Bootstrapping
        job = scope.launch {
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
        log.add(formatFeedLine(System.currentTimeMillis(), java.time.ZoneId.systemDefault(), line))
        lines = log.snapshot()
    }

    private fun apply(event: SessionEvent) {
        // On-device test instrument for E2E builds only: event KIND and length, never content,
        // so background receipt can be measured while the screen is locked.
        if (BuildConfig.ALLOW_INSECURE_WINDOW) {
            val detail = when (event) {
                is SessionEvent.Inbound -> " chars=${event.text.length}"
                is SessionEvent.Sent -> " bytes=${event.bytes}"
                is SessionEvent.SendError -> " error"
                is SessionEvent.SessionError -> " error"
                is SessionEvent.Fatal -> " fatal"
                else -> ""
            }
            android.util.Log.i("umbra-e2e", "event=${event::class.simpleName}$detail")
        }
        when (event) {
            is SessionEvent.Bootstrapping -> status = SessionStatus.Bootstrapping
            is SessionEvent.Ready -> status = SessionStatus.Ready(event.address)
            is SessionEvent.Inbound -> {
                add("← ${event.text}")
                // Content-free alert only when no UI is on screen; never message text.
                if (!AppState.uiVisible) Notifications.newMessage(AppCore.appContext)
            }
            is SessionEvent.Sent ->
                add("✓ accepted by Tor for ${event.peer} (${event.bytes} bytes; not a delivery receipt)")
            is SessionEvent.SendError -> add("✗ send to ${event.peer} failed: ${event.message}")
            is SessionEvent.SessionError -> add("! ${event.message}")
            is SessionEvent.Fatal -> status = SessionStatus.Failed(event.message)
        }
    }
}
