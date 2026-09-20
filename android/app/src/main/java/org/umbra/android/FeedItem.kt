package org.umbra.android

enum class FeedKind { IN, OUT, SYSTEM, ERROR }

/** One parsed feed line. [body] is the display text without the direction marker and time prefix. */
data class FeedItem(val time: String?, val kind: FeedKind, val body: String)

private val TIME_PREFIX = Regex("^(\\d{2}:\\d{2}:\\d{2}) (.*)$", RegexOption.DOT_MATCHES_ALL)

/** Inverse of [formatFeedLine] plus the marker conventions used by [SessionModel]. */
fun parseFeedLine(line: String): FeedItem {
    val m = TIME_PREFIX.matchEntire(line)
    val time = m?.groupValues?.get(1)
    val rest = m?.groupValues?.get(2) ?: line
    return when {
        rest.startsWith("← ") -> FeedItem(time, FeedKind.IN, rest.removePrefix("← "))
        rest.startsWith("→ ") -> {
            val after = rest.removePrefix("→ ")
            val sep = after.indexOf(": ")
            FeedItem(time, FeedKind.OUT, if (sep >= 0) after.substring(sep + 2) else after)
        }
        rest.startsWith("✗ ") -> FeedItem(time, FeedKind.ERROR, rest.removePrefix("✗ "))
        rest.startsWith("! ") -> FeedItem(time, FeedKind.ERROR, rest.removePrefix("! "))
        rest.startsWith("✓ ") -> FeedItem(time, FeedKind.SYSTEM, rest.removePrefix("✓ "))
        else -> FeedItem(time, FeedKind.SYSTEM, rest)
    }
}

/** Groups a purely numeric SAS in threes ("633386" -> "633 386"); anything else is shown as given. */
fun groupSas(code: String): String {
    val compact = code.filterNot { it.isWhitespace() }
    return if (compact.isNotEmpty() && compact.all { it.isDigit() }) compact.chunked(3).joinToString(" ") else code
}
