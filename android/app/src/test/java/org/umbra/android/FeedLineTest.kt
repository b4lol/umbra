package org.umbra.android

import java.time.ZoneOffset
import org.junit.Assert.assertEquals
import org.junit.Test

class FeedLineTest {
    @Test
    fun prefixesTheLocalTimeWithSeconds() {
        // 2026-09-20T00:03:07Z
        assertEquals("00:03:07 ← hi", formatFeedLine(1_789_862_587_000, ZoneOffset.UTC, "← hi"))
    }

    @Test
    fun honoursTheZone() {
        assertEquals("03:03:07 ← hi", formatFeedLine(1_789_862_587_000, ZoneOffset.ofHours(3), "← hi"))
    }
}
