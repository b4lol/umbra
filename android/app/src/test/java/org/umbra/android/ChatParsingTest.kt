package org.umbra.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ChatParsingTest {
    @Test
    fun inbound() {
        assertEquals(FeedItem("00:03:07", FeedKind.IN, "hi there"), parseFeedLine("00:03:07 ← hi there"))
    }

    @Test
    fun outboundStripsThePeerName() {
        assertEquals(FeedItem("10:00:00", FeedKind.OUT, "a: b"), parseFeedLine("10:00:00 → alice: a: b"))
    }

    @Test
    fun outboundWithoutSeparatorKeepsTheRest() {
        assertEquals(FeedKind.OUT, parseFeedLine("10:00:00 → weird").kind)
    }

    @Test
    fun errorsAndSystem() {
        assertEquals(FeedKind.ERROR, parseFeedLine("10:00:00 ✗ send to bob failed: x").kind)
        assertEquals(FeedKind.ERROR, parseFeedLine("10:00:00 ! boom").kind)
        assertEquals(FeedKind.SYSTEM, parseFeedLine("10:00:00 ✓ accepted by Tor for bob (5 bytes; not a delivery receipt)").kind)
    }

    @Test
    fun missingTimePrefixStillParses() {
        val item = parseFeedLine("← bare")
        assertNull(item.time)
        assertEquals(FeedKind.IN, item.kind)
        assertEquals("bare", item.body)
    }

    @Test
    fun multilineBodySurvives() {
        assertEquals("a\nb", parseFeedLine("10:00:00 ← a\nb").body)
    }

    @Test
    fun sasGrouping() {
        assertEquals("633 386", groupSas("633386"))
        assertEquals("633 386", groupSas("633 386"))
        assertEquals("ab-cd", groupSas("ab-cd"))
    }
}
