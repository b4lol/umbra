package org.umbra.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BackgroundPolicyTest {
    private val max = 1_000L

    @Test fun neverLocksWhileTheUiIsVisible() = assertFalse(BackgroundPolicy.shouldAutoLock(null, 5_000, max))

    @Test fun doesNotLockBeforeTheLimit() = assertFalse(BackgroundPolicy.shouldAutoLock(0, 999, max))

    @Test fun locksExactlyAtTheLimit() = assertTrue(BackgroundPolicy.shouldAutoLock(0, 1_000, max))

    @Test fun locksAfterTheLimit() = assertTrue(BackgroundPolicy.shouldAutoLock(0, 5_000, max))

    @Test fun aClockGoingBackwardsNeverLocksEarly() = assertFalse(BackgroundPolicy.shouldAutoLock(2_000, 1_000, max))

    @Test fun twelveHoursIsTheDefaultBound() = assertEquals(12L * 60 * 60 * 1000, BackgroundPolicy.MAX_BACKGROUND_MS)

    @Test fun anOverrideCanOnlyShortenTheBound() {
        assertEquals(60_000L, BackgroundPolicy.effectiveLimitMs(60_000L))
        assertEquals(BackgroundPolicy.MAX_BACKGROUND_MS, BackgroundPolicy.effectiveLimitMs(0L))
        assertEquals(BackgroundPolicy.MAX_BACKGROUND_MS, BackgroundPolicy.effectiveLimitMs(-5L))
        assertEquals(BackgroundPolicy.MAX_BACKGROUND_MS, BackgroundPolicy.effectiveLimitMs(BackgroundPolicy.MAX_BACKGROUND_MS * 2))
    }
}
