package org.umbra.android.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MotionTest {
    @Test fun configFlagWins() = assertTrue(effectiveReduceMotion(true, 1f))
    @Test fun systemAnimationsOffCounts() = assertTrue(effectiveReduceMotion(false, 0f))
    @Test fun normalOtherwise() {
        assertFalse(effectiveReduceMotion(false, 1f))
        assertFalse(effectiveReduceMotion(false, 0.5f))
    }
}
