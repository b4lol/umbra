package org.umbra.android.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ThemeConfigTest {
    @Test fun defaultsRoundTrip() {
        assertEquals(ThemeConfig.DEFAULT, ThemeConfig.decode(ThemeConfig.DEFAULT.encode()))
    }

    @Test fun customValuesRoundTrip() {
        val c = ThemeConfig.DEFAULT.copy(
            mode = ThemeMode.AMOLED, hue = 305, vibrancePct = 130, radiusDp = 8, corner = CornerStyle.SQUIRCLE,
            density = Density.SPACIOUS, list = ListStyle.FLAT, header = HeaderStyle.COMPACT, textScalePct = 115,
            font = FontChoice.MONO, messages = MessageStyle.TERMINAL, showTimes = false, tapToReveal = true, reduceMotion = true,
        )
        assertEquals(c, ThemeConfig.decode(c.encode()))
    }

    @Test fun outOfRangeValuesAreClamped() {
        val c = ThemeConfig.decode(mapOf("hue" to "999", "vibrance" to "-40", "radius" to "500", "textScale" to "1000"))
        assertTrue(c.hue in 0..360)
        assertTrue(c.vibrancePct in 0..160)
        assertTrue(c.radiusDp in 0..36)
        assertTrue(c.textScalePct in 85..130)
    }

    @Test fun garbageFallsBackToDefaults() {
        val c = ThemeConfig.decode(mapOf("mode" to "<script>", "hue" to "abc", "corner" to "", "font" to "Comic Sans", "showTimes" to "maybe"))
        assertEquals(ThemeConfig.DEFAULT, c)
    }

    @Test fun unknownKeysAreIgnored() {
        assertEquals(ThemeConfig.DEFAULT, ThemeConfig.decode(mapOf("nonsense" to "1")))
    }
}
