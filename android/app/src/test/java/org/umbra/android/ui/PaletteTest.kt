package org.umbra.android.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PaletteTest {
    private val hues = (0..355 step 5).map { it.toDouble() }
    private val vibrances = listOf(0.0, 0.5, 1.0, 1.6)

    private inline fun forAll(block: (Mode, Double, Double, Palette) -> Unit) {
        for (mode in Mode.values()) for (h in hues) for (v in vibrances) block(mode, h, v, derivePalette(mode, h, v))
    }

    @Test fun bodyTextIsAlwaysReadable() = forAll { mode, h, v, p ->
        val tag = "$mode h=$h v=$v"
        assertTrue("ink/bg $tag", Oklch.contrast(p.ink, p.bg) >= 7.0)
        assertTrue("ink/card $tag", Oklch.contrast(p.ink, p.card) >= 7.0)
        assertTrue("mut/bg $tag", Oklch.contrast(p.mut, p.bg) >= 4.5)
        assertTrue("mut/card $tag", Oklch.contrast(p.mut, p.card) >= 4.5)
    }

    @Test fun semanticColoursAreReadable() = forAll { mode, h, v, p ->
        val tag = "$mode h=$h v=$v"
        listOf("ok" to p.ok, "err" to p.err).forEach { (name, col) ->
            assertTrue("$name/bg $tag", Oklch.contrast(col, p.bg) >= 4.5)
            assertTrue("$name/card $tag", Oklch.contrast(col, p.card) >= 4.5)
        }
    }

    @Test fun accentButtonsAreReadableAndVisible() = forAll { mode, h, v, p ->
        val tag = "$mode h=$h v=$v"
        assertTrue("accInk/acc $tag", Oklch.contrast(p.accInk, p.acc) >= 4.5)
        assertTrue("acc/bg $tag", Oklch.contrast(p.acc, p.bg) >= 3.0)
    }

    @Test fun everyColourIsInsideTheSrgbGamut() = forAll { _, _, _, p ->
        listOf(p.bg, p.card, p.ink, p.mut, p.line, p.acc, p.accInk, p.soft, p.ok, p.err).forEach {
            assertTrue(it.r in 0.0..1.0 && it.g in 0.0..1.0 && it.b in 0.0..1.0)
        }
    }

    @Test fun amoledBackgroundIsPureBlack() {
        val p = derivePalette(Mode.AMOLED, 205.0, 1.0)
        assertEquals(0xFF000000.toInt(), p.bg.toArgb())
    }

    @Test fun derivationIsDeterministic() {
        assertEquals(derivePalette(Mode.DARK, 123.0, 0.8).acc.toArgb(), derivePalette(Mode.DARK, 123.0, 0.8).acc.toArgb())
    }

    @Test fun hueOfRoundTripsThroughTheGenerator() {
        val argb = Oklch.toSrgbInGamut(0.65, 0.12, 205.0).toArgb()
        assertTrue(kotlin.math.abs(Oklch.hueOf(argb) - 205.0) < 2.0)
    }

    @Test fun contrastOfBlackOnWhiteIsTwentyOne() {
        assertEquals(21.0, Oklch.contrast(Srgb(0.0, 0.0, 0.0), Srgb(1.0, 1.0, 1.0)), 0.01)
    }
}
