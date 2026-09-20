package org.umbra.android.ui

import kotlin.math.atan2
import kotlin.math.cbrt
import kotlin.math.cos
import kotlin.math.pow
import kotlin.math.roundToInt
import kotlin.math.sin

/** sRGB in 0..1 (gamma-encoded). */
data class Srgb(val r: Double, val g: Double, val b: Double) {
    fun toArgb(): Int =
        (0xFF shl 24) or
            ((r * 255).roundToInt().coerceIn(0, 255) shl 16) or
            ((g * 255).roundToInt().coerceIn(0, 255) shl 8) or
            (b * 255).roundToInt().coerceIn(0, 255)
}

object Oklch {
    private fun encode(x: Double): Double {
        val v = x.coerceIn(0.0, 1.0)
        return if (v <= 0.0031308) 12.92 * v else 1.055 * v.pow(1 / 2.4) - 0.055
    }

    private fun decode(x: Double): Double = if (x <= 0.04045) x / 12.92 else ((x + 0.055) / 1.055).pow(2.4)

    /** Linear-light sRGB (unclamped) for an OKLCH colour. */
    private fun toLinear(l: Double, c: Double, hDeg: Double): DoubleArray {
        val a = c * cos(Math.toRadians(hDeg))
        val b = c * sin(Math.toRadians(hDeg))
        val l_ = l + 0.3963377774 * a + 0.2158037573 * b
        val m_ = l - 0.1055613458 * a - 0.0638541728 * b
        val s_ = l - 0.0894841775 * a - 1.2914855480 * b
        val lc = l_ * l_ * l_
        val mc = m_ * m_ * m_
        val sc = s_ * s_ * s_
        return doubleArrayOf(
            4.0767416621 * lc - 3.3077115913 * mc + 0.2309699292 * sc,
            -1.2684380046 * lc + 2.6097574011 * mc - 0.3413193965 * sc,
            -0.0041960863 * lc - 0.7034186147 * mc + 1.7076147010 * sc,
        )
    }

    private fun fits(lin: DoubleArray): Boolean = lin.all { it >= -1e-4 && it <= 1 + 1e-4 }

    /** The colour, with chroma reduced (never lightness or hue) until it fits sRGB. */
    fun toSrgbInGamut(l: Double, c: Double, hDeg: Double): Srgb {
        var lo = 0.0
        var hi = c.coerceAtLeast(0.0)
        var lin = toLinear(l, hi, hDeg)
        if (!fits(lin)) {
            repeat(24) {
                val mid = (lo + hi) / 2
                if (fits(toLinear(l, mid, hDeg))) lo = mid else hi = mid
            }
            lin = toLinear(l, lo, hDeg)
        }
        return Srgb(encode(lin[0]), encode(lin[1]), encode(lin[2]))
    }

    fun luminance(s: Srgb): Double = 0.2126 * decode(s.r) + 0.7152 * decode(s.g) + 0.0722 * decode(s.b)

    fun contrast(a: Srgb, b: Srgb): Double {
        val x = luminance(a) + 0.05
        val y = luminance(b) + 0.05
        return if (x > y) x / y else y / x
    }

    /** OKLCH hue in degrees (0..360) of an ARGB colour (used for the wallpaper accent). */
    fun hueOf(argb: Int): Double {
        val r = decode(((argb shr 16) and 0xFF) / 255.0)
        val g = decode(((argb shr 8) and 0xFF) / 255.0)
        val b = decode((argb and 0xFF) / 255.0)
        val l = cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b)
        val m = cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b)
        val s = cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b)
        val a = 1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s
        val bb = 0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s
        val h = Math.toDegrees(atan2(bb, a))
        return if (h < 0) h + 360 else h
    }
}

enum class Mode { LIGHT, DARK, AMOLED }

class Palette(
    val bg: Srgb,
    val card: Srgb,
    val ink: Srgb,
    val mut: Srgb,
    val line: Srgb,
    val acc: Srgb,
    val accInk: Srgb,
    val soft: Srgb,
    val ok: Srgb,
    val err: Srgb,
)

/**
 * One hue + one vibrance make every surface (the same formulas as the design mockup). The
 * generator REPAIRS contrast: `mut` is stepped until it reads on both bg and card, the accent is
 * stepped until its label colour reads on it, and the semantic colours are stepped like `mut`, so
 * no customization can produce an unreadable UI (see PaletteTest).
 */
fun derivePalette(mode: Mode, hueDeg: Double, vibrance: Double): Palette {
    val cs = vibrance.coerceIn(0.0, 1.6)
    val h = ((hueDeg % 360) + 360) % 360
    fun c(l: Double, chroma: Double) = Oklch.toSrgbInGamut(l, chroma, h)

    val bg: Srgb
    val card: Srgb
    val ink: Srgb
    val line: Srgb
    val soft: Srgb
    val accInk: Srgb
    var mutL: Double
    val mutStep: Double
    val accBase: Double
    when (mode) {
        Mode.LIGHT -> {
            bg = c(.955, .012 * cs); card = c(.995, .004); ink = c(.22, .02); line = c(.91, .008); soft = c(.925, .04 * cs)
            accInk = Srgb(1.0, 1.0, 1.0); mutL = .52; mutStep = -.01; accBase = .60
        }
        Mode.DARK -> {
            bg = c(.18, .012); card = c(.235, .014); ink = c(.94, .01); line = c(.30, .012); soft = c(.30, .05 * cs)
            accInk = c(.20, .03); mutL = .70; mutStep = +.01; accBase = .75
        }
        Mode.AMOLED -> {
            bg = Srgb(0.0, 0.0, 0.0); card = c(.16, .01); ink = c(.95, .008); line = c(.25, .01); soft = c(.27, .05 * cs)
            accInk = c(.20, .03); mutL = .68; mutStep = +.01; accBase = .76
        }
    }
    var mut = c(mutL, .02)
    var guard = 0
    while (guard++ < 60 && (Oklch.contrast(mut, bg) < 4.5 || Oklch.contrast(mut, card) < 4.5)) {
        mutL = (mutL + mutStep).coerceIn(0.0, 1.0); mut = c(mutL, .02)
    }

    var accL = accBase
    val accStep = if (Oklch.luminance(accInk) > .5) -.01 else +.01
    var acc = c(accL, .14 * cs)
    guard = 0
    while (guard++ < 60 && (Oklch.contrast(accInk, acc) < 4.5 || Oklch.contrast(acc, bg) < 3.0)) {
        accL = (accL + accStep).coerceIn(0.0, 1.0); acc = c(accL, .14 * cs)
    }

    // Semantic colours: fixed hues (150 = ok, 25 = error) so they never blend into a user's accent,
    // repaired for text contrast on both surfaces like `mut`.
    fun semantic(hueDeg: Double, startL: Double): Srgb {
        var l = startL
        var col = Oklch.toSrgbInGamut(l, .17, hueDeg)
        var g = 0
        while (g++ < 60 && (Oklch.contrast(col, bg) < 4.5 || Oklch.contrast(col, card) < 4.5)) {
            l = (l + mutStep).coerceIn(0.0, 1.0); col = Oklch.toSrgbInGamut(l, .17, hueDeg)
        }
        return col
    }
    return Palette(
        bg, card, ink, mut, line, acc, accInk, soft,
        semantic(150.0, if (mode == Mode.LIGHT) .55 else .78),
        semantic(25.0, if (mode == Mode.LIGHT) .5 else .74),
    )
}
