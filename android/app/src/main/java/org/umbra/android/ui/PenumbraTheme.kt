package org.umbra.android.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.Density as ComposeDensity

@Immutable
class PenumbraColors(
    val bg: Color, val card: Color, val ink: Color, val mut: Color, val line: Color,
    val acc: Color, val accInk: Color, val soft: Color, val ok: Color, val err: Color,
)

@Immutable
class Metrics(val config: ThemeConfig, val font: FontFamily)

val LocalColors = compositionLocalOf<PenumbraColors> { error("PenumbraTheme missing") }
val LocalMetrics = compositionLocalOf<Metrics> { error("PenumbraTheme missing") }

object Penumbra {
    val colors: PenumbraColors @Composable get() = LocalColors.current
    val metrics: Metrics @Composable get() = LocalMetrics.current
}

private fun Srgb.color() = Color(toArgb())

@Composable
fun PenumbraTheme(content: @Composable () -> Unit) {
    val config = ThemeStore.config
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val mode = when (config.mode) {
        ThemeMode.SYSTEM -> if (dark) Mode.DARK else Mode.LIGHT
        ThemeMode.LIGHT -> Mode.LIGHT
        ThemeMode.DARK -> Mode.DARK
        ThemeMode.AMOLED -> Mode.AMOLED
    }
    val hue = if (config.accentSource == AccentSource.WALLPAPER && android.os.Build.VERSION.SDK_INT >= 31) {
        Oklch.hueOf(context.getColor(android.R.color.system_accent1_500))
    } else {
        config.hue.toDouble()
    }
    val palette = remember(mode, hue, config.vibrancePct) { derivePalette(mode, hue, config.vibrancePct / 100.0) }
    val colors = remember(palette) {
        PenumbraColors(
            palette.bg.color(), palette.card.color(), palette.ink.color(), palette.mut.color(), palette.line.color(),
            palette.acc.color(), palette.accInk.color(), palette.soft.color(), palette.ok.color(), palette.err.color(),
        )
    }
    val font = when (config.font) {
        FontChoice.SYSTEM -> FontFamily.Default
        FontChoice.SERIF -> FontFamily.Serif
        FontChoice.MONO -> FontFamily.Monospace
    }
    val animatorScale = remember(context) {
        android.provider.Settings.Global.getFloat(context.contentResolver, android.provider.Settings.Global.ANIMATOR_DURATION_SCALE, 1f)
    }
    val reduceMotion = effectiveReduceMotion(config.reduceMotion, animatorScale)
    val base = LocalDensity.current
    CompositionLocalProvider(
        LocalColors provides colors,
        LocalMetrics provides Metrics(config.copy(reduceMotion = reduceMotion), font),
        LocalDensity provides ComposeDensity(base.density, base.fontScale * config.textScalePct / 100f),
        content = content,
    )
}
