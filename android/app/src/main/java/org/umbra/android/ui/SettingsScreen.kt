package org.umbra.android.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.roundToInt

private class Preset(val name: String, val hue: Int, val vibrancePct: Int = 100)

private val PRESETS = listOf(
    Preset("Lagoon", 205), Preset("Ember", 45), Preset("Orchid", 305),
    Preset("Moss", 140), Preset("Coral", 15), Preset("Graphite", 250, 25),
)

private fun swatch(hue: Double, vibrance: Double) = Color(Oklch.toSrgbInGamut(.72, .13 * vibrance, hue).toArgb())

private val HUE_TRACK = Brush.horizontalGradient((0..360 step 30).map { swatch(it.toDouble(), 1.0) })

@Composable
private fun Labeled(title: String, value: String? = null, content: @Composable () -> Unit) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            PText(title, style = PStyle.Label)
            if (value != null) PText(value, style = PStyle.Caption)
        }
        Spacer(Modifier.height(8.dp))
        content()
    }
}

@Composable
private fun Swatch(color: Color, selected: Boolean, label: String, onClick: () -> Unit) {
    val ink = Penumbra.colors.ink
    Box(
        Modifier
            .size(38.dp)
            .clip(CircleShape)
            .background(color)
            .let { if (selected) it.border(3.dp, ink, CircleShape) else it }
            .semantics { role = Role.RadioButton; contentDescription = label }
            .tappable(role = Role.RadioButton, onClick = onClick),
    )
}

@Composable
private fun Padlock(tint: Color) {
    Canvas(Modifier.size(20.dp)) {
        val w = size.width
        val body = Size(w * .68f, w * .48f)
        val left = (w - body.width) / 2
        val top = w * .46f
        drawArc(tint, 180f, 180f, false, Offset(w * .3f, w * .12f), Size(w * .4f, w * .5f), style = Stroke(w * .1f))
        drawRoundRect(tint, Offset(left, top), body, CornerRadius(w * .1f))
    }
}

@Composable
private fun Preview() {
    val colors = Penumbra.colors
    val config = Penumbra.metrics.config
    PGroupLabel("PREVIEW")
    PCard(tone = colors.bg.let { colors.card }) {
        PText("A sample row", style = PStyle.Label)
        PText("Everything below restyles as you change it.", style = PStyle.Caption)
        Spacer(Modifier.height(10.dp))
        Box(
            Modifier
                .clip(shapeFor(config.corner, config.radiusDp, .8f))
                .background(colors.acc)
                .padding(horizontal = 14.dp, vertical = 10.dp),
        ) { CanvasText("Sample message", TextStyle(fontSize = 15.sp, fontFamily = Penumbra.metrics.font), colors.accInk) }
        Spacer(Modifier.height(10.dp))
        PButton("Sample button", kind = PKind.Tonal) {}
    }
}

@Composable
fun SettingsScreen(onBack: () -> Unit) {
    val c = ThemeStore.config
    val colors = Penumbra.colors
    PScreen(title = "Appearance", onBack = onBack) {
        Preview()

        PGroupLabel("COLOUR")
        PGroup {
            row {
                Labeled("Theme") {
                    PSegmented(
                        listOf(ThemeMode.SYSTEM to "System", ThemeMode.LIGHT to "Light", ThemeMode.DARK to "Dark", ThemeMode.AMOLED to "AMOLED"),
                        c.mode,
                    ) { v -> ThemeStore.update { it.copy(mode = v) } }
                }
            }
            row {
                Labeled("Accent") {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        PRESETS.forEach { p ->
                            Swatch(
                                swatch(p.hue.toDouble(), p.vibrancePct / 100.0),
                                selected = c.accentSource == AccentSource.PRESET && c.hue == p.hue && c.vibrancePct == p.vibrancePct,
                                label = p.name,
                            ) { ThemeStore.update { it.copy(accentSource = AccentSource.PRESET, hue = p.hue, vibrancePct = p.vibrancePct) } }
                        }
                        if (android.os.Build.VERSION.SDK_INT >= 31) {
                            val ctx = androidx.compose.ui.platform.LocalContext.current
                            Swatch(
                                Color(ctx.getColor(android.R.color.system_accent1_500)),
                                selected = c.accentSource == AccentSource.WALLPAPER,
                                label = "Wallpaper",
                            ) { ThemeStore.update { it.copy(accentSource = AccentSource.WALLPAPER) } }
                        }
                    }
                }
            }
            row {
                Labeled("Hue", "${c.hue}°") {
                    PSlider(c.hue.toFloat(), 0f..360f, { v -> ThemeStore.update { it.copy(accentSource = AccentSource.CUSTOM, hue = v.roundToInt()) } }, track = HUE_TRACK)
                }
            }
            row {
                Labeled("Vibrance", "${c.vibrancePct}%") {
                    PSlider(c.vibrancePct.toFloat(), 0f..160f, { v -> ThemeStore.update { it.copy(accentSource = AccentSource.CUSTOM, vibrancePct = v.roundToInt()) } })
                }
            }
        }

        PGroupLabel("SHAPE AND DENSITY")
        PGroup {
            row {
                Labeled("Corner radius", "${c.radiusDp} dp") {
                    PSlider(c.radiusDp.toFloat(), 0f..36f, { v -> ThemeStore.update { it.copy(radiusDp = v.roundToInt()) } })
                }
            }
            row {
                Labeled("Corner style") {
                    PSegmented(listOf(CornerStyle.ROUND to "Round", CornerStyle.SQUIRCLE to "Squircle", CornerStyle.BEVEL to "Bevel"), c.corner) { v -> ThemeStore.update { it.copy(corner = v) } }
                }
            }
            row {
                Labeled("Density") {
                    PSegmented(listOf(Density.COMPACT to "Compact", Density.COMFORTABLE to "Comfortable", Density.SPACIOUS to "Spacious"), c.density) { v -> ThemeStore.update { it.copy(density = v) } }
                }
            }
            row {
                Labeled("Lists") {
                    PSegmented(listOf(ListStyle.GROUPED to "Grouped", ListStyle.FLAT to "Flat"), c.list) { v -> ThemeStore.update { it.copy(list = v) } }
                }
            }
            row {
                Labeled("Header") {
                    PSegmented(listOf(HeaderStyle.LARGE to "Large title", HeaderStyle.COMPACT to "Compact"), c.header) { v -> ThemeStore.update { it.copy(header = v) } }
                }
            }
        }

        PGroupLabel("TEXT")
        PGroup {
            row {
                Labeled("Size", "${c.textScalePct}%") {
                    PSlider(c.textScalePct.toFloat(), 85f..130f, { v -> ThemeStore.update { it.copy(textScalePct = v.roundToInt()) } })
                }
            }
            row {
                Labeled("Font") {
                    PSegmented(listOf(FontChoice.SYSTEM to "System", FontChoice.SERIF to "Serif", FontChoice.MONO to "Mono"), c.font) { v -> ThemeStore.update { it.copy(font = v) } }
                }
            }
        }

        PGroupLabel("MESSAGES")
        PGroup {
            row {
                Labeled("Style") {
                    PSegmented(listOf(MessageStyle.BUBBLE to "Bubbles", MessageStyle.FLAT to "Flat", MessageStyle.TERMINAL to "Terminal"), c.messages) { v -> ThemeStore.update { it.copy(messages = v) } }
                }
            }
            row { PRow("Show times", trailing = { PSwitch(c.showTimes, { v -> ThemeStore.update { it.copy(showTimes = v) } }) }) }
            row {
                PRow(
                    "Tap to reveal",
                    summary = "Hide message text until tapped; it hides again after 5 seconds.",
                    trailing = { PSwitch(c.tapToReveal, { v -> ThemeStore.update { it.copy(tapToReveal = v) } }) },
                )
            }
            row { PRow("Reduce motion", trailing = { PSwitch(c.reduceMotion, { v -> ThemeStore.update { it.copy(reduceMotion = v) } }) }) }
        }

        PGroupLabel("FIXED BY DESIGN")
        PGroup {
            row { PRow("Secure window", summary = "Screenshots and recents thumbnails are blocked.", leading = { Padlock(colors.ok) }, trailing = { PText("On", style = PStyle.Caption) }) }
            row { PRow("Canvas-drawn content", summary = "Messages and codes are hidden from accessibility services.", leading = { Padlock(colors.ok) }, trailing = { PText("On", style = PStyle.Caption) }) }
            row { PRow("Privacy footer", summary = "The privacy summary is always shown where messages are.", leading = { Padlock(colors.ok) }, trailing = { PText("On", style = PStyle.Caption) }) }
        }

        Spacer(Modifier.height(16.dp))
        PButton("Reset to default", kind = PKind.Ghost) { ThemeStore.reset() }
    }
}
