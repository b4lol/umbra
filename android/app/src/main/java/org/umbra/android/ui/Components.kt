package org.umbra.android.ui

import androidx.compose.animation.core.snap
import androidx.compose.animation.core.tween
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.setProgress
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

enum class PStyle { Display, Title, Body, Label, Caption }

/** Ordinary text for NON-sensitive chrome. Sensitive content uses CanvasText. */
@Composable
fun PText(
    text: String,
    modifier: Modifier = Modifier,
    style: PStyle = PStyle.Body,
    color: Color = Color.Unspecified,
    align: TextAlign? = null,
    mono: Boolean = false,
) {
    val colors = Penumbra.colors
    val font = if (mono) androidx.compose.ui.text.font.FontFamily.Monospace else Penumbra.metrics.font
    val base = when (style) {
        PStyle.Display -> TextStyle(fontSize = 34.sp, fontWeight = FontWeight.SemiBold, letterSpacing = (-0.6).sp, lineHeight = 38.sp)
        PStyle.Title -> TextStyle(fontSize = 22.sp, fontWeight = FontWeight.SemiBold, letterSpacing = (-0.3).sp)
        PStyle.Body -> TextStyle(fontSize = 15.sp, lineHeight = 21.sp)
        PStyle.Label -> TextStyle(fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
        PStyle.Caption -> TextStyle(fontSize = 12.5.sp, lineHeight = 17.sp)
    }
    val resolved = if (color != Color.Unspecified) color else if (style == PStyle.Caption) colors.mut else colors.ink
    BasicText(text, modifier, style = base.copy(color = resolved, fontFamily = font, textAlign = align ?: androidx.compose.ui.text.style.TextAlign.Unspecified))
}

/** Tap feedback without a ripple: a small alpha dip while pressed. */
@Composable
fun Modifier.tappable(enabled: Boolean = true, role: Role? = Role.Button, onClick: () -> Unit): Modifier {
    val source = remember { MutableInteractionSource() }
    val pressed by source.collectIsPressedAsState()
    return this
        .alpha(if (pressed) .72f else 1f)
        .clickable(interactionSource = source, indication = null, enabled = enabled, role = role, onClick = onClick)
}

@Composable
private fun cornerShape(scale: Float = 1f) = Penumbra.metrics.config.let { shapeFor(it.corner, it.radiusDp, scale) }

@Composable
private fun densityFactor(): Float = Penumbra.metrics.config.density.factor

@Composable
fun PCard(modifier: Modifier = Modifier, tone: Color = Penumbra.colors.card, content: @Composable ColumnScope.() -> Unit) {
    val d = densityFactor()
    Column(
        modifier.fillMaxWidth().clip(cornerShape()).background(tone).padding(horizontal = 16.dp, vertical = (14 * d).dp),
        content = content,
    )
}

class GroupScope {
    internal val rows = mutableListOf<@Composable () -> Unit>()
    fun row(content: @Composable () -> Unit) { rows += content }
}

/** A Miuix-style inset list: rows on one rounded card, hairline dividers (or a flat list). */
@Composable
fun PGroup(modifier: Modifier = Modifier, content: GroupScope.() -> Unit) {
    val scope = GroupScope().apply(content)
    val flat = Penumbra.metrics.config.list == ListStyle.FLAT
    val colors = Penumbra.colors
    Column(
        modifier.fillMaxWidth().let { if (flat) it else it.clip(cornerShape()).background(colors.card) },
    ) {
        scope.rows.forEachIndexed { i, row ->
            if (i > 0) Box(Modifier.fillMaxWidth().height(1.dp).background(colors.line))
            row()
        }
    }
}

@Composable
fun PGroupLabel(text: String) {
    PText(text, Modifier.padding(start = 6.dp, top = 18.dp, bottom = 8.dp), style = PStyle.Caption)
}

@Composable
fun PRow(
    title: String,
    modifier: Modifier = Modifier,
    summary: String? = null,
    leading: (@Composable () -> Unit)? = null,
    trailing: (@Composable RowScope.() -> Unit)? = null,
    onClick: (() -> Unit)? = null,
) {
    val d = densityFactor()
    val flat = Penumbra.metrics.config.list == ListStyle.FLAT
    val base = if (onClick != null) modifier.tappable(role = Role.Button, onClick = onClick) else modifier
    Row(
        base.fillMaxWidth().padding(horizontal = if (flat) 6.dp else 16.dp, vertical = (13 * d).dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (leading != null) leading()
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            PText(title, style = PStyle.Label)
            if (summary != null) PText(summary, style = PStyle.Caption)
        }
        if (trailing != null) trailing()
    }
}

@Composable
fun PSwitch(checked: Boolean, onChange: (Boolean) -> Unit, modifier: Modifier = Modifier) {
    val colors = Penumbra.colors
    val reduce = Penumbra.metrics.config.reduceMotion
    val offset by animateDpAsState(if (checked) 20.dp else 0.dp, if (reduce) snap() else tween(160), label = "knob")
    Box(
        modifier
            .width(46.dp).height(28.dp)
            .clip(CircleShape)
            .background(if (checked) colors.acc else colors.mut.copy(alpha = .5f))
            .semantics { role = Role.Switch }
            .tappable(role = Role.Switch) { onChange(!checked) }
            .padding(3.dp),
    ) {
        Box(Modifier.offset(x = offset).size(22.dp).clip(CircleShape).background(if (checked) colors.accInk else Color.White))
    }
}

enum class PKind { Primary, Tonal, Ghost }

@Composable
fun PButton(text: String, modifier: Modifier = Modifier, kind: PKind = PKind.Primary, enabled: Boolean = true, onClick: () -> Unit) {
    val colors = Penumbra.colors
    val d = densityFactor()
    val (bg, fg) = when (kind) {
        PKind.Primary -> colors.acc to colors.accInk
        PKind.Tonal -> colors.soft to colors.ink
        PKind.Ghost -> colors.card to colors.ink
    }
    Box(
        modifier
            .fillMaxWidth()
            .alpha(if (enabled) 1f else .38f)
            .clip(cornerShape(.8f))
            .background(bg)
            .tappable(enabled = enabled, onClick = onClick)
            .padding(vertical = (14 * d).dp, horizontal = 16.dp),
        contentAlignment = Alignment.Center,
    ) { PText(text, style = PStyle.Label, color = fg, align = TextAlign.Center) }
}

@Composable
fun PField(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    password: Boolean = false,
    enabled: Boolean = true,
    singleLine: Boolean = true,
    minLines: Int = 1,
    maxLines: Int = if (singleLine) 1 else 6,
    mono: Boolean = false,
) {
    val colors = Penumbra.colors
    val d = densityFactor()
    val font = if (mono) androidx.compose.ui.text.font.FontFamily.Monospace else Penumbra.metrics.font
    BasicTextField(
        value = value,
        onValueChange = onChange,
        enabled = enabled,
        singleLine = singleLine,
        minLines = minLines,
        maxLines = maxLines,
        visualTransformation = if (password) PasswordVisualTransformation() else VisualTransformation.None,
        keyboardOptions = if (password) KeyboardOptions(keyboardType = KeyboardType.Password) else KeyboardOptions.Default,
        textStyle = TextStyle(color = colors.ink, fontSize = 15.sp, fontFamily = font),
        cursorBrush = SolidColor(colors.acc),
        modifier = modifier.fillMaxWidth().alpha(if (enabled) 1f else .6f),
        decorationBox = { inner ->
            Column(
                Modifier.fillMaxWidth().clip(cornerShape(.8f)).background(colors.card).padding(horizontal = 16.dp, vertical = (10 * d).dp),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                PText(label, style = PStyle.Caption)
                Box(Modifier.fillMaxWidth().padding(bottom = 2.dp)) { inner() }
            }
        },
    )
}

@Composable
fun <T> PSegmented(options: List<Pair<T, String>>, selected: T, modifier: Modifier = Modifier, onSelect: (T) -> Unit) {
    val colors = Penumbra.colors
    Row(
        modifier.fillMaxWidth().clip(cornerShape(.7f)).background(colors.soft).padding(3.dp),
        horizontalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        options.forEach { (value, label) ->
            val on = value == selected
            Box(
                Modifier
                    .weight(1f)
                    .clip(cornerShape(.55f))
                    .background(if (on) colors.card else Color.Transparent)
                    .semantics { role = Role.RadioButton }
                    .tappable(role = Role.RadioButton) { onSelect(value) }
                    .padding(vertical = 9.dp, horizontal = 4.dp),
                contentAlignment = Alignment.Center,
            ) { PText(label, style = PStyle.Caption, color = if (on) colors.ink else colors.mut, align = TextAlign.Center) }
        }
    }
}

@Composable
fun PSlider(
    value: Float,
    range: ClosedFloatingPointRange<Float>,
    onChange: (Float) -> Unit,
    modifier: Modifier = Modifier,
    track: Brush? = null,
) {
    val colors = Penumbra.colors
    val span = range.endInclusive - range.start
    Canvas(
        modifier
            .fillMaxWidth().height(34.dp)
            .semantics {
                progressBarRangeInfo = ProgressBarRangeInfo(value.coerceIn(range), range)
                setProgress { target -> onChange(target.coerceIn(range)); true }
            }
            .pointerInput(range) {
                detectTapGestures { p -> onChange((range.start + span * (p.x / size.width)).coerceIn(range)) }
            }
            .pointerInput(range) {
                detectHorizontalDragGestures { change, _ ->
                    change.consume()
                    onChange((range.start + span * (change.position.x / size.width)).coerceIn(range))
                }
            },
    ) {
        val cy = size.height / 2
        val th = 6.dp.toPx()
        val r = th / 2
        val frac = ((value - range.start) / span).coerceIn(0f, 1f)
        val pad = 11.dp.toPx()
        val x0 = pad
        val x1 = size.width - pad
        if (track != null) {
            drawRoundRect(track, topLeft = Offset(x0, cy - r), size = androidx.compose.ui.geometry.Size(x1 - x0, th), cornerRadius = androidx.compose.ui.geometry.CornerRadius(r, r))
        } else {
            drawRoundRect(colors.line, Offset(x0, cy - r), androidx.compose.ui.geometry.Size(x1 - x0, th), androidx.compose.ui.geometry.CornerRadius(r, r))
            drawRoundRect(colors.acc, Offset(x0, cy - r), androidx.compose.ui.geometry.Size((x1 - x0) * frac, th), androidx.compose.ui.geometry.CornerRadius(r, r))
        }
        val tx = x0 + (x1 - x0) * frac
        drawCircle(colors.card, radius = 11.dp.toPx(), center = Offset(tx, cy))
        drawCircle(colors.acc, radius = 9.dp.toPx(), center = Offset(tx, cy))
    }
}

/**
 * The large-title screen scaffold: a collapsing header over a scrolling column (or a fixed layout
 * when [scroll] is false, e.g. the chat list which scrolls itself).
 */
@Composable
fun PScreen(
    title: String,
    modifier: Modifier = Modifier,
    onBack: (() -> Unit)? = null,
    scroll: Boolean = true,
    bottomBar: (@Composable () -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val colors = Penumbra.colors
    val config = Penumbra.metrics.config
    val state = rememberScrollState()
    val threshold = 44f
    val p by remember(scroll, config.header) {
        derivedStateOf { if (!scroll || config.header == HeaderStyle.COMPACT) 1f else (state.value / threshold).coerceIn(0f, 1f) }
    }
    Box(modifier.fillMaxSize().background(colors.bg).imePadding()) {
        Column(Modifier.fillMaxSize()) {
            Spacer(Modifier.windowInsetsPadding(WindowInsets.statusBars).height(52.dp))
            Column(
                Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .let { if (scroll) it.verticalScroll(state) else it }
                    .padding(horizontal = 16.dp),
            ) {
                if (config.header == HeaderStyle.LARGE) {
                    PText(title, Modifier.alpha(1f - p).padding(top = 4.dp, bottom = 10.dp), style = PStyle.Display)
                }
                content()
                if (scroll) Spacer(Modifier.height(24.dp).navigationBarsPadding())
            }
            if (bottomBar != null) Box(Modifier.navigationBarsPadding()) { bottomBar() }
        }
        // top bar: translucent surface (a true backdrop blur needs a third-party library)
        Row(
            Modifier
                .fillMaxWidth()
                .background(colors.bg.copy(alpha = .92f))
                .windowInsetsPadding(WindowInsets.statusBars)
                .height(52.dp)
                .padding(horizontal = 16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (onBack != null) {
                Box(
                    Modifier.size(36.dp).clip(CircleShape).background(colors.card)
                        .semantics { role = Role.Button }
                        .tappable(onClick = onBack),
                    contentAlignment = Alignment.Center,
                ) { PText("‹", style = PStyle.Title) }
            }
            PText(title, Modifier.alpha(p), style = PStyle.Label)
        }
    }
}

/** A hairline-bordered chip for footers and notes. */
@Composable
fun PNote(text: String, modifier: Modifier = Modifier) {
    val colors = Penumbra.colors
    PText(
        text,
        modifier.fillMaxWidth().clip(cornerShape(.6f)).border(BorderStroke(1.dp, colors.line), cornerShape(.6f)).padding(12.dp),
        style = PStyle.Caption,
        align = TextAlign.Center,
    )
}
