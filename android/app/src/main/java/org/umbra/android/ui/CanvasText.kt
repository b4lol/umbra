package org.umbra.android.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.Constraints

/**
 * Sensitive text (message bodies, SAS codes) — ANDROID.md §4: drawn into a Canvas and exposed to NO
 * accessibility tree; never a Text/BasicText composable. The layout object lives only in this
 * process's memory. (TalkBack therefore cannot read these values, by design.)
 */
@Composable
fun CanvasText(text: String, style: TextStyle, color: Color, modifier: Modifier = Modifier) {
    val measurer = rememberTextMeasurer()
    BoxWithConstraints(modifier) {
        val layout = measurer.measure(AnnotatedString(text), style, constraints = Constraints(maxWidth = constraints.maxWidth))
        val d = LocalDensity.current
        Box(
            Modifier
                .size(with(d) { layout.size.width.toDp() }, with(d) { layout.size.height.toDp() })
                .clearAndSetSemantics { }
                .drawBehind { drawText(layout, color = color) },
        )
    }
}
