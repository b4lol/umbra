package org.umbra.android.ui

import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Outline
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.pow
import kotlin.math.sign
import kotlin.math.sin

/**
 * Points along one superellipse corner (|x|^n + |y|^n = r^n; n = 5 gives the HyperOS "continuous"
 * look). quadrant: 0 = top-right, 1 = bottom-right, 2 = bottom-left, 3 = top-left. Pure so it can
 * be unit-tested without Android.
 */
fun squircleCornerPoints(cx: Float, cy: Float, r: Float, quadrant: Int, steps: Int, n: Float = 5f): List<Pair<Float, Float>> {
    if (r <= 0f) return listOf(cx to cy)
    val startAngle = when (quadrant) {
        0 -> -90.0
        1 -> 0.0
        2 -> 90.0
        else -> 180.0
    }
    return (0..steps).map { i ->
        val t = Math.toRadians(startAngle + 90.0 * i / steps)
        val c = cos(t).toFloat()
        val s = sin(t).toFloat()
        val x = sign(c) * abs(c).pow(2f / n) * r
        val y = sign(s) * abs(s).pow(2f / n) * r
        (cx + x) to (cy + y)
    }
}

class SquircleShape(private val radiusPx: Float) : Shape {
    override fun createOutline(size: Size, layoutDirection: LayoutDirection, density: androidx.compose.ui.unit.Density): Outline {
        val r = radiusPx.coerceAtMost(minOf(size.width, size.height) / 2f)
        val path = Path()
        val corners = listOf(
            squircleCornerPoints(size.width - r, r, r, 0, 12),
            squircleCornerPoints(size.width - r, size.height - r, r, 1, 12),
            squircleCornerPoints(r, size.height - r, r, 2, 12),
            squircleCornerPoints(r, r, r, 3, 12),
        )
        corners.forEachIndexed { i, pts ->
            pts.forEachIndexed { j, (x, y) -> if (i == 0 && j == 0) path.moveTo(x, y) else path.lineTo(x, y) }
        }
        path.close()
        return Outline.Generic(path)
    }
}

/** The shape for a card-sized surface; `scale` shrinks the radius for inner controls. */
@Composable
fun shapeFor(style: CornerStyle, radiusDp: Int, scale: Float = 1f): Shape {
    val r = (radiusDp * scale).coerceAtLeast(0f)
    val px = with(LocalDensity.current) { r.dp.toPx() }
    return when (style) {
        CornerStyle.ROUND -> RoundedCornerShape(r.dp)
        CornerStyle.SQUIRCLE -> SquircleShape(px)
        CornerStyle.BEVEL -> CutCornerShape((r * 0.7f).dp)
    }
}
