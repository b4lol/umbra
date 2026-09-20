package org.umbra.android.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ShapesTest {
    @Test fun cornerPointsStayInsideTheirBox() {
        val pts = squircleCornerPoints(cx = 20f, cy = 20f, r = 20f, quadrant = 0, steps = 16)
        assertEquals(17, pts.size)
        pts.forEach { (x, y) -> assertTrue(x in 19.999f..40.001f && y in -0.001f..20.001f) }
    }

    @Test fun cornerEndsMeetTheStraightEdges() {
        val pts = squircleCornerPoints(cx = 0f, cy = 0f, r = 10f, quadrant = 0, steps = 8)
        assertEquals(0f, pts.first().first, 0.01f)
        assertEquals(-10f, pts.first().second, 0.01f)
        assertEquals(10f, pts.last().first, 0.01f)
        assertEquals(0f, pts.last().second, 0.01f)
    }

    @Test fun squircleBulgesOutsideAPlainCircleAtTheDiagonal() {
        val (dx, dy) = squircleCornerPoints(0f, 0f, 10f, 0, 8)[4]
        assertTrue(Math.hypot(dx.toDouble(), dy.toDouble()) > 10.0)
    }

    @Test fun zeroRadiusIsAPointNotACrash() {
        assertEquals(1, squircleCornerPoints(5f, 5f, 0f, 2, 8).distinct().size)
    }
}
