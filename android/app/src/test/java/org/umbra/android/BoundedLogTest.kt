package org.umbra.android

import org.junit.Assert.assertEquals
import org.junit.Test

class BoundedLogTest {
    @Test
    fun keepsOnlyTheNewestLinesUpToTheBound() {
        val log = BoundedLog(3)
        listOf("a", "b", "c", "d", "e").forEach(log::add)
        assertEquals(listOf("c", "d", "e"), log.snapshot())
    }

    @Test
    fun belowTheBoundKeepsEverythingInOrder() {
        val log = BoundedLog(400)
        log.add("one")
        log.add("two")
        assertEquals(listOf("one", "two"), log.snapshot())
    }
}
