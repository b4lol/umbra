package org.umbra.android.ui

/** Motion is reduced when the user asked for it in Appearance OR turned system animations off. */
fun effectiveReduceMotion(configFlag: Boolean, animatorScale: Float): Boolean = configFlag || animatorScale == 0f
