package org.umbra.android.ui

enum class ThemeMode { SYSTEM, LIGHT, DARK, AMOLED }
enum class AccentSource { PRESET, CUSTOM, WALLPAPER }
enum class CornerStyle { ROUND, SQUIRCLE, BEVEL }
enum class Density(val factor: Float) { COMPACT(.82f), COMFORTABLE(1f), SPACIOUS(1.22f) }
enum class ListStyle { GROUPED, FLAT }
enum class HeaderStyle { LARGE, COMPACT }
enum class FontChoice { SYSTEM, SERIF, MONO }
enum class MessageStyle { BUBBLE, FLAT, TERMINAL }

/** Everything the user may customize. Values are UNTRUSTED when decoded: clamp, default, ignore the unknown. */
data class ThemeConfig(
    val mode: ThemeMode = ThemeMode.SYSTEM,
    val accentSource: AccentSource = AccentSource.PRESET,
    val hue: Int = 205,
    val vibrancePct: Int = 100,
    val radiusDp: Int = 22,
    val corner: CornerStyle = CornerStyle.ROUND,
    val density: Density = Density.COMFORTABLE,
    val list: ListStyle = ListStyle.GROUPED,
    val header: HeaderStyle = HeaderStyle.LARGE,
    val textScalePct: Int = 100,
    val font: FontChoice = FontChoice.SYSTEM,
    val messages: MessageStyle = MessageStyle.BUBBLE,
    val showTimes: Boolean = true,
    val tapToReveal: Boolean = false,
    val reduceMotion: Boolean = false,
) {
    fun encode(): Map<String, String> = mapOf(
        "mode" to mode.name, "accentSource" to accentSource.name, "hue" to hue.toString(),
        "vibrance" to vibrancePct.toString(), "radius" to radiusDp.toString(), "corner" to corner.name,
        "density" to density.name, "list" to list.name, "header" to header.name,
        "textScale" to textScalePct.toString(), "font" to font.name, "messages" to messages.name,
        "showTimes" to showTimes.toString(), "tapToReveal" to tapToReveal.toString(),
        "reduceMotion" to reduceMotion.toString(),
    )

    companion object {
        val DEFAULT = ThemeConfig()

        private inline fun <reified E : Enum<E>> Map<String, String?>.enum(key: String, default: E): E =
            this[key]?.let { v -> enumValues<E>().firstOrNull { it.name == v } } ?: default

        private fun Map<String, String?>.int(key: String, default: Int, range: IntRange): Int =
            this[key]?.toIntOrNull()?.coerceIn(range.first, range.last) ?: default

        private fun Map<String, String?>.bool(key: String, default: Boolean): Boolean =
            when (this[key]) {
                "true" -> true
                "false" -> false
                else -> default
            }

        fun decode(m: Map<String, String?>): ThemeConfig = ThemeConfig(
            mode = m.enum("mode", DEFAULT.mode),
            accentSource = m.enum("accentSource", DEFAULT.accentSource),
            hue = m.int("hue", DEFAULT.hue, 0..360),
            vibrancePct = m.int("vibrance", DEFAULT.vibrancePct, 0..160),
            radiusDp = m.int("radius", DEFAULT.radiusDp, 0..36),
            corner = m.enum("corner", DEFAULT.corner),
            density = m.enum("density", DEFAULT.density),
            list = m.enum("list", DEFAULT.list),
            header = m.enum("header", DEFAULT.header),
            textScalePct = m.int("textScale", DEFAULT.textScalePct, 85..130),
            font = m.enum("font", DEFAULT.font),
            messages = m.enum("messages", DEFAULT.messages),
            showTimes = m.bool("showTimes", DEFAULT.showTimes),
            tapToReveal = m.bool("tapToReveal", DEFAULT.tapToReveal),
            reduceMotion = m.bool("reduceMotion", DEFAULT.reduceMotion),
        )
    }
}
