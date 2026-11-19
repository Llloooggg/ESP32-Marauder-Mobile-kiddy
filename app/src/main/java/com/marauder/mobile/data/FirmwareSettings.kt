package com.marauder.mobile.data

/**
 * The board's own settings, as the firmware reports them.
 *
 * `settings` (no arguments) is not JSON: [Settings::printJsonSettings] prints a plain
 * `Name: / Type: / Value:` block per setting, and redacts `ClientPW` and the saved Wi-Fi
 * profiles itself, so the app never sees those values either. The writes go back through
 * `settings -s <key> enable|disable`, which the firmware only accepts for boolean
 * settings — the string settings (client SSID/password, wardrive keys) stay read-only
 * here on purpose, because the CLI has no way to set them.
 */
data class BoardSetting(val name: String, val type: String, val value: String, val redacted: Boolean) {

    /** `bool` settings are the only ones the firmware lets the app change. */
    val editable: Boolean get() = type.equals("bool", ignoreCase = true)

    /** The current state of a boolean setting; false for anything that is not one. */
    val enabled: Boolean
        get() = editable && value.equals("true", ignoreCase = true)
}

object FirmwareSettings {

    /** Firmware wording when a settings write is rejected (`CommandLine.cpp`, SETTINGS branch). */
    const val WRITE_FAILED = "Could not successfully update setting"

    /** Firmware wording when the settings file itself cannot be read. */
    const val NO_SETTINGS = "Settings"

    /**
     * Parse a `settings` dump. Malformed blocks are skipped rather than guessed at: a
     * half-read setting shown as a toggle would let the app write a value it never read.
     */
    fun parse(text: String): List<BoardSetting> {
        val out = ArrayList<BoardSetting>()
        var name: String? = null
        var type: String? = null
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            when {
                line.startsWith("Name:") -> {
                    // A Name without its Value: the previous block was cut short, drop it.
                    name = line.substringAfter(':').trim().ifEmpty { null }
                    type = null
                }
                line.startsWith("Type:") -> type = line.substringAfter(':').trim().ifEmpty { null }
                line.startsWith("Value:") -> {
                    val value = line.substringAfter(':').trim()
                    val n = name
                    val t = type
                    if (n != null && t != null) {
                        out += BoardSetting(
                            name = n,
                            type = t,
                            value = if (value == REDACTED) "" else value,
                            redacted = value == REDACTED,
                        )
                    }
                    name = null
                    type = null
                }
                // Anything else (header, dashes, blank lines, the device's own chatter) is
                // not part of a block; a stray line between Name: and Value: must not make
                // the app invent a type for it.
                line.isNotEmpty() && name != null -> {
                    name = null
                    type = null
                }
            }
        }
        return out
    }

    /** The firmware's own placeholder for settings it refuses to print. */
    private const val REDACTED = "[redacted]"

    /**
     * Whether a fresh dump proves the write landed. Comparing the whole list keeps a
     * partially applied change visible instead of reporting success on one line.
     */
    fun agrees(before: List<BoardSetting>, after: List<BoardSetting>, key: String, want: Boolean): Boolean {
        val now = after.firstOrNull { it.name == key } ?: return false
        return now.enabled == want
    }
}
