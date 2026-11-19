package com.marauder.mobile.data

/**
 * Reading the board's own words about where its radio sits.
 *
 * `channel` with no arguments makes the firmware print the channel it has set and nothing else:
 * `CommandLine.cpp:658-668` prints `wifi_scan_obj.set_channel` on a line of its own. The reply has
 * no end marker and no label, so the parse takes the first line that is a bare number and rejects
 * everything else.
 *
 * Rejecting matters more than guessing. On the board's built-in USB-CDC link characters are lost
 * while the console is busy (a field run produced `50:ff:20:90:5a:ef ESSMo` where the SSID should
 * have been), so a garbled reply is possible. `null` means the app does not know where the radio
 * is, and it says that instead of aiming a run at a channel the board cannot hear.
 */
object BoardRadio {

    /** Channels the firmware can be pointed at: 1-14 in 2.4 GHz, higher numbers exist in 5 GHz. */
    private val CHANNEL_RANGE = 1..255

    /**
     * The channel from the board's `channel` reply, or null when the reply does not contain one.
     * Only whole lines of digits count, so a number inside a garbled or unrelated line is never
     * mistaken for the answer.
     */
    fun parseChannelAnswer(text: String): Int? =
        text.lineSequence()
            .map { it.trim() }
            .firstOrNull { line ->
                line.isNotEmpty() && line.all { it.isDigit() } && (line.toIntOrNull() ?: 0) in CHANNEL_RANGE
            }
            ?.toIntOrNull()
}
