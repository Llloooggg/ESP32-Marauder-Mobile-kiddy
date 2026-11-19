package com.marauder.mobile.data

/**
 * What the firmware actually does with a capture command, so the app can set the board
 * up for it instead of explaining an empty pcap afterwards.
 *
 * Two behaviours in this firmware tree are the reason a capture can come back with
 * nothing in it even while the board is sitting on the right channel:
 *
 *  * **A channel-pinned passive sniff still hops.** `sniffpmkid -c <ch>` only calls
 *    `changeChannel()` once (CommandLine.cpp:1058-1061) and then runs
 *    `WIFI_SCAN_EAPOL` (CommandLine.cpp:1067), whose loop calls `channelHop()` every
 *    2 s (WiFiScan.cpp:13028-13039). The only thing that stops it is the
 *    persisted `ChanHop` setting (WiFiScan.cpp:10997-11006). So without that setting
 *    the radio is on the target channel for at most one hop interval.
 *  * **A leftover selection blinds the sniffer.** `eapolSnifferCallback` asks
 *    `filterActive()`, and when *any* AP is selected it returns for every frame whose
 *    AP is not selected (WiFiScan.cpp:10616-10623) — before `eapol_frames++`
 *    (WiFiScan.cpp:10637) and before the frame is handed to the pcap buffer
 *    (WiFiScan.cpp:10692). Selection is not reset when a scan stops (only
 *    `WIFI_SCAN_SIG_STREN` does that, WiFiScan.cpp:3252-3260), so one earlier targeted
 *    run quietly disables every later untargeted capture.
 */
object CaptureOps {

    private val channelArg = Regex("""-c\s+\d+""")

    /** `sniffpmkid` without `-d`: the passive PMKID/EAPOL sniff (`WIFI_SCAN_EAPOL`). */
    private fun passiveEapolSniff(cmd: String): Boolean {
        val c = cmd.trim()
        return c.startsWith("sniffpmkid") && !c.contains("-d")
    }

    /**
     * True when the command pins a passive sniff to one channel with `-c`, and the
     * `ChanHop` setting therefore has to be off for the whole run — otherwise the
     * board hops away 2 s later and the capture only sees that channel by accident.
     *
     * Deliberately narrow: with `-d` the firmware runs `WIFI_SCAN_ACTIVE_EAPOL`
     * (CommandLine.cpp:1075) or `WIFI_SCAN_ACTIVE_LIST_EAPOL` (CommandLine.cpp:1071),
     * and the ChanHop gate at WiFiScan.cpp:10997 does not cover those modes — turning
     * the setting off there would do nothing, so the app must not pretend it helps.
     */
    fun needsHopOff(command: String): Boolean =
        passiveEapolSniff(command) && channelArg.containsMatchIn(command)

    /**
     * True when the command listens for other people's traffic and the firmware drops
     * every frame that does not belong to a selected AP. That is every `sniffpmkid`
     * without `-l`: the passive sniff and the `-d` deauth-assisted run both stream the
     * EAPOL frames through `eapolSnifferCallback`, whose filter sits before the counter
     * and before the pcap buffer.
     *
     * `sniffpmkid ... -l` is the opposite: it *requires* a selection and the firmware
     * refuses outright when there is none ("You don't have any targets selected. Use
     * select", CommandLine.cpp:1051-1056).
     */
    fun needsEmptySelection(command: String): Boolean =
        command.trim().startsWith("sniffpmkid") && !command.trim().contains("-l")

    /**
     * The firmware's refusal when `-l` is used with nothing selected
     * (CommandLine.cpp:1051-1056). Catching it turns a mission that looks idle into a
     * sentence that says why nothing was transmitted.
     */
    const val NO_TARGETS_SELECTED = "You don't have any targets selected"

    /** Firmware wording when a settings write is rejected (CommandLine.cpp:747-751). */
    const val SETTING_WRITE_FAILED = "Could not successfully update setting"

    /**
     * Channel the command pins itself to, or 0 when it does not pin one. Only
     * `sniffpmkid -c` and the `channel` command set a channel from the CLI
     * (CommandLine.cpp:647 and 1059).
     */
    fun pinnedChannel(command: String): Int {
        val m = channelArg.find(command.trim()) ?: return 0
        return m.value.substringAfter("-c").trim().toIntOrNull() ?: 0
    }
}
