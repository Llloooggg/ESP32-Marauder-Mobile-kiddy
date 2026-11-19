package com.marauder.mobile.data

/**
 * What the firmware actually does with a capture command, so the app can set the board
 * up for it instead of explaining an empty pcap afterwards.
 *
 * Two behaviours in this firmware tree are the reason a capture can come back with
 * nothing in it even while the board is sitting on the right channel:
 *
 *  * **A channel-pinned sniff can hop away.** `sniffpmkid -c <ch>` only calls
 *    `changeChannel()` once (CommandLine.cpp:1058-1061). Whether the radio then stays
 *    put depends on which mode the command chose:
 *      - passive (`sniffpmkid`, `-c` only) runs `WIFI_SCAN_EAPOL`, whose loop calls
 *        `channelHop()` every 2 s (WiFiScan.cpp:13028-13039), and that call returns
 *        early when the persisted `ChanHop` setting is off
 *        (WiFiScan.cpp:10997-11006). The setting decides this mode, and
 *        [needsHopOff] turns it off for the run.
 *      - `sniffpmkid -d` runs `WIFI_SCAN_ACTIVE_EAPOL`, which is **not** in that gate
 *        list, so it hops every 2 s no matter what the setting says
 *        ([unhoppableHopping]). A real run on our own AP lost the client's M2 this
 *        way: the board was on the right channel for the deauth and elsewhere when
 *        the client re-associated.
 *      - `sniffpmkid -d -l` runs `WIFI_SCAN_ACTIVE_LIST_EAPOL`, which hops through
 *        `channelHop(true)` (WiFiScan.cpp:13040-13045) and only visits the channels of
 *        SELECTED APs, so a pinned selection keeps the radio where it belongs. That is
 *        why the app's pinned capture uses `-l`.
 *  * **A leftover selection blinds the sniffer.** `eapolSnifferCallback` asks
 *    `filterActive()`, and when *any* AP is selected it returns for every frame whose
 *    AP is not selected (WiFiScan.cpp:10616-10623) — before `eapol_frames++`
 *    (WiFiScan.cpp:10637) and before the frame is handed to the pcap buffer
 *    (WiFiScan.cpp:10692). Selection is not reset when a scan stops (only
 *    `WIFI_SCAN_SIG_STREN` does that, WiFiScan.cpp:3252-3260), so one earlier targeted
 *    run quietly disables every later untargeted capture.
 *  * **A scan verb can ignore `-c` completely.** Apart from `sniffpmkid`, every scan command
 *    is routed through `CommandLine::startScanFromCLI`, which reads none of its arguments —
 *    it prints a line and calls `StartScan(mode)`. So `sniffbeacon -c 6` starts a beacon scan
 *    on whatever channel the board already had. The channel has to be set with
 *    `channel -s <n>`, and it only holds for the modes the `ChanHop` setting gates
 *    (`WIFI_SCAN_AP/PROBE/DEAUTH/EAPOL/RAW_CAPTURE/PACKET_RATE/SIG_STREN`,
 *    WiFiScan.cpp:10997-11006); `scanall`, `sniffsae`, `sniffpwn`, `sniffpinescan` and
 *    `sniffmultissid` hop regardless.
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
     * True for `sniffpmkid -d` without `-l`: the active sniff runs
     * `WIFI_SCAN_ACTIVE_EAPOL`, a mode the `ChanHop` setting does not gate
     * (WiFiScan.cpp:10997-11006), so the board hops away from a pinned `-c` channel
     * every 2 s and no setting can stop it. The app warns instead of silently
     * capturing on the wrong channel, and [needsEmptySelection] plus the pinned-list
     * flow (`-l` with a selection) is what actually keeps it on channel.
     */
    fun unhoppableHopping(command: String): Boolean {
        val c = command.trim()
        return c.startsWith("sniffpmkid") && c.contains("-d") && !c.contains("-l") &&
            channelArg.containsMatchIn(c)
    }

    /**
     * Scan verbs that go through `CommandLine::startScanFromCLI`, which never looks at the
     * arguments it is given — it only prints a message and calls `StartScan(mode)`. So a
     * `-c` on these commands is parsed out of the line and thrown away: the board starts on
     * whatever channel it already had.
     */
    private val channelBlindScans = setOf(
        "sniffbeacon", "sniffprobe", "sniffdeauth", "sniffraw", "sniffsae",
        "sniffpwn", "sniffpinescan", "sniffmultissid", "scanall",
    )

    /**
     * Scan modes whose hop loop *is* gated by the `ChanHop` setting
     * (`WiFiScan::channelHop`, the early return at WiFiScan.cpp:10997-11006). For these,
     * `channel -s <n>` plus `ChanHop` off really does hold one channel — which is how the
     * app pins a sniff whose own verb ignores `-c`.
     */
    private val hopIsGated = setOf("sniffbeacon", "sniffprobe", "sniffdeauth", "sniffraw")

    /**
     * Scan modes that hop whatever the setting says (their mode is not in that gate list):
     * `scanall` (WIFI_SCAN_AP_STA), `sniffsae`, `sniffpwn`, `sniffpinescan`,
     * `sniffmultissid`. A pinned channel cannot survive them, and saying so is better than
     * showing a capture of the wrong air.
     */
    private val hopIsUngated = setOf("scanall", "sniffsae", "sniffpwn", "sniffpinescan", "sniffmultissid")

    /** True when the command names a channel that this scan verb's own parser would drop. */
    fun channelFlagIgnored(command: String): Boolean {
        val c = command.trim()
        return channelBlindScans.contains(c.substringBefore(' ')) && channelArg.containsMatchIn(c)
    }

    /**
     * True when the app can honour a `-c` written on a channel-blind scan by pinning the
     * radio instead (`channel -s <n>` + `ChanHop` off): the mode's hopping is gated, so the
     * board stays put.
     */
    fun channelPinWillHold(command: String): Boolean {
        val c = command.trim()
        return hopIsGated.contains(c.substringBefore(' ')) && channelArg.containsMatchIn(c)
    }

    /** True when a `-c` on this command cannot be honoured at all: the mode always hops. */
    fun alwaysHops(command: String): Boolean {
        val c = command.trim()
        return hopIsUngated.contains(c.substringBefore(' ')) && channelArg.containsMatchIn(c)
    }

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
