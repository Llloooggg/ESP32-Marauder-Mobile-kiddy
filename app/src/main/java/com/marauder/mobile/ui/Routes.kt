package com.marauder.mobile.ui

import android.net.Uri
import com.marauder.mobile.data.AnalyzerKind
import com.marauder.mobile.data.ListType

/**
 * Route map, and next to it the one rule that belongs there: which screens work with no board
 * attached.
 *
 * The product flow is home → scan → ap index → mission id; the firmware command tree stays reachable
 * from Home's toolbox, so no firmware verb becomes unreachable.
 *
 * The rule about the link is here because the other half of this app is about files the phone already
 * has: a capture, a wardrive track, a set of extracted hashes, the wordlists to attack them. None of
 * that asks a board anything. A person standing at a table with last week's capture and no cable should
 * not be shown a wall - and the previous arrangement was exactly that: no link meant the app put them
 * on the connect screen and nowhere else, so the library, the wordlists and the cracker were
 * unreachable, and even a board that was already plugged in had to be bounced through that screen on
 * the way to the app.
 *
 * What needs the link keeps needing it: those screens either say so themselves or are sent to the
 * connect screen, which states what is missing. Anything not listed below counts as board-only, on
 * purpose: a route nobody thought about gets the honest answer rather than a silent half-screen.
 */
internal object Routes {
    const val CONNECT = "connect"
    const val HOME = "home"
    const val SCAN = "scan"
    const val ARTIFACTS = "artifacts"
    const val ARTIFACT = "artifact"
    const val WORDLISTS = "wordlists"
    const val CRACK = "crack"
    const val MISSION = "mission"
    const val AP = "ap"
    const val MENU = "menu"
    const val LIST = "list"
    const val CONSOLE = "console"
    const val ANALYZER = "analyzer"
    const val LIVE = "live"
    const val ABOUT = "about"
    const val SETTINGS = "settings"
    const val BOARD_SETTINGS = "board_settings"
    const val POSTURE = "posture"
    const val SCENARIOS = "scenarios"
    const val FLASH = "flash"
    const val EVIL_PORTAL = "evil_portal_screen"

    fun menu(id: String) = "$MENU/$id"
    fun ap(bssid: String) = "$AP/${Uri.encode(bssid)}"
    fun mission(id: Long) = "$MISSION/$id"
    fun artifact(name: String) = "$ARTIFACT/${Uri.encode(name)}"
    fun crack(name: String) = "$CRACK/${Uri.encode(name)}"
    fun list(type: ListType) = "$LIST/${type.name}"
    fun analyzer(kind: AnalyzerKind, command: String) = "$ANALYZER/${kind.name}/${Uri.encode(command)}"
    fun live(title: String, command: String) = "$LIVE/${Uri.encode(title)}/${Uri.encode(command)}"

    /**
     * The patterns of screens that ask the board nothing - the route patterns as [NavHost] declares
     * them, not the filled-in URLs, so the comparison is against something stable.
     *
     * `posture` is deliberately absent: that screen offers live commands and a scan, so it is about
     * a running link. The flasher is not here either, and navigation makes a documented exception for
     * it: it holds the port itself, so it runs while the serial session is down on purpose.
     */
    private val offlinePatterns = setOf(
        CONNECT,
        HOME,
        ARTIFACTS,
        "$ARTIFACT/{name}",
        WORDLISTS,
        "$CRACK/{name}",
        SETTINGS,
        ABOUT,
    )

    /** Whether this screen has nothing to do without a board. Unknown patterns count as board-only. */
    fun needsBoard(routePattern: String?): Boolean =
        routePattern != null && routePattern !in offlinePatterns

    /** The other half of the same statement, for callers that phrase the question positively. */
    fun worksWithoutBoard(routePattern: String?): Boolean =
        routePattern != null && routePattern in offlinePatterns

    /**
     * The name to put on the notice that replaces a board-only screen while the link is down. Without
     * it that screen has no title and no way to know which screen it was told about.
     *
     * Matched on the first path segment, so `menu` and `menu/{id}` are the same screen. Anything not
     * named here falls back to a wording that does not claim to know the screen.
     */
    fun headingFor(routePattern: String?): String {
        if (routePattern == null) return "This screen"
        return when (routePattern.substringBefore('/')) {
            SCAN -> "Scan"
            MISSION -> "Mission"
            AP -> "Access point"
            MENU -> "Commands"
            LIST -> "Lists"
            CONSOLE -> "Console"
            ANALYZER -> "Analyzer"
            LIVE -> "Live output"
            BOARD_SETTINGS -> "Board settings"
            POSTURE -> "Network posture"
            SCENARIOS -> "Playbooks"
            EVIL_PORTAL -> "Evil portal"
            FLASH -> "Flash firmware"
            else -> "This screen"
        }
    }
}
