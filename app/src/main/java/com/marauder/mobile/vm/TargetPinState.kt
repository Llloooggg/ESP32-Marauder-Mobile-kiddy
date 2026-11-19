package com.marauder.mobile.vm

/**
 * State of the app's attempt to pin a targeted operation to one access point.
 *
 * The firmware cannot be told "attack this BSSID": it attacks what is *selected*,
 * and selection is a list slot that any scan can move. So the app pins the
 * selection, reads the board's list back, and only then starts anything — and this
 * is what the target screen shows while that happens. A targeted action is
 * supposed to look like a promise, not like a guess.
 */
sealed class TargetPinState {

    /** Nothing pinned; no targeted action armed. */
    data object Idle : TargetPinState()

    /** Selection commands sent, the board's answer being checked. */
    data class Pinning(val bssid: String, val essid: String, val byEssid: Boolean) : TargetPinState()

    /**
     * The board confirmed exactly this network is selected.
     *
     * [duplicates] are other BSSIDs that carry the same SSID and are therefore
     * selected too — the app cannot separate them by name, and says so rather than
     * implying a single-AP attack.
     */
    data class Pinned(
        val bssid: String,
        val essid: String,
        val selected: Set<String>,
        val duplicates: Set<String>,
        val byEssid: Boolean,
    ) : TargetPinState()

    /** The action was refused and nothing was transmitted. */
    data class Refused(val bssid: String, val reason: String) : TargetPinState()
}
