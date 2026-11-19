package com.marauder.mobile.data

import com.marauder.mobile.protocol.DeviceMessage

/**
 * The firmware addresses access points and stations by **position in a list that
 * keeps changing**: `jsonlist a` prints `i` = the row's current slot, and any scan
 * (or `clearlist`) rebuilds that list, so the same network can sit in a different
 * slot seconds later. `jsonlist c` prints `ap` = the slot of the AP it was
 * iterating while emitting the row, and `select -a N` addresses a slot, not a
 * network — so a stale index silently means "some other network".
 *
 * That is the whole reason this class exists: the app's only stable identity is the
 * BSSID, so every snapshot is kept here keyed by BSSID, together with a generation
 * counter that tells callers whether the slot they are about to use is still the
 * slot it came from.
 */
class ScanLedger {

    /** One access point as the app pins it: identity first, slot second. */
    data class ApPin(
        val bssid: String,
        val essid: String,
        val channel: Int,
        val index: Int,
        val selected: Boolean,
        val rssi: Int,
    )

    /** Bumped whenever the BSSID→slot map changed, i.e. whenever an old index is now wrong. */
    var apGeneration: Int = 0
        private set

    /** Latest access-point snapshot, in firmware slot order. */
    var aps: List<ApPin> = emptyList()
        private set

    /** Clients keyed by the BSSID of the AP they belong to (never by a drifting slot). */
    var stationsByBssid: Map<String, List<DeviceMessage.Sta>> = emptyMap()
        private set

    /** [apGeneration] that was in force when the client rows were mapped. */
    var stationGeneration: Int = -1
        private set

    /** The slot→BSSID map the client rows were resolved against, kept for exports. */
    var stationSlots: Map<Int, String> = emptyMap()
        private set

    /** True when no AP-list change happened after the clients were mapped, so the
     *  client→AP attribution provably came from the same firmware snapshot. */
    val stationsTrusted: Boolean
        get() = stationGeneration >= 0 && stationGeneration == apGeneration

    /**
     * Record a `jsonlist a` commit.
     *
     * @return `true` when the BSSID→slot map changed, i.e. every index the caller
     *         kept from the previous snapshot must be discarded.
     */
    fun commitAps(rows: List<DeviceMessage.Ap>): Boolean {
        val pins = rows.map {
            ApPin(
                bssid = normalizeMac(it.bssid),
                essid = it.essid,
                channel = it.channel,
                index = it.index,
                selected = it.selected,
                rssi = it.rssi,
            )
        }
        val drifted = pins.map { it.bssid to it.index } != aps.map { it.bssid to it.index }
        aps = pins
        if (drifted) apGeneration++
        return drifted
    }

    /**
     * Record a `jsonlist c` commit. The `ap` field on each row is resolved against
     * the AP snapshot currently held, which is the same snapshot the caller should
     * have fetched immediately before the list (see [requestVerifiedClientList]).
     */
    fun commitStations(rows: List<DeviceMessage.Sta>) {
        val bySlot = aps.associate { it.index to it.bssid }
        val grouped = LinkedHashMap<String, MutableList<DeviceMessage.Sta>>()
        for (row in rows) {
            val owner = bySlot[row.ap] ?: continue
            grouped.getOrPut(owner) { ArrayList() }.add(row)
        }
        stationsByBssid = grouped
        stationSlots = bySlot
        stationGeneration = apGeneration
    }

    fun pin(bssid: String): ApPin? = aps.firstOrNull { it.bssid == normalizeMac(bssid) }

    /** The firmware slot this network occupies **right now**, or null when the board
     *  no longer lists it (a scan cleared or forgot it). */
    fun indexOf(bssid: String): Int? = pin(bssid)?.index

    fun bssidAt(index: Int): String? = aps.firstOrNull { it.index == index }?.bssid

    fun selectedBssids(): Set<String> = aps.filter { it.selected }.map { it.bssid }.toSet()

    fun stationsOf(bssid: String): List<DeviceMessage.Sta> =
        stationsByBssid[normalizeMac(bssid)].orEmpty()

    /** Live slot of a client MAC, for `select -c <slot>`; null when it left the list. */
    fun stationIndex(mac: String): Int? {
        val want = normalizeMac(mac)
        return stationsByBssid.values.asSequence().flatten().firstOrNull { normalizeMac(it.mac) == want }?.index
    }

    /** BSSID the firmware currently believes this client belongs to. */
    fun stationOwner(mac: String): String? {
        val want = normalizeMac(mac)
        return stationsByBssid.entries.firstOrNull { e -> e.value.any { normalizeMac(it.mac) == want } }?.key
    }

    fun clear() {
        aps = emptyList()
        stationsByBssid = emptyMap()
        stationSlots = emptyMap()
        stationGeneration = -1
        apGeneration = 0
    }

    companion object {
        /** MACs arrive from the firmware upper-cased; compare case-insensitively. */
        fun normalizeMac(mac: String): String = mac.trim().uppercase()
    }
}
