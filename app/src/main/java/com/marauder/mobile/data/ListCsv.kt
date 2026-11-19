package com.marauder.mobile.data

import com.marauder.mobile.protocol.DeviceMessage

/**
 * Renders the firmware's structured lists (`jsonlist a|s|c|i|p|t|d`, plus the
 * Evil Portal credential stream) as CSV so they become library artifacts that
 * open in a spreadsheet or upload to WiGLE as-is.
 */
object ListCsv {

    fun aps(rows: List<DeviceMessage.Ap>): String = build(
        listOf("index", "essid", "bssid", "channel", "rssi", "security", "wps", "stations", "packets", "selected"),
        rows,
    ) { r ->
        listOf(
            r.index.toString(), r.essid, r.bssid, r.channel.toString(), r.rssi.toString(),
            Security.label(r.sec), r.wps.toString(), r.stations.toString(), r.packets.toString(),
            r.selected.toString(),
        )
    }

    fun stations(rows: List<DeviceMessage.Sta>): String = build(
        listOf("index", "mac", "ap_index", "packets", "selected"), rows,
    ) { r -> listOf(r.index.toString(), r.mac, r.ap.toString(), r.packets.toString(), r.selected.toString()) }

    fun probes(rows: List<DeviceMessage.Probe>): String = build(
        listOf("index", "probe_ssid", "requests", "selected"), rows,
    ) { r -> listOf(r.index.toString(), r.essid, r.requests.toString(), r.selected.toString()) }

    fun ips(rows: List<DeviceMessage.Ip>): String = build(listOf("index", "ip"), rows) { r ->
        listOf(r.index.toString(), r.ip)
    }

    fun ssids(rows: List<DeviceMessage.SsidRow>): String = build(
        listOf("index", "essid", "channel", "selected"), rows,
    ) { r -> listOf(r.index.toString(), r.essid, r.channel.toString(), r.selected.toString()) }

    fun airtags(rows: List<DeviceMessage.Airtag>): String = build(
        listOf("index", "mac", "rssi", "selected"), rows,
    ) { r -> listOf(r.index.toString(), r.mac, r.rssi.toString(), r.selected.toString()) }

    /** Remote ID (drone) records: UAS id, operator, position (decimal degrees), motion. */
    fun drones(rows: List<DeviceMessage.Rid>): String = build(
        listOf("index", "mac", "uas_id", "operator", "ua_type", "lat", "lon",
            "alt_m", "speed_mps", "direction_deg", "rssi", "packets"),
        rows,
    ) { r ->
        listOf(
            r.index.toString(), r.mac, r.uas, r.op, r.uaType.toString(),
            if (r.hasLocation) r.latitude.toString() else "",
            if (r.hasLocation) r.longitude.toString() else "",
            r.altMeters.toString(), r.speedMps.toString(), r.directionDeg.toString(),
            r.rssi.toString(), r.packets.toString(),
        )
    }

    /** Configured geofences (`jsonlist g`), 1..5 with radius in miles. */
    fun geofences(rows: List<DeviceMessage.Fence>): String = build(
        listOf("index", "enabled", "lat", "lon", "radius_miles", "name"), rows,
    ) { f ->
        listOf(f.index.toString(), f.enabled.toString(), f.lat.toString(), f.lon.toString(),
            f.radiusMiles.toString(), f.name)
    }

    /** Evil Portal submissions — only ever credentials submitted to the operator's own page. */
    fun creds(rows: List<DeviceMessage.Cred>): String = build(listOf("user", "password"), rows) { r ->
        listOf(r.user, r.pass)
    }

    private fun <T> build(header: List<String>, rows: List<T>, row: (T) -> List<String>): String =
        buildString {
            appendLine(header.joinToString(",") { quote(it) })
            rows.forEach { r -> appendLine(row(r).joinToString(",") { quote(it) }) }
        }

    private fun quote(s: String): String =
        if (s.any { it == ',' || it == '"' || it == '\n' }) "\"" + s.replace("\"", "\"\"") + "\"" else s
}
