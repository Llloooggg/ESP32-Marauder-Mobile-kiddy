package com.marauder.mobile.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Guards for the catalog: every command we expose must be a verb the firmware
 * actually parses, capability gating must work, and the policy tiers must line up
 * with how dangerous the command is.
 */
class CatalogPolicyTest {

    /** Command heads verified against CommandLine.h / CommandLine.cpp. */
    private val firmwareVerbs = setOf(
        "add", "analyzer", "arpscan", "attack", "blespam", "brightness", "channel", "clearlist",
        "clonestamac", "cloneapmac", "csimotion", "evilportal", "findmy", "foxhunt", "geofence",
        "gps", "gpsdata", "gpspoi", "gpstracker", "info", "join", "karma", "led", "list", "load",
        "ls", "mactrack", "nmea", "packetcount", "pingscan", "portscan", "randapmac", "randstamac",
        "reboot", "recon", "remoteid", "save", "scanall", "scansta", "select", "settings",
        "sniffbeacon", "sniffbt", "sniffdeauth", "sniffmultissid", "sniffpinescan", "sniffpmkid",
        "sniffprobe", "sniffpwn", "sniffraw", "sniffsae", "sniffskim", "spoofat", "stopscan",
        "ssid", "update", "upload", "wardrive", "wardrivepoi",
        // App-protocol extensions answered by the JSON layer, not the CLI parser.
        "jsoninfo", "jsonstatus", "jsonlist",
    )

    private val allItems: List<MenuItem> = Catalog.screens.getValue(Catalog.ROOT).items +
        Catalog.screens.values.flatMap { it.items }

    @Test
    fun everySendCommandUsesAFirmwareVerb() {
        val unknown = allItems.mapNotNull { (it.action as? MenuAction.Send)?.command }
            .map { it.trim().substringBefore(' ') }
            .filter { it !in firmwareVerbs }
            .distinct()
        assertEquals("commands not present in the firmware: $unknown", emptyList<String>(), unknown)
    }

    @Test
    fun capabilityGatedEntriesAppearOnlyWhenTheBoardReportsTheCap() {
        val device = Catalog.screens.getValue("device")
        val gated = device.items.filter { it.requiresCaps.isNotEmpty() }
        assertTrue("expected capability-gated device entries", gated.isNotEmpty())

        assertEquals(0, device.itemsFor(emptyList()).count { it.requiresCaps.isNotEmpty() })
        assertEquals(gated.size, device.itemsFor(listOf("sd", "recon", "remoteid")).count { it.requiresCaps.isNotEmpty() })
        // Unknown capabilities (board never answered jsoninfo) must not hide anything.
        assertEquals(device.items.size, device.itemsFor(null).size)
    }

    @Test
    fun highTierIsReserveForActiveInterferenceAndAlwaysDangerous() {
        val high = allItems.filter { it.tier == Tier.HIGH }
        assertTrue(high.isNotEmpty())
        assertTrue("HIGH entries must be marked dangerous", high.all { it.dangerous })
        assertTrue(
            "the lab section may only hold spam/spoof transmitters: ${high.map { it.title }}",
            high.all {
                val head = (it.action as? MenuAction.Send)?.command?.trim()?.substringBefore(' ')
                head == "blespam" || head == "spoofat"
            },
        )
        assertTrue(
            "a dangerous entry can never be SAFE",
            allItems.filter { it.dangerous }.none { it.tier == Tier.SAFE },
        )
    }

    @Test
    fun handshakeSniffingOffersBothPassiveAndActiveForms() {
        val sniffers = Catalog.screens.getValue("wifi_sniffers").items.filter { it.title.contains("EAPOL", ignoreCase = true) || it.title.contains("PMKID", ignoreCase = true) }
        assertEquals(2, sniffers.size)
        assertTrue(sniffers.any { (it.action as MenuAction.Send).command == "sniffpmkid" && !it.dangerous })
        assertTrue(sniffers.any { (it.action as MenuAction.Send).command == "sniffpmkid -d" && it.dangerous })
    }

    @Test
    fun deauthFloodIsLabelledAsDoNotCapture() {
        val deauth = allItems.first { (it.action as? MenuAction.Send)?.command == "attack -t deauth -c" }
        assertTrue(deauth.title.contains("DoS", ignoreCase = true))
    }
}
