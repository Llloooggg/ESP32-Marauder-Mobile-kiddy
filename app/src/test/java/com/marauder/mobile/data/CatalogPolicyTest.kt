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

    /** Command heads verified against CommandLine.h / CommandLine.cpp (see [FirmwareCommands]). */
    private val firmwareVerbs: Set<String> = FirmwareCommands.verbs

    private val allItems: List<MenuItem> = Catalog.screens.getValue(Catalog.ROOT).items +
        Catalog.screens.values.flatMap { it.items }

    /** The verb a catalog entry sends, whether the command is fixed or takes one argument. */
    private fun headOf(item: MenuItem): String? = when (val a = item.action) {
        is MenuAction.Send -> a.command.trim().substringBefore(' ')
        is MenuAction.Arg -> a.base.trim().substringBefore(' ')
        is MenuAction.OpenAnalyzer -> a.command.trim().substringBefore(' ')
        else -> null
    }

    @Test
    fun everySendCommandUsesAFirmwareVerb() {
        val unknown = allItems.mapNotNull { headOf(it) }
            .filter { it !in firmwareVerbs }
            .distinct()
        assertEquals("commands not present in the firmware: $unknown", emptyList<String>(), unknown)
    }

    /**
     * The firmware has these verbs commented out, so its CLI never dispatches them. If any
     * command the app can build used one, the user would get a silent no-op instead of a
     * result — and this test would say so.
     */
    @Test
    fun verbsTheFirmwareHasCommentedOutAreNeverSent() {
        val built = allItems.mapNotNull { (it.action as? MenuAction.Send)?.command } +
            FirmwareCommands.dynamic.values +
            listOf(
                FirmwareCommands.analyzer("wifi"),
                FirmwareCommands.sniffPmkid(6, deauth = true, listOnly = true),
                FirmwareCommands.stopscan(force = true),
            )
        val dead = built.filter { cmd -> FirmwareCommands.neverSend.any { verb -> cmd.trim().startsWith(verb) } }
        assertEquals("commands the firmware does not dispatch: $dead", emptyList<String>(), dead)
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
            "HIGH is reserved for spam/spoof transmitters, not for anything merely targeted: ${high.map { it.title }}",
            high.all {
                val head = headOf(it)
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

    /**
     * Nothing about a command hides it: an entry may only be absent because the connected
     * board does not advertise the capability it needs. If someone reintroduces a tier,
     * safety or settings gate over the catalog, this fails — the consent model here is the
     * first-launch banner, so a second invisible permission layer would only make the
     * firmware's own menu tree unreachable.
     */
    @Test
    fun entriesAreHidOnlyByMissingFirmwareCapabilities() {
        val caps = allItems.flatMap { it.requiresCaps }.distinct()
        Catalog.screens.values.forEach { screen ->
            assertEquals("${screen.id}: a capable board must expose every entry it has",
                screen.items.size, screen.itemsFor(caps).size)
            assertEquals("${screen.id}: an unknown board (never answered jsoninfo) must hide nothing",
                screen.items.size, screen.itemsFor(null).size)
        }
        assertTrue(
            "every tier value must stay reachable on one board",
            Tier.entries.all { tier ->
                Catalog.screens.values.any { it.itemsFor(caps).any { item -> item.tier == tier } }
            },
        )
    }
}
