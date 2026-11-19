package com.marauder.mobile.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Keeps the playbooks honest. A playbook is a promise about what the board will do, so the
 * commands it shows have to be commands this firmware answers, its placeholders have to be
 * ones the app can actually fill, and its capability requirements have to name real caps —
 * otherwise the screen advertises a job the board cannot perform.
 */
class ScenarioSanityTest {

    @Test
    fun playbookIdsAreUnique() {
        val ids = Scenarios.all.map { it.id }
        assertEquals("duplicate playbook ids", ids.size, ids.distinct().size)
        assertTrue("ids must be url/menu safe", ids.all { it.matches(Regex("[a-z0-9-]+")) })
    }

    /** Every firmware line a playbook shows must be a verb the firmware dispatches. */
    @Test
    fun everyCommandUsesAFirmwareVerb() {
        val commands = Scenarios.all.flatMap { s ->
            s.steps.mapNotNull { it.command } + listOfNotNull(s.command.ifBlank { null }) + s.pre
        }
        val bad = commands.filter { cmd ->
            val head = cmd.trim().substringBefore(' ')
            head !in FirmwareCommands.verbs
        }.distinct()
        assertEquals("commands the firmware does not answer: $bad", emptyList<String>(), bad)
    }

    @Test
    fun noPlaybookUsesAVerbTheFirmwareHasCommentedOut() {
        val commands = Scenarios.all.flatMap { s ->
            s.steps.mapNotNull { it.command } + listOfNotNull(s.command.ifBlank { null }) + s.pre
        }
        val dead = commands.filter { cmd -> FirmwareCommands.neverSend.any { cmd.trim().startsWith(it) } }
        assertEquals("verbs the firmware does not dispatch: $dead", emptyList<String>(), dead)
    }

    /**
     * `{ap}` and `{ch}` are the only placeholders the app knows how to fill, and it only
     * fills them when the playbook asks for a network. A placeholder on a playbook with no
     * target would be a command sent with a hole in it.
     */
    @Test
    fun placeholdersOnlyAppearWhereTheAppCanFillThem() {
        val offenders = Scenarios.all.filter { scenario ->
            val used = Scenarios.placeholders(scenario.command)
            used.any { it != "{ap}" && it != "{ch}" } ||
                (used.isNotEmpty() && !Scenarios.needsTarget(scenario))
        }.map { it.id }
        assertEquals("playbooks whose placeholders cannot be resolved: $offenders", emptyList<String>(), offenders)
    }

    /** A run that needs a selection must pin it; a passive run must not be pinned. */
    @Test
    fun runModeMatchesWhatTheCommandNeeds() {
        val pinnedWithoutTarget = Scenarios.all
            .filter { it.run == ScenarioRun.PINNED_MISSION && !Scenarios.needsTarget(it) }
            .map { it.id }
        assertEquals("pinned runs with nothing to pin: $pinnedWithoutTarget", emptyList<String>(), pinnedWithoutTarget)

        val commandless = Scenarios.all
            .filter { it.run != ScenarioRun.NAVIGATE && it.command.isBlank() }
            .map { it.id }
        assertEquals("runs with no command to send: $commandless", emptyList<String>(), commandless)

        val navless = Scenarios.all
            .filter { it.run == ScenarioRun.NAVIGATE && it.navigate == null }
            .map { it.id }
        assertEquals("hand-over playbooks with nowhere to go: $navless", emptyList<String>(), navless)
    }

    /** Every firmware line a playbook shows must also satisfy the app's own capture rules. */
    @Test
    fun capabilityRequirementsNameCapsTheBoardReports() {
        // `jsoninfo` is where caps come from; the caps used here must be ones the firmware
        // actually emits (JsonSerial.cpp), otherwise the playbook is hidden forever.
        val emitted = setOf(
            "wifi", "capstream", "bt", "gps", "sd", "screen",
            "remoteid", "foxhunt", "recon", "csi", "proto3",
        )
        val unknown = Scenarios.all.flatMap { it.requiresCaps }
            .filter { it !in emitted }
            .distinct()
        assertEquals("capabilities this firmware never reports: $unknown", emptyList<String>(), unknown)
    }

    @Test
    fun everyPlaybookSaysWhatItProduces() {
        val thin = Scenarios.all.filter { it.outcome.isBlank() || it.goal.isBlank() || it.steps.size < 2 }.map { it.id }
        assertEquals("playbooks without a goal, an outcome or steps: $thin", emptyList<String>(), thin)
    }

    @Test
    fun channelDependentPlaybooksSayWhatTheRadioCannotHear() {
        // Anything that runs on one channel has to say so: the board is 2.4 GHz only, and a mode
        // that does not hop hears exactly where it sits, so an empty result is a radio fact that
        // the playbook owns, not a mystery the user has to debug.
        val silent = Scenarios.all.filter { s ->
            val text = (s.command + " " + s.steps.joinToString(" ") { it.command ?: "" })
            // A channel is being addressed when the command names {ch}, carries `-c <number>`,
            // or ends in a bare `-c` (the firmware's "only what is on the selected list" form).
            // Other `-c` verbs (evilportal -c start) mean something else and are not in scope.
            val channelDependent = Regex("""\{ch\}|-c\s+\d|\s-c$""").containsMatchIn(text)
            channelDependent && (s.warn.isBlank() || !s.warn.contains("channel"))
        }.map { it.id }
        assertEquals("playbooks that address a channel without saying so: $silent", emptyList<String>(), silent)

        val band = Scenarios.all.filter { it.warn.contains("2.4 GHz") }.map { it.id }
        assertTrue("playbooks that promise 2.4 GHz coverage must also say 5 GHz is inaudible", band.isNotEmpty())
        val halfTruth = Scenarios.all.filter { s ->
            s.warn.contains("2.4 GHz") && !s.warn.contains("5 GHz") && !s.warn.contains("above 14")
        }.map { it.id }
        assertEquals("one-sided band warnings: $halfTruth", emptyList<String>(), halfTruth)
    }

    /**
     * A verb only counts as covered if a playbook says why it is not in one.
     *
     * The catalog already reaches every verb, but a catalog entry is a button, not a job: the verbs
     * that take a list index or a mode are exactly the ones a person cannot use without knowing what
     * the number means. So each of them must either appear as a step of some playbook (with the
     * screen that shows the list its indices come from next to it), or be listed here with the
     * reason it is left out — a reason the reader can disagree with, unlike a gap nobody notices.
     *
     * Only the CLI verbs are checked. The JSON verbs are the app's own protocol: `jsonlist` and
     * `jsonmode` run on every connection, so putting them in a playbook would describe plumbing,
     * not a job the user asked for.
     */
    @Test
    fun everyVerbIsSpelledOutInAPlaybookOrSaysWhyItIsNot() {
        val shown = Scenarios.all.flatMap { s ->
            s.steps.mapNotNull { it.command } + listOfNotNull(s.command.ifBlank { null }) + s.pre
        }.map { it.trim().substringBefore(' ') }.toSet()

        val missing = (FirmwareCommands.cli.map { it.name } - shown - PLAYBOOK_LESS.keys).sorted()
        assertEquals("verbs no playbook mentions and none explains: $missing", emptyList<String>(), missing)

        val stale = PLAYBOOK_LESS.keys.filter { it !in FirmwareCommands.verbs }.sorted()
        assertEquals("reasons given for verbs that are not in the census: $stale", emptyList<String>(), stale)
    }

    companion object {
        /** Verb -> why no playbook spells it out. Every CLI verb not named in a step belongs here. */
        private val PLAYBOOK_LESS: Map<String, String> = emptyMap()
    }

    @Test
    fun instantiateFillsTheLiveSlotAndChannelOnly() {
        val cmd = Scenarios.instantiate("sniffpmkid -c {ch} -d -l", slot = 4, channel = 11)
        assertEquals("sniffpmkid -c 11 -d -l", cmd)
        // No slot/channel invented when there is no picked network: the placeholders stay,
        // and MarauderViewModel refuses to send a command that still has one.
        val unfilled = Scenarios.instantiate("attack -t deauth -c {ap}", null, 0)
        assertEquals("attack -t deauth -c {ap}", unfilled)
        assertTrue(Scenarios.placeholders(unfilled).contains("{ap}"))
    }

    @Test
    fun capsFilteringHidesOnlyWhatTheBoardCannotDo() {
        val capable = listOf(
            "wifi", "capstream", "bt", "gps", "sd", "screen",
            "remoteid", "foxhunt", "recon", "csi", "proto3",
        )
        val full = Scenarios.forCaps(capable)
        assertEquals("a capable board sees every playbook", Scenarios.all.size, full.size)
        val plain = Scenarios.forCaps(listOf("wifi"))
        assertTrue(
            "a WiFi-only board must not be shown the capture or Bluetooth playbooks: ${plain.map { it.id }}",
            plain.none { it.requiresCaps.isNotEmpty() && !it.requiresCaps.all { c -> c == "wifi" } },
        )
        assertNotEquals("the WiFi-only list must be shorter", full.size, plain.size)
        assertNull("unknown playbook", Scenarios.get("no-such-thing"))
    }
}
