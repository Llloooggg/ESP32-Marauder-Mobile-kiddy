package com.marauder.mobile.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The coverage guard: the app exposes the firmware's whole command surface, and nothing
 * outside it. [FirmwareCommands] is the census (taken from the verb constants in
 * `CommandLine.h` and the dispatch chain in `CommandLine.cpp` of the json-serial tree),
 * and this test is what turns that census from a note into a guarantee.
 */
class FirmwareCoverageTest {

    private val allItems: List<MenuItem> = Catalog.screens.values.flatMap { it.items }

    /** Verbs a catalog entry can send, fixed or argument-prompted. */
    private val catalogHeads: Set<String> = allItems.mapNotNull { item ->
        when (val a = item.action) {
            is MenuAction.Send -> a.command.trim().substringBefore(' ')
            is MenuAction.Arg -> a.base.trim().substringBefore(' ')
            is MenuAction.OpenAnalyzer -> a.command.trim().substringBefore(' ')
            else -> null
        }
    }.toSet()

    @Test
    fun everyFirmwareVerbIsReachableFromTheApp() {
        val reachable = catalogHeads + FirmwareCommands.dynamic.keys + FirmwareCommands.appInternal.keys
        val missing = FirmwareCommands.verbs - reachable
        assertEquals(
            "firmware verbs no UI path can send (add a catalog entry, or a builder + a dynamic entry): $missing",
            emptySet<String>(),
            missing,
        )
    }

    /**
     * The census count is pinned on purpose: when the firmware adds or drops a verb, this
     * fails and the app has to look at the new command instead of quietly ignoring it.
     * 62 CLI verbs + the 5 answered by the JSON layer. (`gpstracker` is not one of them: the
     * firmware prints it in `help` and never parses it, and the app answers that word itself.)
     */
    @Test
    fun theCensusCoversTheWholeDispatchChain() {
        assertEquals("CLI verb census", 62, FirmwareCommands.cli.size)
        assertEquals("JSON verb census", 5, FirmwareCommands.json.size)
        assertEquals("total verbs", 67, FirmwareCommands.verbs.size)
        assertTrue(
            "every verb needs the firmware's own syntax note",
            (FirmwareCommands.cli + FirmwareCommands.json).all { it.syntax.isNotBlank() && it.syntax.startsWith(it.name) },
        )
        assertEquals(
            "no verb may be listed twice",
            FirmwareCommands.cli.size,
            FirmwareCommands.cli.map { it.name }.distinct().size,
        )
    }

    @Test
    fun dynamicEntriesAreAddressedBySlotOrArgumentNotGuessedText() {
        val mismatched = FirmwareCommands.dynamic.filter { (verb, command) ->
            command.trim().substringBefore(' ') != verb
        }
        assertEquals("dynamic sample commands whose head is not their verb: $mismatched", emptyMap<String, String>(), mismatched)
        assertTrue(
            "slot-resolved commands must carry the slot they address",
            FirmwareCommands.dynamic.values.all { it.isNotBlank() },
        )
    }

    @Test
    fun commentedOutFirmwareVerbsAreNotInTheCensus() {
        // `scansta`/`btwardrive` exist in the firmware source only as comments, so the CLI
        // never parses them. The app must not carry them either.
        assertTrue(
            "verbs the firmware has commented out must stay out of the census: ${FirmwareCommands.neverSend}",
            FirmwareCommands.neverSend.none { it in FirmwareCommands.verbs },
        )
    }

    /**
     * The app answers some words itself, and they look exactly like firmware commands. Two things
     * have to be true for that to stay honest: the word is not counted as a firmware verb (or the app
     * would be claiming the board does it), and the note says what the app does instead — including,
     * for `gpstracker`, the firmware line that actually starts the board's own tracker.
     */
    @Test
    fun appAnsweredWordsAreNotPassedOffAsFirmwareVerbs() {
        val claimed = FirmwareCommands.appOnly.keys.filter { it in FirmwareCommands.verbs }
        assertEquals("app-answered words listed as firmware verbs: $claimed", emptyList<String>(), claimed)

        val undocumented = FirmwareCommands.appOnly.filter { (_, whatItDoes) -> whatItDoes.isBlank() }
        assertEquals("app-answered words with no note about what the app does: $undocumented",
            emptyMap<String, String>(), undocumented)

        // The one that started it: `gpstracker` is in the firmware's help text but not in its parser.
        assertTrue("gpstracker must never be sent to a board", "gpstracker" in FirmwareCommands.neverSend)
        assertEquals("gps -t", FirmwareCommands.gpsTracker())
    }

    // --- argument quoting, the one place a command can be silently mangled -------------

    @Test
    fun quotingFollowsTheFirmwareParser() {
        assertEquals("'one'", FirmwareCommands.quote("one"))
        assertEquals("'two words'", FirmwareCommands.quote("two words"))
        assertNull(FirmwareCommands.quote(""))
        assertNull(FirmwareCommands.quote("line\nbreak"))
        assertNull(FirmwareCommands.quote("mixed ' and \" quotes"))
    }

    @Test
    fun buildersRefuseWhatTheFirmwareWouldMisread() {
        assertNull(FirmwareCommands.ssidAdd("bad 'and\" name"))
        assertEquals("ssid -a -n 'my lab'", FirmwareCommands.ssidAdd("my lab"))
        assertEquals(
            "add -a -b AA:BB:CC:DD:EE:FF -ch 6 -e 'lab ap'",
            FirmwareCommands.addAp("AA:BB:CC:DD:EE:FF", 6, "lab ap"),
        )
        assertNull(FirmwareCommands.addAp("AA:BB:CC:DD:EE:FF", 6, "bad 'and\" name"))
        assertEquals(
            "geofence set 1 55.7522 37.6156 0.25 'home'",
            FirmwareCommands.geofenceSet(1, 55.7522, 37.6156, 0.25, "home"),
        )
        assertNull(FirmwareCommands.wardrivePoi("bad 'and\" label"))
    }

    @Test
    fun sniffPmkidFlagsAreTheFirmwaresOwnGrammar() {
        assertEquals("sniffpmkid", FirmwareCommands.sniffPmkid())
        assertEquals("sniffpmkid -c 6", FirmwareCommands.sniffPmkid(6))
        assertEquals("sniffpmkid -d", FirmwareCommands.sniffPmkid(deauth = true))
        assertEquals("sniffpmkid -c 6 -d -l", FirmwareCommands.sniffPmkid(6, deauth = true, listOnly = true))
    }

    @Test
    fun selectionWritesThroughTheFirmwaresListSlots() {
        assertEquals("select -a 3", FirmwareCommands.toggleAp(3))
        assertEquals("select -a 0,4,9", FirmwareCommands.selectApSlots(listOf(0, 4, 9)))
        assertEquals("select -a all", FirmwareCommands.toggleAllAps())
        // The filter branch needs `-a` to be present and ignores its value: 0 is a
        // placeholder there, never an index (TargetLock depends on that).
        assertEquals("select -a 0 -f 'equals \"lab\"'", FirmwareCommands.selectByFilter("'equals \"lab\"'"))
        assertEquals("clearlist -a", FirmwareCommands.clearList("a"))
    }

    @Test
    fun listIndexesMatchTheContainersTheFirmwareStreams() {
        // `jsonlist p` iterates probe_req_ssids and `karma -p <index>` addresses the same
        // container, so the probe row index in the app is the karma index.
        val probeSlot = 2
        val karma = FirmwareCommands.karmaProbe(probeSlot)
        assertEquals("karma -p 2", karma)
        // `list -b` is the only view of the BLE list, and its indices are what
        // spoofat/findmy/foxhunt -b take — say so in the command the app offers.
        assertEquals("spoofat -t 1", FirmwareCommands.spoofAirTag(1))
        assertEquals("findmy -t 1", FirmwareCommands.findMyBeacon(1))
        assertEquals("list -b", FirmwareCommands.listDump("b"))
        // The same rule for the board's own MACs: `cloneapmac -a` / `clonestamac -s` copy from the
        // AP / station lists, so their index is a row of `list -a` / `list -c`, never a remembered number.
        assertEquals("cloneapmac -a 2", FirmwareCommands.cloneApMac(2))
        assertEquals("clonestamac -s 4", FirmwareCommands.cloneStationMac(4))
        assertEquals("randapmac", FirmwareCommands.randomiseApMac())
        assertEquals("randstamac", FirmwareCommands.randomiseStationMac())
    }

    // --- depth inside a verb, where the census cannot see a gap --------------------------

    /**
     * The census counts verbs, so it cannot notice a mode the app never offers. Fox Hunt has
     * seven mutually exclusive flags and each one is a different hunt; `-s` also checks that
     * the station belongs to the AP before starting, so its two slots are both real inputs.
     */
    @Test
    fun everyFoxhuntModeHasItsOwnEntryPoint() {
        val offered = allItems.mapNotNull { item ->
            when (val a = item.action) {
                is MenuAction.Send -> a.command
                is MenuAction.Arg -> a.base
                else -> null
            }
        }.filter { it.startsWith("${FirmwareCommands.FOXHUNT} ") }

        // -w opens the AP list instead of asking for a slot; the rest are sent or prompted.
        for (flag in listOf("-s", "-b", "-t", "-f", "-p", "-m")) {
            assertTrue(
                "foxhunt $flag has no entry point (offered: $offered)",
                offered.any { it.split(" ").contains(flag) },
            )
        }
        assertTrue(
            "the AP hunt must open the firmware's own AP list, not ask for a remembered slot",
            allItems.any { item ->
                val a = item.action
                a is MenuAction.OpenList && a.type == ListType.ACCESS_POINTS &&
                    item.requiresCaps.contains("foxhunt")
            },
        )
        assertEquals("foxhunt -s 3 7", FirmwareCommands.foxhuntStation(3, 7))
    }

    /**
     * `gps -b` is not a command: the parser only looks for it inside the `-n beidou`
     * branch, where it selects BD over GB. The builder has to keep that shape, and the
     * NMEA filters are the three readings of `-g nmea` the firmware distinguishes.
     */
    @Test
    fun gpsModifiersKeepTheBranchTheParserReadsThemIn() {
        assertEquals("gps -n beidou", FirmwareCommands.gpsSetSystems("beidou"))
        assertEquals("gps -n beidou -b", FirmwareCommands.gpsBeidouBd())
        assertEquals("gps -g nmea", FirmwareCommands.gpsNmea())
        assertEquals("gps -g nmea -r", FirmwareCommands.gpsNmea("r"))
        assertEquals("gps -g nmea -i", FirmwareCommands.gpsNmea("i"))
        assertEquals("gps -g nmea -p", FirmwareCommands.gpsNmea("p"))

        val offered = allItems.mapNotNull { item ->
            when (val a = item.action) {
                is MenuAction.Send -> a.command
                is MenuAction.Arg -> a.base
                else -> null
            }
        }.filter { it.startsWith("${FirmwareCommands.GPS} ") }
        assertTrue("bare `gps -b` reaches no parser branch", offered.none { it.trim() == "gps -b" })
    }

    /**
     * What `help` prints is not what the parser reads. `update -w` is advertised and never
     * dispatched, so no catalog entry may build it — and the syntax note still has to match
     * the firmware's own line, because that is what the board tells a person in the console.
     */
    @Test
    fun documentedArgumentsTheFirmwareNeverAnswersAreNotBuilt() {
        val built = allItems.mapNotNull { item ->
            when (val a = item.action) {
                is MenuAction.Send -> a.command
                is MenuAction.Arg -> a.base
                else -> null
            }
        } + FirmwareCommands.dynamic.values

        for ((arg, why) in FirmwareCommands.documentedButUnanswered) {
            assertTrue("$arg needs a stated reason", why.isNotBlank())
            assertEquals(
                "$arg is printed by help but read by no parser branch; nothing may send it",
                emptyList<String>(),
                built.filter { it == arg || it.startsWith("$arg ") },
            )
            assertTrue(
                "$arg must still name a verb in the census",
                arg.substringBefore(' ') in FirmwareCommands.verbs,
            )
        }
        assertTrue(
            "the update note must keep the firmware's own -s/-w spelling",
            FirmwareCommands.cli.first { it.name == FirmwareCommands.UPDATE }.syntax.contains("-w"),
        )
    }
}
