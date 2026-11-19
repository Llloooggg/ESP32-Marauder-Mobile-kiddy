package com.marauder.mobile.data

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Login
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Bluetooth
import androidx.compose.material.icons.filled.CellTower
import androidx.compose.material.icons.filled.DeveloperBoard
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.MyLocation
import androidx.compose.material.icons.filled.Podcasts
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.SettingsInputAntenna
import androidx.compose.material.icons.filled.WifiOff
import androidx.compose.ui.graphics.vector.ImageVector

/** How a playbook is executed once the user presses Run. */
enum class ScenarioRun {
    /** Run [Scenario.command] as a mission, after pinning the chosen network and reading the
     *  selection back (nothing is transmitted until that read agrees). */
    PINNED_MISSION,

    /** Run [Scenario.command] as a mission without selecting anything — the flows that must
     *  keep an empty selection (a passive capture) or that do not address an AP at all. */
    MISSION,

    /** Hand over to an existing guided screen or list; the playbook explains the route. */
    NAVIGATE,
}

/** Whether a playbook needs an access point picked before it can run. */
enum class ScenarioTarget { NONE, ACCESS_POINT }

/** One visible step of a playbook: what it does, and the firmware line that does it. */
data class ScenarioStep(val label: String, val command: String? = null)

/**
 * A playbook: one job done end to end, written the way a person thinks about it
 * ("get the handshake and crack it"), but with the firmware's own commands shown next to
 * every step so nothing is hidden and the same recipe can be repeated by hand on any
 * Marauder.
 *
 * `{ap}` and `{ch}` in a command are filled in at run time from the live scan list — the
 * slot the network currently occupies and the channel the board last heard it on. They are
 * never guessed from an earlier run, because a stale slot addresses a different network.
 */
data class Scenario(
    val id: String,
    val title: String,
    val goal: String,
    val steps: List<ScenarioStep>,
    /** What the run produces and what to do with it — the part that makes it a job, not a button. */
    val outcome: String,
    val run: ScenarioRun,
    val icon: ImageVector,
    val accent: Accent,
    val command: String = "",
    val mode: ScenarioMode = ScenarioMode.SCAN,
    val target: ScenarioTarget = ScenarioTarget.NONE,
    val pre: List<String> = emptyList(),
    val navigate: MenuAction? = null,
    val dangerous: Boolean = false,
    val requiresCaps: Set<String> = emptySet(),
)

/** The mission kind a playbook runs as; mirrors the firmware activity, drives counters and Stop. */
enum class ScenarioMode { SCAN, SNIFF, CAPTURE, ATTACK, WARDRIVE, HUNT, PORTAL, OTHER }

object Scenarios {

    val all: List<Scenario> = listOf(
        Scenario(
            id = "capture-targeted",
            title = "Get a handshake or a PMKID from one network",
            goal = "Capture the WPA material for a single access point, keep the board on its " +
                "channel for the whole run, and land a pcap in the Library.",
            steps = listOf(
                ScenarioStep("Scan, then pick the network in the list", FirmwareCommands.SCAN_ALL),
                ScenarioStep("Pin exactly that BSSID and read the selection back", FirmwareCommands.SELECT),
                ScenarioStep("Hold the channel: the hop is switched off for this run", FirmwareCommands.settingsSet("ChanHop", false)),
                ScenarioStep(
                    "Capture with a deauth so the client re-joins, listening only for the selected list",
                    FirmwareCommands.sniffPmkid(6, deauth = true, listOnly = true),
                ),
                ScenarioStep("Watch the console for the firmware's own 'Received EAPOL' lines"),
            ),
            outcome = "A pcap in the Library → open it → Extract to hashcat 22000 → crack on the " +
                "phone (CPU or Vulkan). The mission screen also counts EAPOL frames and lost frames, " +
                "so an empty capture says why.",
            run = ScenarioRun.PINNED_MISSION,
            command = "${FirmwareCommands.SNIFF_PMKID} -c {ch} -d -l",
            mode = ScenarioMode.CAPTURE,
            target = ScenarioTarget.ACCESS_POINT,
            icon = Icons.Filled.Key,
            accent = Accent.ATTACK,
            dangerous = true,
            requiresCaps = setOf("capstream"),
        ),

        Scenario(
            id = "capture-passive",
            title = "Listen for a handshake without transmitting",
            goal = "Collect the WPA material of one network purely by listening — nothing goes out " +
                "on the radio, so it waits for someone else to join.",
            steps = listOf(
                ScenarioStep("Scan, then pick the network", FirmwareCommands.SCAN_ALL),
                ScenarioStep("Clear any leftover selection (one selected AP makes the sniffer drop every other network)", FirmwareCommands.clearList("a")),
                ScenarioStep("Hold its channel", FirmwareCommands.channelSet(6)),
                ScenarioStep("Passive EAPOL/PMKID sniff", FirmwareCommands.sniffPmkid(6)),
            ),
            outcome = "A pcap in the Library when the traffic appears. Nothing was transmitted, so the " +
                "run can be as quiet as the board allows; the same Extract → crack path follows.",
            run = ScenarioRun.MISSION,
            command = "${FirmwareCommands.SNIFF_PMKID} -c {ch}",
            mode = ScenarioMode.CAPTURE,
            target = ScenarioTarget.ACCESS_POINT,
            icon = Icons.Filled.CellTower,
            accent = Accent.SNIFFER,
            requiresCaps = setOf("capstream"),
        ),

        Scenario(
            id = "wardrive",
            title = "Wardrive the area",
            goal = "Walk or drive with the board scanning and the phone's GPS, and come back with a " +
                "spreadsheet of every network on the route.",
            steps = listOf(
                ScenarioStep("Start the board's scan and the phone's location", FirmwareCommands.WARDRIVE),
                ScenarioStep("Tag a point of interest on the way", FirmwareCommands.WARDRIVE_POI),
            ),
            outcome = "A CSV (and a GPX for the route) in the Library, shareable from the report export.",
            run = ScenarioRun.MISSION,
            command = FirmwareCommands.WARDRIVE,
            mode = ScenarioMode.WARDRIVE,
            icon = Icons.Filled.Radar,
            accent = Accent.GPS,
        ),

        Scenario(
            id = "evil-portal",
            title = "Evil portal with a page from the phone",
            goal = "Clone a network's name, serve a captive-portal page chosen on the phone (no SD " +
                "card), and collect what the clients submit.",
            steps = listOf(
                ScenarioStep("Scan and pick the network to impersonate", FirmwareCommands.SCAN_ALL),
                ScenarioStep("Point the portal at that AP", FirmwareCommands.evilPortalSetAp(0)),
                ScenarioStep("Stream the page straight from the phone", FirmwareCommands.evilPortalSetHtmlString(1024)),
                ScenarioStep("Run the portal", FirmwareCommands.EVIL_PORTAL),
            ),
            outcome = "Submitted credentials arrive as structured events and land in the session journal " +
                "and the Library report. The portal screen keeps the AP and the page visible while it runs.",
            run = ScenarioRun.NAVIGATE,
            navigate = MenuAction.OpenEvilPortal,
            icon = Icons.Filled.Language,
            accent = Accent.ATTACK,
            dangerous = true,
        ),

        Scenario(
            id = "karma-probe",
            title = "Answer the networks clients are already looking for",
            goal = "See which SSIDs nearby devices are probing for, then answer one of them.",
            steps = listOf(
                ScenarioStep("Sniff probe requests", FirmwareCommands.SNIFF_PROBE),
                ScenarioStep("Open the Probe Requests list — its rows are the indices `karma -p` takes"),
                ScenarioStep("Tap Karma Clone on a row", FirmwareCommands.karmaProbe(0)),
            ),
            outcome = "The board answers that SSID (the portal flow takes over). The row index is the " +
                "firmware's probe-list slot, so the app shows it rather than asking for a number.",
            run = ScenarioRun.NAVIGATE,
            navigate = MenuAction.OpenList(ListType.PROBES),
            icon = Icons.Filled.Podcasts,
            accent = Accent.ATTACK,
            dangerous = true,
        ),

        Scenario(
            id = "posture",
            title = "Join a network and map what is behind it",
            goal = "Put the board on a network it is allowed to join, then sweep that segment: hosts " +
                "first, then the services on them.",
            steps = listOf(
                ScenarioStep("Join with the board", FirmwareCommands.joinSaved()),
                ScenarioStep("Discover hosts", FirmwareCommands.PINGSCAN),
                ScenarioStep("Discover hosts by ARP", FirmwareCommands.ARPSCAN),
                ScenarioStep("Sweep one host's services", FirmwareCommands.portScan("ssh")),
            ),
            outcome = "An IP list plus the open ports found, saved as CSV artifacts. The screen keeps the " +
                "join state visible, because every later command only works while the board is on that network.",
            run = ScenarioRun.NAVIGATE,
            navigate = MenuAction.OpenPosture,
            icon = Icons.AutoMirrored.Filled.Login,
            accent = Accent.SCANNER,
        ),

        Scenario(
            id = "deauth-target",
            title = "Disconnect one client (denial of service only)",
            goal = "Kick a client off one access point — to test how a network and its clients behave " +
                "under deauth — without capturing anything.",
            steps = listOf(
                ScenarioStep("Scan and pin the target AP", FirmwareCommands.SELECT),
                ScenarioStep("Targeted deauth flood on the selected list", FirmwareCommands.attack("deauth -c")),
            ),
            outcome = "Nothing is captured by design. Stop with Stop; the mission log records what was " +
                "sent, and the AP list shows the clients that dropped and rejoined.",
            run = ScenarioRun.PINNED_MISSION,
            command = "${FirmwareCommands.ATTACK} -t deauth -c",
            mode = ScenarioMode.ATTACK,
            target = ScenarioTarget.ACCESS_POINT,
            icon = Icons.Filled.WifiOff,
            accent = Accent.ATTACK,
            dangerous = true,
        ),

        Scenario(
            id = "foxhunt-ap",
            title = "Find the box physically (fox hunt)",
            goal = "Walk toward one transmitter using the signal-strength readout — the way you find " +
                "an access point or a tracker in a building.",
            steps = listOf(
                ScenarioStep("Scan so the board has the AP list", FirmwareCommands.SCAN_ALL),
                ScenarioStep("Tap Fox Hunt on the AP's row", FirmwareCommands.foxhuntAp(0)),
                ScenarioStep("For a BLE device or a Flipper, use the index from the firmware's own list", FirmwareCommands.listDump("b")),
            ),
            outcome = "A live RSSI readout with a direction hint. BLE/Flipper/FindMy hunts need the index " +
                "from `list -b` / `list -f`, which the Fox Hunt menu shows before asking for a number.",
            run = ScenarioRun.NAVIGATE,
            navigate = MenuAction.Submenu("bt_hunt"),
            icon = Icons.Filled.SettingsInputAntenna,
            accent = Accent.SNIFFER,
            requiresCaps = setOf("foxhunt"),
        ),

        Scenario(
            id = "ble-spam",
            title = "Bluetooth notification spam (on your own devices)",
            goal = "Send the BLE advertisement floods the firmware can send, to test how phones react — " +
                "on devices you own or are allowed to test.",
            steps = listOf(
                ScenarioStep("Pick the flavour in the Bluetooth menu", FirmwareCommands.bleSpam("sourapple")),
                ScenarioStep("All at once", FirmwareCommands.bleSpam("all")),
            ),
            outcome = "Transmits constantly until you Stop. The mission screen shows the command and stops " +
                "it when you leave the screen, so nothing keeps broadcasting in the background.",
            run = ScenarioRun.MISSION,
            command = "${FirmwareCommands.BLESPAM} -t all",
            mode = ScenarioMode.ATTACK,
            icon = Icons.Filled.Bluetooth,
            accent = Accent.ATTACK,
            dangerous = true,
            requiresCaps = setOf("bt"),
        ),

        Scenario(
            id = "recon-sweep",
            title = "One-pass reconnaissance",
            goal = "Let the board do a full sweep by itself (WiFi, then Bluetooth) and read its own report.",
            steps = listOf(
                ScenarioStep("Sweep WiFi", FirmwareCommands.recon("wifi")),
                ScenarioStep("Sweep Bluetooth", FirmwareCommands.recon("ble")),
                ScenarioStep("Read the report", FirmwareCommands.recon("status")),
                ScenarioStep("Stop it early if needed", FirmwareCommands.recon("stop")),
            ),
            outcome = "Counts and lists in the app's own views, plus the firmware's report text. A good " +
                "first run when you do not know what is around.",
            run = ScenarioRun.MISSION,
            command = "${FirmwareCommands.RECON} wifi",
            mode = ScenarioMode.SCAN,
            icon = Icons.Filled.Radar,
            accent = Accent.SCANNER,
            requiresCaps = setOf("recon"),
        ),

        Scenario(
            id = "board-baseline",
            title = "Check the board's switches before a capture",
            goal = "Read what the firmware itself has turned on, because those switches decide whether " +
                "a capture collects anything at all.",
            steps = listOf(
                ScenarioStep("Read the board's settings", FirmwareCommands.settingsDump()),
                ScenarioStep("ChanHop off / on: whether a pinned scan stays on its channel", FirmwareCommands.settingsSet("ChanHop", false)),
                ScenarioStep("SavePCAP, ForcePMKID, ForceProbe, EPDeauth: what a run collects", FirmwareCommands.settingsSet("SavePCAP", true)),
            ),
            outcome = "A list of the board's real settings with switches that verify themselves: each write " +
                "is followed by a fresh read, and a change the board did not apply is reported as failed.",
            run = ScenarioRun.NAVIGATE,
            navigate = MenuAction.OpenBoardSettings,
            icon = Icons.Filled.Settings,
            accent = Accent.DEVICE,
        ),

        Scenario(
            id = "crack-what-was-captured",
            title = "Turn a capture into a cracked key",
            goal = "Take a pcap that is already in the Library, extract the handshake material, and " +
                "attack it with the wordlist on the phone.",
            steps = listOf(
                ScenarioStep("Open the Library and pick the capture"),
                ScenarioStep("Extract → hashcat 22000 file (PMKID and/or M1-M2-M3-M4)"),
                ScenarioStep("Pick a wordlist and start the built-in cracker (CPU or Vulkan)"),
                ScenarioStep("Compare a suspect key against what was captured"),
            ),
            outcome = "The recovered key, or an honest 'not in this wordlist' — with the effort counters, " +
                "so the result can be re-checked on a PC with the same 22000 file.",
            run = ScenarioRun.NAVIGATE,
            navigate = MenuAction.OpenArtifacts,
            icon = Icons.Filled.FolderOpen,
            accent = Accent.PRIMARY,
        ),

        Scenario(
            id = "device-baseline",
            title = "Get the board talking first",
            goal = "Confirm what firmware this board runs, what it answers, and put the link at the speed " +
                "a capture needs.",
            steps = listOf(
                ScenarioStep("Ask the board what it is", FirmwareCommands.JSON_INFO),
                ScenarioStep("Ask it what it supports", FirmwareCommands.PROTOCOL_INFO),
                ScenarioStep("Raise the serial rate for capture streaming", FirmwareCommands.JSON_BAUD),
                ScenarioStep("Reboot if the firmware got stuck", FirmwareCommands.REBOOT),
            ),
            outcome = "The board card on Home shows firmware version, protocol and capability list; the " +
                "catalog then only offers what this board can actually do.",
            run = ScenarioRun.NAVIGATE,
            navigate = MenuAction.Submenu("device"),
            icon = Icons.Filled.DeveloperBoard,
            accent = Accent.DEVICE,
        ),
    )

    /** The playbooks a capable board can run, in the order that makes sense for a first session. */
    fun forCaps(caps: List<String>?): List<Scenario> =
        all.filter { caps == null || it.requiresCaps.isEmpty() || caps.containsAll(it.requiresCaps) }

    fun get(id: String): Scenario? = all.firstOrNull { it.id == id }

    /**
     * Fill `{ap}` and `{ch}` with the live slot and channel of the picked network. Anything
     * else in the command is left exactly as written — the recipe stays readable.
     *
     * When there is no value for a placeholder, the placeholder **stays**: a blank would turn
     * into a command with a hole in it (`sniffpmkid -c`), and the caller can only refuse such
     * a command if the hole is still visible.
     */
    fun instantiate(command: String, slot: Int?, channel: Int): String {
        var out = command
        if (slot != null) out = out.replace("{ap}", slot.toString())
        if (channel > 0) out = out.replace("{ch}", channel.toString())
        return out
    }

    /** True when the playbook needs a network picked before it can start. */
    fun needsTarget(scenario: Scenario): Boolean =
        scenario.target == ScenarioTarget.ACCESS_POINT

    /** The `{…}` placeholders a command uses, for the test that keeps them honest. */
    fun placeholders(command: String): Set<String> =
        Regex("""\{\w+}""").findAll(command).map { it.value }.toSet()
}
