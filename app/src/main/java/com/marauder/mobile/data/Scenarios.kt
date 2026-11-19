package com.marauder.mobile.data

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Login
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Bluetooth
import androidx.compose.material.icons.filled.CellTower
import androidx.compose.material.icons.filled.DeveloperBoard
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.MyLocation
import androidx.compose.material.icons.filled.Numbers
import androidx.compose.material.icons.filled.Podcasts
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.SettingsInputAntenna
import androidx.compose.material.icons.filled.Sensors
import androidx.compose.material.icons.filled.Shuffle
import androidx.compose.material.icons.filled.SmartToy
import androidx.compose.material.icons.filled.TrackChanges
import androidx.compose.material.icons.filled.Visibility
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
    /**
     * The condition that makes this playbook silently produce nothing, in the board's own terms.
     * Anything that runs on one channel says it here: the ESP32-S3 has a 2.4 GHz radio only, and
     * a mode that does not hop hears exactly the channel the board is sitting on — so a capture
     * of a network that lives elsewhere is empty even though every command worked.
     */
    val warn: String = "",
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
            warn = "The ESP32-S3 has a 2.4 GHz radio only. A row whose channel is above 14 is a " +
                "5 GHz interface of the same router, and this board can never hear its handshake — " +
                "pick the 2.4 GHz row. `ChanHop` is also a board setting, not a per-run switch: a " +
                "previous run that left it off keeps the radio on one channel, so the list here may " +
                "hold only what is on that channel. Read the channel and RSSI of the row you picked, " +
                "and only trust a capture that reports EAPOL frames.",
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
            warn = "Two things decide whether this ever fills a file: the channel (this mode holds " +
                "one, and a row whose channel is above 14 is a 5 GHz interface this 2.4 GHz board " +
                "cannot hear), and the fact that nothing is transmitted — so a handshake only " +
                "appears if some client joins or re-joins on its own while the board is listening " +
                "on that exact channel.",
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
                ScenarioStep(
                    "Let the board send its own log, if it was built to: it joins a saved WiFi first",
                    FirmwareCommands.uploadTo("wigle"),
                ),
            ),
            outcome = "A CSV (and a GPX for the route) in the Library, shareable from the report export.",
            warn = "The CSV on the phone is made from what the board streams, so the route is only as " +
                "complete as the channels the board was hearing — its radio is 2.4 GHz only, and a " +
                "5 GHz network (a channel above 14) never appears in it. `upload` is the other way " +
                "round: the board reads the log it wrote itself, joins a saved WiFi network, and needs " +
                "a firmware built with direct upload — the app cannot prove that from the board's " +
                "capability list, so it sends the command and reports what the board says.",
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
            warn = "The board addresses the clients it can hear on the channel it is on, and its radio " +
                "is 2.4 GHz only: a client that is associated to the router's 5 GHz interface will " +
                "not move, no matter how long the flood runs. If nothing drops, that is usually where " +
                "the client is, not a fault in the command.",
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
                ScenarioStep("What the board's own display is set to, where it has a display", FirmwareCommands.brightnessCurrent()),
                ScenarioStep("A colour on the RGB LED strip, where the board has one", FirmwareCommands.ledColor("#ff8800")),
                ScenarioStep("Rainbow: the board looks awake while it runs", FirmwareCommands.ledPattern("rainbow")),
            ),
            outcome = "A list of the board's real settings with switches that verify themselves: each write " +
                "is followed by a fresh read, and a change the board did not apply is reported as failed.",
            warn = "Two of these answer nothing on some boards, and that is a build fact rather than a " +
                "broken command: the firmware compiles the brightness branch only for boards with a " +
                "display of its own, and the LED branch only for boards with an RGB LED strip. The " +
                "settings dump is the one that always answers, and it is where to start.",
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
            warn = "Extraction reports what was actually in the file: zero hash lines means the pcap " +
                "carried no EAPOL at all, which is a capture problem (wrong channel, or a 5 GHz " +
                "network this board cannot hear), not a cracker problem. Fix the capture before " +
                "lengthening the wordlist.",
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
                ScenarioStep("Ask it for its own command list, in its own words", FirmwareCommands.helpText()),
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

        // ----------------------------------------------------------------------------------
        // The rest of the firmware's surface, as jobs. These exist because the commands below take
        // an index or a mode: a bare button for `csimotion start` or `remoteid track` is a button
        // that does nothing until the user knows which row of which list the number means. A
        // playbook is what puts that list in front of them.
        // ----------------------------------------------------------------------------------

        Scenario(
            id = "silent-watchers",
            title = "Watch what is already on the air",
            goal = "Ask nothing and transmit nothing: run the firmware's own detectors one at a time " +
                "and read what the air carries by itself.",
            steps = listOf(
                ScenarioStep("Is there any traffic at all? Frames counted per channel", FirmwareCommands.PACKET_COUNT),
                ScenarioStep("Beacons only - the access points, without the rest", FirmwareCommands.SNIFF_BEACON),
                ScenarioStep("Deauth frames - who is being disconnected, and by whom", FirmwareCommands.SNIFF_DEAUTH),
                ScenarioStep("WPA3 commit frames - what a WPA3 network sends before a handshake", FirmwareCommands.SNIFF_SAE),
                ScenarioStep("Pineapple-style probe answers", FirmwareCommands.SNIFF_PINESCAN),
                ScenarioStep("Several SSIDs from one access point", FirmwareCommands.SNIFF_MULTISSID),
                ScenarioStep("Pwnagotchi packets", FirmwareCommands.SNIFF_PWN),
                ScenarioStep("Every management frame, raw", FirmwareCommands.SNIFF_RAW),
                ScenarioStep("Channel occupancy while the board hops", FirmwareCommands.analyzer("chan")),
                ScenarioStep("End it, and the counters end", FirmwareCommands.stopscan()),
            ),
            outcome = "What the board noticed, in the console and in the session journal. Whether a " +
                "capture file also appears depends on the mode, and the app does not guess: the " +
                "Library lists the files that exist after the run. This is the honest first run " +
                "before choosing a target, because it cannot disturb anything.",
            warn = "The detectors hear exactly what the radio can reach, and this board's radio is " +
                "2.4 GHz only: anything on a channel above 14 is a 5 GHz interface and no detector " +
                "here will report it, however long it runs.",
            run = ScenarioRun.MISSION,
            command = FirmwareCommands.PACKET_COUNT,
            mode = ScenarioMode.SCAN,
            icon = Icons.Filled.Sensors,
            accent = Accent.SNIFFER,
        ),

        Scenario(
            id = "hidden-network",
            title = "Work with a network the scan does not show",
            goal = "A hidden SSID, or an access point you already know the address of: put it in the " +
                "board's own list by hand, and read back the slot it landed in before using it.",
            steps = listOf(
                ScenarioStep(
                    "Insert it by hand: address, channel, and its name if it has one",
                    requireNotNull(FirmwareCommands.addAp("AA:BB:CC:DD:EE:FF", 6, "lab ap")),
                ),
                ScenarioStep("Read the list back - the slot the board gave it is what every later command takes", FirmwareCommands.listDump("a")),
                ScenarioStep("What the board believes about that row", FirmwareCommands.apInfo(0)),
                ScenarioStep("A client that is not in the list either", "${FirmwareCommands.ADD} -c -b AA:BB:CC:DD:EE:02"),
                ScenarioStep("Then the capture, against the channel you wrote", "${FirmwareCommands.SNIFF_PMKID} -c 6 -d -l"),
            ),
            outcome = "A row in the board's own list, with its slot and channel, which the capture " +
                "playbooks can then be run against. The app re-reads the list before it uses a slot: " +
                "a number remembered from before the insert addresses a different network.",
            warn = "The channel you write is the channel the board will hold. If it is wrong the run is " +
                "silent even though every command worked - and a channel above 14 is a 5 GHz interface " +
                "this 2.4 GHz board cannot hear at all.",
            run = ScenarioRun.NAVIGATE,
            navigate = MenuAction.Submenu("wifi_lists"),
            icon = Icons.Filled.Router,
            accent = Accent.SCANNER,
        ),

        Scenario(
            id = "follow-devices",
            title = "Which devices move with you",
            goal = "Walk with the board. It keeps a signal history per address, and the addresses " +
                "whose signal grows as you come closer and fades as you leave are the ones beside you.",
            steps = listOf(
                ScenarioStep("Start the run the firmware itself calls MAC Tracker", FirmwareCommands.MAC_TRACK),
                ScenarioStep("Walk - it is judging a trend over readings, not one reading", FirmwareCommands.stopscan()),
                ScenarioStep("Then the same question for one transmitter, with a live signal readout", FirmwareCommands.foxhuntAp(0)),
            ),
            outcome = "The board marks the addresses whose signal moved with yours, and writes those " +
                "frames into its capture buffer. It is a coarse answer to a physical question: which " +
                "of these is near me - and unlike a fox hunt it answers it for everything at once.",
            warn = "It needs readings of the same address over time, so standing still proves nothing. " +
                "It also only ever sees this 2.4 GHz radio: a device that talks to a 5 GHz interface " +
                "(a channel above 14) is not in this list, no matter how close it is.",
            run = ScenarioRun.MISSION,
            command = FirmwareCommands.MAC_TRACK,
            mode = ScenarioMode.SCAN,
            icon = Icons.Filled.Visibility,
            accent = Accent.SNIFFER,
        ),

        Scenario(
            id = "mac-identity",
            title = "Change the address the board transmits with",
            goal = "Some tests, and some access points, care about the MAC the board puts in frames it " +
                "sends itself. This is where those addresses come from.",
            steps = listOf(
                ScenarioStep("A new random address for the board's access-point frames", FirmwareCommands.randomiseApMac()),
                ScenarioStep("A new random address for its station frames", FirmwareCommands.randomiseStationMac()),
                ScenarioStep("Copy the address of a row of the access-point list", FirmwareCommands.cloneApMac(0)),
                ScenarioStep("Copy the address of a row of the station list", FirmwareCommands.cloneStationMac(0)),
                ScenarioStep("Those two lists, with their slots", FirmwareCommands.listDump("a")),
            ),
            outcome = "The board's own frames go out with a different address: a portal it opens, a " +
                "network it joins, a deauth it sends. Nothing that was already captured changes, and " +
                "a reboot puts the firmware's default back.",
            warn = "The index is a row of the list the board is holding now, not a number from an " +
                "earlier scan: after a rescan the same slot addresses a different device.",
            run = ScenarioRun.NAVIGATE,
            navigate = MenuAction.Submenu("wifi_macs"),
            icon = Icons.Filled.Shuffle,
            accent = Accent.GENERAL,
        ),

        Scenario(
            id = "bluetooth-devices",
            title = "AirTags, beacons and Flipper badges",
            goal = "Look at the Bluetooth advertisements around you, then answer as one of them.",
            steps = listOf(
                ScenarioStep("Every advertisement the board can classify", FirmwareCommands.sniffBt()),
                ScenarioStep("One kind at a time", FirmwareCommands.sniffBt("airtag")),
                ScenarioStep("Credit-card skimmers, which advertise loudly and quietly everywhere else", FirmwareCommands.SNIFF_SKIM),
                ScenarioStep("The board's own list of what it saw - its rows are the indices below", FirmwareCommands.listDump("b")),
                ScenarioStep("Answer as that AirTag", FirmwareCommands.spoofAirTag(0)),
                ScenarioStep("Make a FindMy beacon", FirmwareCommands.findMyBeacon(0)),
            ),
            outcome = "A list of Bluetooth devices with their slots, and one of them answered in the " +
                "board's own name. The slots come from the list built during this run, which is why " +
                "the list is opened before any index is used.",
            warn = "Bluetooth is a second radio, not the WiFi one: this is advertising traffic, and a " +
                "device that is connected but not broadcasting does not appear at all. The index is a " +
                "row of the list the board built in this run, and the list is cleared by a restart.",
            run = ScenarioRun.MISSION,
            command = FirmwareCommands.sniffBt(),
            mode = ScenarioMode.SNIFF,
            icon = Icons.Filled.Bluetooth,
            accent = Accent.BLUETOOTH,
            requiresCaps = setOf("bt"),
        ),

        Scenario(
            id = "board-position",
            title = "Let the board carry its own position",
            goal = "A board with a GPS module can log where it was, which is what makes its own files " +
                "stand on their own instead of depending on the phone.",
            steps = listOf(
                ScenarioStep("Does it have a fix at all - read this first", FirmwareCommands.gpsGet("fix")),
                ScenarioStep("How many satellites, and how well", FirmwareCommands.gpsGet("sat")),
                ScenarioStep("The position it currently believes", FirmwareCommands.gpsGet("lat")),
                ScenarioStep("Start the board's own track", FirmwareCommands.gpsTracker()),
                ScenarioStep("End the track, like any other scan", FirmwareCommands.stopscan()),
                ScenarioStep("The position as the board reads it right now - the board says to stop it with stopscan", FirmwareCommands.GPS_DATA),
                ScenarioStep("The raw sentences, one line at a time", FirmwareCommands.NMEA),
                ScenarioStep("A point of interest: begin, mark it, write it out", FirmwareCommands.gpsPoi("m")),
                ScenarioStep("Which satellite systems to listen to", FirmwareCommands.gpsSetSystems("all")),
                ScenarioStep("The fences the board checks its position against", FirmwareCommands.geofenceList()),
                ScenarioStep(
                    "One fence: slot, latitude, longitude, radius in miles, name",
                    requireNotNull(FirmwareCommands.geofenceSet(1, 55.7522, 37.6156, 0.25, "home")),
                ),
            ),
            outcome = "Position that came from the board, so the files the board writes carry it with " +
                "no phone involved. The app keeps the fix state visible while this runs, and writes no " +
                "position it did not receive.",
            warn = "A cold GPS answers nothing at all, and no command here can make a position appear: " +
                "the fix line is the first thing to read. The menu entry called Phone Track is the " +
                "phone's own GPS, not this one - the board's tracker is the command above.",
            run = ScenarioRun.NAVIGATE,
            navigate = MenuAction.Submenu("gps"),
            icon = Icons.Filled.MyLocation,
            accent = Accent.GPS,
            requiresCaps = setOf("gps"),
        ),

        Scenario(
            id = "drone-id",
            title = "Drones that say who they are",
            goal = "Drones that broadcast Remote ID announce their position and their operator. The " +
                "board listens, keeps a list, and can follow one of them.",
            steps = listOf(
                ScenarioStep("Hear what is around", FirmwareCommands.remoteId("scan")),
                ScenarioStep("The list the board built - its rows are the index `track` takes", FirmwareCommands.remoteId("list")),
                ScenarioStep("Follow one of them instead of everything", FirmwareCommands.remoteId("track", 0)),
                ScenarioStep("Start the list again", FirmwareCommands.remoteId("clear")),
            ),
            outcome = "A Remote ID list with the slots that `track` addresses, kept live in the app's " +
                "Remote ID view. Tracking one keeps the board listening for that transmitter rather " +
                "than sorting every broadcast it hears.",
            warn = "This is broadcast, not a connection: a drone that is switched off, too far away, " +
                "or announcing on a radio this board does not have is simply not in the list, and an " +
                "empty list is not a failed command.",
            run = ScenarioRun.MISSION,
            command = FirmwareCommands.remoteId("scan"),
            mode = ScenarioMode.SCAN,
            icon = Icons.Filled.SmartToy,
            accent = Accent.SCANNER,
            requiresCaps = setOf("remoteid"),
        ),

        Scenario(
            id = "csi-motion",
            title = "Notice movement in one network's signal",
            goal = "The S3 reads the channel state of the frames it receives. Against one steady " +
                "transmitter that becomes a motion sensor: the room changes the signal, and the change " +
                "is what is measured.",
            steps = listOf(
                ScenarioStep("Fill the access-point list first - the board says so itself: 'Run sniffbeacon, stopscan, then list -a.'", FirmwareCommands.SNIFF_BEACON),
                ScenarioStep("Stop the scan so the list stays where it is", FirmwareCommands.stopscan()),
                ScenarioStep("The rows, and the slots they have", FirmwareCommands.listDump("a")),
                ScenarioStep("Start sensing against one of them", FirmwareCommands.csimotionStart(0)),
                ScenarioStep("What it measured", FirmwareCommands.csimotionStatus()),
                ScenarioStep("Teach it an empty room: keep still for 30 seconds", FirmwareCommands.csimotionRecalibrate()),
            ),
            outcome = "A per-target motion reading, with the board's own status output beside it. The " +
                "reference transmitter matters more than the word 'sensor': this measures that a " +
                "signal the board already trusts has changed.",
            warn = "The index is a row of the list the board is holding now; with an empty list it " +
                "answers 'Invalid AP index. Run sniffbeacon, stopscan, then list -a.' And the " +
                "reference has to keep transmitting: without frames from that network there is no " +
                "signal to notice a change in.",
            run = ScenarioRun.MISSION,
            command = "${FirmwareCommands.CSI_MOTION} start {ap}",
            mode = ScenarioMode.OTHER,
            target = ScenarioTarget.ACCESS_POINT,
            icon = Icons.Filled.TrackChanges,
            accent = Accent.SNIFFER,
            requiresCaps = setOf("csi"),
        ),

        Scenario(
            id = "board-files",
            title = "The board's own files, and a way back",
            goal = "A board with an SD card keeps its lists, its logs and a copy of its settings on the " +
                "card - which is how a session survives a reboot, and how a bad change is undone.",
            steps = listOf(
                ScenarioStep("What is on the card", FirmwareCommands.ls("/spiffs")),
                ScenarioStep("Write the access-point list there", FirmwareCommands.saveList("a")),
                ScenarioStep("Take it back after a reboot", FirmwareCommands.loadList("a")),
                ScenarioStep("A copy of the board's settings before changing anything", FirmwareCommands.backupSpiffs()),
                ScenarioStep("Did the copy finish", FirmwareCommands.backupStatus()),
                ScenarioStep("Undo everything back to that copy", FirmwareCommands.restoreSpiffs()),
                ScenarioStep("Replace the firmware from the card", FirmwareCommands.updateFromSd()),
            ),
            outcome = "Files and settings on the card, written and read by the board itself, with its " +
                "own answers shown. A restore replaces settings every screen of the app writes to, " +
                "which is the point of having it.",
            warn = "The card is the whole subject: without an SD socket these verbs answer nothing. An " +
                "update from the card is also the one step here the app cannot undo - it writes over " +
                "the firmware, and the only way back is another update or a flash.",
            run = ScenarioRun.NAVIGATE,
            navigate = MenuAction.Submenu("device_files"),
            icon = Icons.Filled.Folder,
            accent = Accent.DEVICE,
            requiresCaps = setOf("sd"),
        ),

        Scenario(
            id = "ssid-list",
            title = "A list of names to work with",
            goal = "Karma-style answers, an evil portal and a beacon flood all read their names from " +
                "the board's SSID list. That list is built here, and its slots are what those commands take.",
            steps = listOf(
                ScenarioStep("A batch of names, made up", FirmwareCommands.ssidGenerate(20)),
                ScenarioStep("One name you chose", requireNotNull(FirmwareCommands.ssidAdd("lab-network"))),
                ScenarioStep("The rows, with their slots", FirmwareCommands.listDump("s")),
                ScenarioStep("Answer only those names", FirmwareCommands.toggleAllSsids()),
                ScenarioStep("Take one name out", FirmwareCommands.ssidRemove(0)),
                ScenarioStep("Empty the list", FirmwareCommands.clearList("s")),
            ),
            outcome = "An SSID list with visible slots, ready for the portal and the beacon attacks. " +
                "The names the board answers with are exactly the ones on this list, so the list is " +
                "shown rather than remembered.",
            run = ScenarioRun.NAVIGATE,
            navigate = MenuAction.Submenu("wifi_lists"),
            icon = Icons.Filled.Numbers,
            accent = Accent.GENERAL,
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
