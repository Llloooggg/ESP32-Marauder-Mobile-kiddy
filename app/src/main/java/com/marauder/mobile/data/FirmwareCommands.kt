package com.marauder.mobile.data

/**
 * One firmware verb plus the syntax the firmware itself documents. [syntax] is copied
 * from the firmware's own help strings (`HELP_*` in `CommandLine.h` of the json-serial
 * tree), so the app's wording and the device's wording cannot drift apart.
 */
data class FirmwareVerb(val name: String, val syntax: String)

/**
 * The complete firmware command surface, in one place.
 *
 * Two rules keep this honest:
 *
 *  * **Only verbs the firmware actually dispatches are listed.** The census was taken
 *    from the verb constants in `CommandLine.h` and the dispatch chain in
 *    `CommandLine.cpp`; verbs that the firmware has commented out (`scansta`,
 *    `btwardrive`, `sourapple`, `swiftpair`, …) are absent, because the CLI never
 *    parses them and sending one is a silent no-op.
 *  * **Every verb here has to be reachable from the app**, either as a catalog entry or
 *    through one of the builders below / [dynamic] / [appInternal].
 *    `FirmwareCoverageTest` fails if a verb becomes unreachable, so a firmware update
 *    that adds a command shows up as a failing test rather than as a missing feature.
 */
object FirmwareCommands {

    /** CLI verbs, as dispatched by `CommandLine::runCommand` (upstream + json-serial fork). */
    val cli: List<FirmwareVerb> = listOf(
        FirmwareVerb(ADD, "add -a -b <mac> [-ch <channel>] [-e <ssid>] / add -c"),
        FirmwareVerb(ANALYZER, "analyzer [-t <wifi/bt/chan>]"),
        FirmwareVerb(ARPSCAN, "arpscan [-f]"),
        FirmwareVerb(ATTACK, "attack -t <quiet/csa/sae/beacon [-l/-r/-a]/deauth [-c]" +
            "/[-s <src mac>] [-d <dst mac>]/probe/rickroll/badmsg [-c]/sleep [-c]>"),
        FirmwareVerb(BACKUP_SPIFFS, "backupspiffs [--machine <transaction-id>]"),
        FirmwareVerb(BACKUP_STATUS, "backupstatus [--machine <transaction-id>]"),
        FirmwareVerb(BLESPAM, "blespam -t <sourapple/applejuice/google/samsung/windows/flipper/all>"),
        FirmwareVerb(BRIGHTNESS, "brightness [-c cycle] [-s <0-9>]"),
        FirmwareVerb(CHANNEL, "channel [-s <channel>]"),
        FirmwareVerb(CLEARLIST, "clearlist -a/-s/-c"),
        FirmwareVerb(CLONE_AP_MAC, "cloneapmac [-a <index>]"),
        FirmwareVerb(CLONE_STA_MAC, "clonestamac [-s <index>]"),
        FirmwareVerb(CSI_MOTION, "csimotion start <AP index>/recalibrate/status (stop with stopscan)"),
        FirmwareVerb(EVIL_PORTAL, "evilportal [-c start [-w html.html]/sethtml <html.html>" +
            "/sethtmlstr <len>/setap <n>]"),
        FirmwareVerb(FINDMY, "findmy -t <index>"),
        FirmwareVerb(FOXHUNT, "foxhunt -w <ap>/-s <ap> <station>/-b <ble>/-t <findmy>" +
            "/-f <flipper>/-p <pineapple>/-m <multissid>"),
        FirmwareVerb(GEOFENCE, "geofence list/set <1-5> <lat> <lon> <0.1-1.0 mi> \"<name>\"/clear <1-5>"),
        FirmwareVerb(GPS, "gps [-t] [-g] <fix/sat/lon/lat/alt/date/accuracy/text/nmea>" +
            " [-n] <native/all/gps/glonass/galileo/navic/qzss/beidou> [-b = BeiDou BD]"),
        FirmwareVerb(GPS_DATA, "gpsdata"),
        FirmwareVerb(GPS_POI, "gpspoi -s/-m/-e"),
        FirmwareVerb(HELP, "help"),
        FirmwareVerb(INFO, "info [-a <index>]"),
        FirmwareVerb(JOIN, "join -a <index> -p <password>/-s"),
        FirmwareVerb(KARMA, "karma -p <index>"),
        FirmwareVerb(LED, "led -s <hex color>/-p <rainbow>"),
        FirmwareVerb(LIST, "list -a/-s/-c/-i/-p/-b/-f/-x/-m"),
        FirmwareVerb(LOAD, "load -a/-s"),
        FirmwareVerb(LS, "ls <directory>"),
        FirmwareVerb(MAC_TRACK, "mactrack"),
        FirmwareVerb(NMEA, "nmea"),
        FirmwareVerb(PACKET_COUNT, "packetcount"),
        FirmwareVerb(PINGSCAN, "pingscan"),
        FirmwareVerb(PORTSCAN, "portscan [-a -t <ip index>]/[-s <ssh/telnet/dns/http/smtp/https/rdp>]"),
        FirmwareVerb(PROTOCOL_INFO, "protocolinfo [--machine <transaction-id>]"),
        FirmwareVerb(RAND_AP_MAC, "randapmac"),
        FirmwareVerb(RAND_STA_MAC, "randstamac"),
        FirmwareVerb(REBOOT, "reboot"),
        FirmwareVerb(RECON, "recon wifi|ble|status|stop"),
        FirmwareVerb(REMOTE_ID, "remoteid <scan/list/track/clear> [index]"),
        FirmwareVerb(RESTORE_SPIFFS, "restorespiffs [--machine <transaction-id>]"),
        FirmwareVerb(SAVE, "save -a/-s"),
        FirmwareVerb(SCAN_ALL, "scanall"),
        FirmwareVerb(SELECT, "select -a <index|all|1,2,3> [-f <filter>]/-s <index|all>/-c <index|all>"),
        FirmwareVerb(SETTINGS, "settings [-s <setting> enable|disable]/[-r]"),
        FirmwareVerb(SNIFF_BEACON, "sniffbeacon"),
        FirmwareVerb(SNIFF_BT, "sniffbt [-t] <airtag/ibeacon/flipper/flock/meta>"),
        FirmwareVerb(SNIFF_DEAUTH, "sniffdeauth"),
        FirmwareVerb(SNIFF_MULTISSID, "sniffmultissid"),
        FirmwareVerb(SNIFF_PINESCAN, "sniffpinescan"),
        FirmwareVerb(SNIFF_PMKID, "sniffpmkid [-c <channel>][-d][-l]"),
        FirmwareVerb(SNIFF_PROBE, "sniffprobe"),
        FirmwareVerb(SNIFF_PWN, "sniffpwn"),
        FirmwareVerb(SNIFF_RAW, "sniffraw"),
        FirmwareVerb(SNIFF_SAE, "sniffsae"),
        FirmwareVerb(SNIFF_SKIM, "sniffskim"),
        FirmwareVerb(SPOOF_AT, "spoofat -t <index>"),
        FirmwareVerb(SSID, "ssid -a -g <count>/-a -n <name>/-r <index>"),
        FirmwareVerb(STOPSCAN, "stopscan [-f]"),
        FirmwareVerb(UPDATE, "update -s/-w"),
        FirmwareVerb(UPLOAD, "upload -d <wdg/wigle/both>"),
        FirmwareVerb(WARDRIVE, "wardrive"),
        FirmwareVerb(WARDRIVE_POI, "wardrivepoi [label]"),
    )

    /**
     * App-protocol verbs answered by the JSON layer (`JsonSerial.h`), which runs before
     * the CLI parser: the app drives the board with these, plus [cli] on top of it.
     */
    val json: List<FirmwareVerb> = listOf(
        FirmwareVerb(JSON_INFO, "jsoninfo"),
        FirmwareVerb(JSON_STATUS, "jsonstatus [-v]"),
        FirmwareVerb(JSON_LIST, "jsonlist <a|s|c|i|p|t|d|g>"),
        FirmwareVerb(JSON_MODE, "jsonmode [on|off]"),
        FirmwareVerb(JSON_BAUD, "jsonbaud <rate>"),
    )

    /** Every verb name the board accepts. */
    val verbs: Set<String> = (cli + json).map { it.name }.toSet()

    /**
     * Verbs the firmware never answers, so sending one is a silent no-op and nothing may build them:
     * either the verb constant is commented out in `CommandLine.h` (`scansta`, `btwardrive`, …), or the
     * word is printed by the firmware's own `help` but has no branch in its parser — `gpstracker` is
     * that second kind (`CommandLine.h:76` declares it, `CommandLine.cpp` never compares against it,
     * and the board's tracker is started by `gps -t`). The app's own phone-GPS tracker keeps the name
     * for itself; see [appOnly].
     */
    val neverSend: Set<String> = setOf("scansta", "btwardrive", "btspamall", "sourapple", "swiftpair", GPS_TRACKER)

    /**
     * Words the app answers by itself and never puts on the wire. They look like firmware commands
     * because they came from the same menus, so they need naming here: a menu item that "sends" one of
     * these is doing the work on the phone, and the app has to say so rather than let the word imply
     * the board did it.
     */
    val appOnly: Map<String, String> = linkedMapOf(
        GPS_TRACKER to "the phone's own GPS writes the GPX track; the board has no `gpstracker` " +
            "dispatch, and its own tracker is `gps -t`",
    )

    /**
     * Arguments the firmware's `help` advertises but its parser never reads. They are not
     * verbs — the verb itself is reachable — so [neverSend] cannot hold them. Listing them
     * here keeps two things true: the app never builds one, and a firmware update that
     * starts answering it has to face a test instead of silently changing meaning.
     *
     * `update -w` is the only one today: `CommandLine.cpp` searches for `-s` and nothing
     * else, so `update -w` falls through every branch and the board does nothing at all.
     * (No `-w` is printed in the firmware's dispatch chain; the help string at
     * `CommandLine.h:150` is the only place it exists.)
     */
    val documentedButUnanswered: Map<String, String> = linkedMapOf(
        "$UPDATE -w" to "help prints it, but CommandLine.cpp only searches for -s: no branch reads -w",
    )

    // --- verb prefixes -----------------------------------------------------------------
    // One constant per verb, so a builder and an argument-prompted catalog entry can
    // never disagree about the same command.

    const val ADD = "add"
    const val ANALYZER = "analyzer"
    const val ARPSCAN = "arpscan"
    const val ATTACK = "attack"
    const val BACKUP_SPIFFS = "backupspiffs"
    const val BACKUP_STATUS = "backupstatus"
    const val BLESPAM = "blespam"
    const val BRIGHTNESS = "brightness"
    const val CHANNEL = "channel"
    const val CLEARLIST = "clearlist"
    const val CLONE_AP_MAC = "cloneapmac"
    const val CLONE_STA_MAC = "clonestamac"
    const val CSI_MOTION = "csimotion"
    const val EVIL_PORTAL = "evilportal"
    const val FINDMY = "findmy"
    const val FOXHUNT = "foxhunt"
    const val GEOFENCE = "geofence"
    const val GPS = "gps"
    const val GPS_DATA = "gpsdata"
    const val GPS_POI = "gpspoi"

    /** Not in the [cli] census: the firmware's help prints it, its parser never answers it. The app
     *  uses the word for its own phone-GPS tracker — see [appOnly] and [neverSend]. */
    const val GPS_TRACKER = "gpstracker"
    const val HELP = "help"
    const val INFO = "info"
    const val JOIN = "join"
    const val KARMA = "karma"
    const val LED = "led"
    const val LIST = "list"
    const val LOAD = "load"
    const val LS = "ls"
    const val MAC_TRACK = "mactrack"
    const val NMEA = "nmea"
    const val PACKET_COUNT = "packetcount"
    const val PINGSCAN = "pingscan"
    const val PORTSCAN = "portscan"
    const val PROTOCOL_INFO = "protocolinfo"
    const val RAND_AP_MAC = "randapmac"
    const val RAND_STA_MAC = "randstamac"
    const val REBOOT = "reboot"
    const val RECON = "recon"
    const val REMOTE_ID = "remoteid"
    const val RESTORE_SPIFFS = "restorespiffs"
    const val SAVE = "save"
    const val SCAN_ALL = "scanall"
    const val SELECT = "select"
    const val SETTINGS = "settings"
    const val SNIFF_BEACON = "sniffbeacon"
    const val SNIFF_BT = "sniffbt"
    const val SNIFF_DEAUTH = "sniffdeauth"
    const val SNIFF_MULTISSID = "sniffmultissid"
    const val SNIFF_PINESCAN = "sniffpinescan"
    const val SNIFF_PMKID = "sniffpmkid"
    const val SNIFF_PROBE = "sniffprobe"
    const val SNIFF_PWN = "sniffpwn"
    const val SNIFF_RAW = "sniffraw"
    const val SNIFF_SAE = "sniffsae"
    const val SNIFF_SKIM = "sniffskim"
    const val SPOOF_AT = "spoofat"
    const val SSID = "ssid"
    const val STOPSCAN = "stopscan"
    const val UPDATE = "update"
    const val UPLOAD = "upload"
    const val WARDRIVE = "wardrive"
    const val WARDRIVE_POI = "wardrivepoi"

    const val JSON_INFO = "jsoninfo"
    const val JSON_STATUS = "jsonstatus"
    const val JSON_LIST = "jsonlist"
    const val JSON_MODE = "jsonmode"
    const val JSON_BAUD = "jsonbaud"

    // --- builders ---------------------------------------------------------------------

    /**
     * `select -a <slot>` toggles one AP slot (CommandLine.cpp, SEL_CMD branch). Verified on a real
     * board, and it bites: `add -a -b <mac> -ch <n> -e <ssid>` inserts the AP **already selected**
     * ("Added AP [0][CH:7] … (selected)"), so following it with `select -a 0` removes the selection
     * and the next `sniffpmkid -l` answers "You don't have any targets selected". Anything that
     * needs a known selection reads the board's own `jsonlist a` / `sel` flag first and toggles only
     * when the flag disagrees — see TargetLock.
     */
    fun toggleAp(slot: Int): String = "$SELECT -a $slot"
    /** `select -a <slot>[,<slot>…]`: one line can address many slots (the firmware splits on `,`). */
    fun selectApSlots(slots: List<Int>): String = "$SELECT -a ${slots.joinToString(",")}"

    /** `select -a all` toggles the whole AP list — which is why clearing must be explicit. */
    fun toggleAllAps(): String = "$SELECT -a all"

    /** `select -s …` / `select -c …` address the SSID and station lists by slot. */
    fun toggleSsid(slot: Int): String = "$SELECT -s $slot"
    fun toggleStation(slot: Int): String = "$SELECT -c $slot"
    fun toggleAllSsids(): String = "$SELECT -s all"
    fun toggleAllStations(): String = "$SELECT -c all"

    /**
     * `select -a 0 -f <filter>`: the filter branch sets `selected` for the whole list in
     * one command, and the `-a` value is ignored there, so 0 is a placeholder, not an index.
     */
    fun selectByFilter(filter: String): String = "$SELECT -a 0 -f $filter"

    /** `clearlist -a|-s|-c` empties one of the firmware's lists. */
    fun clearList(kind: String): String = "$CLEARLIST -$kind"

    /** `list -a|-s|-c|-i|-p|-b|-f|-x|-m`: the firmware's own text dumps, for lists the
     *  JSON layer does not stream (BLE devices, flippers, Pineapple / MultiSSID hits). */
    fun listDump(kind: String): String = "$LIST -$kind"

    fun saveList(kind: String): String = "$SAVE -$kind"
    fun loadList(kind: String): String = "$LOAD -$kind"

    /**
     * The board's own transmitted MACs. These change what the *board* puts on the air; they do not
     * touch what it captures, and a restart puts the firmware's default back.
     * `cloneapmac -a <index>` / `clonestamac -s <index>` copy a MAC out of the firmware's own AP /
     * station lists, so the index is a row of `list -a` / `list -c`.
     */
    fun randomiseApMac(): String = RAND_AP_MAC
    fun randomiseStationMac(): String = RAND_STA_MAC
    fun cloneApMac(slot: Int): String = "$CLONE_AP_MAC -a $slot"
    fun cloneStationMac(slot: Int): String = "$CLONE_STA_MAC -s $slot"

    /**
     * `add -a -b <mac> [-ch <n>] [-e <ssid>]` inserts an AP into the firmware's list.
     * null when the SSID cannot be quoted safely for the firmware's parser.
     */
    fun addAp(mac: String, channel: Int = 0, essid: String? = null): String? {
        val parts = StringBuilder("$ADD -a -b $mac")
        if (channel > 0) parts.append(" -ch $channel")
        if (!essid.isNullOrBlank()) {
            val q = quote(essid) ?: return null
            parts.append(" -e $q")
        }
        return parts.toString()
    }

    /** `ssid -a -g <count>` / `ssid -a -n <name>` / `ssid -r <index>`. */
    fun ssidGenerate(count: Int): String = "$SSID -a -g $count"

    /** null when the name cannot be quoted (a quote, a control character, or edge spaces). */
    fun ssidAdd(name: String): String? = quote(name)?.let { "$SSID -a -n $it" }
    fun ssidRemove(slot: Int): String = "$SSID -r $slot"

    /** `karma -p <index>` — the index is a row of the captured probe-request list. */
    fun karmaProbe(slot: Int): String = "$KARMA -p $slot"

    /** `spoofat -t <index>` / `findmy -t <index>` — indices of the firmware's BLE list (`list -b`). */
    fun spoofAirTag(slot: Int): String = "$SPOOF_AT -t $slot"
    fun findMyBeacon(slot: Int): String = "$FINDMY -t $slot"

    /** `foxhunt …`: the direction-finder modes, each addressed by a list slot. */
    fun foxhuntAp(slot: Int): String = "$FOXHUNT -w $slot"
    fun foxhuntStation(apSlot: Int, staSlot: Int): String = "$FOXHUNT -s $apSlot $staSlot"
    fun foxhuntBle(slot: Int): String = "$FOXHUNT -b $slot"
    fun foxhuntFindMy(slot: Int): String = "$FOXHUNT -t $slot"
    fun foxhuntFlipper(slot: Int): String = "$FOXHUNT -f $slot"
    fun foxhuntPineapple(): String = "$FOXHUNT -p 0"
    fun foxhuntMultiSsid(): String = "$FOXHUNT -m 0"

    /** `info` / `info -a <index>`: the firmware's own device / AP information dump. */
    fun deviceInfo(): String = INFO
    fun apInfo(slot: Int): String = "$INFO -a $slot"

    /** `geofence …`: five slots, radius in miles, name is quoted. null when the name cannot be quoted. */
    fun geofenceList(): String = "$GEOFENCE list"
    fun geofenceSet(
        slot: Int,
        latitude: Double,
        longitude: Double,
        radiusMiles: Double,
        name: String,
    ): String? = quote(name)?.let { "$GEOFENCE set $slot $latitude $longitude $radiusMiles $it" }
    fun geofenceClear(slot: Int): String = "$GEOFENCE clear $slot"

    /** `csimotion …` (ESP32-S3 CSI): starts on an AP slot from the firmware's list. */
    fun csimotionStart(slot: Int): String = "$CSI_MOTION start $slot"
    fun csimotionStatus(): String = "$CSI_MOTION status"
    fun csimotionRecalibrate(): String = "$CSI_MOTION recalibrate"

    /** `recon wifi|ble|status|stop` — the fork's one-shot reconnaissance run. */
    fun recon(target: String): String = "$RECON $target"

    /** `remoteid <scan|list|track|clear> [index]` — drone Remote ID. */
    fun remoteId(action: String, slot: Int? = null): String =
        if (slot == null) "$REMOTE_ID $action" else "$REMOTE_ID $action $slot"

    /** `upload -d <wdg|wigle|both>` — the firmware pushes its wardrive logs to a remote service. */
    fun uploadTo(target: String): String = "$UPLOAD -d $target"

    /** `protocolinfo` / `help`: the firmware's self-description, straight from the device. */
    fun protocolInfo(): String = PROTOCOL_INFO
    fun helpText(): String = HELP

    /** SPIFFS backup to / restore from the SD card (SD-only boards). */
    fun backupSpiffs(): String = BACKUP_SPIFFS
    fun backupStatus(): String = BACKUP_STATUS
    fun restoreSpiffs(): String = RESTORE_SPIFFS

    /** `channel` prints the board's set channel; `channel -s <n>` pins it. With `ChanHop`
     *  off this is how a non-pmkid sniff is kept on one channel: the scan verbs do not
     *  parse `-c` themselves (`CommandLine::startScanFromCLI` ignores their arguments). */
    fun currentChannel(): String = CHANNEL
    fun channelSet(channel: Int): String = "$CHANNEL -s $channel"

    fun brightnessCycle(): String = "$BRIGHTNESS -c"
    /** `brightness` with no flags prints the board's own level — the read-only form, and the only
     *  one worth offering before anything is written. */
    fun brightnessCurrent(): String = BRIGHTNESS
    fun brightnessLevel(level: Int): String = "$BRIGHTNESS -s $level"
    fun ledColor(hex: String): String = "$LED -s $hex"
    fun ledPattern(name: String): String = "$LED -p $name"

    /** `settings` dumps the board's settings as plain `Name:/Type:/Value:` lines. */
    fun settingsDump(): String = SETTINGS
    fun settingsSet(key: String, enabled: Boolean): String =
        "$SETTINGS -s $key ${if (enabled) "enable" else "disable"}"
    fun settingsReset(): String = "$SETTINGS -r"

    /** `join -a <index> -p <password>` / `join -s`. The index is a row of the AP list. */
    fun joinAp(slot: Int, password: String): String = "$JOIN -a $slot -p $password"
    fun joinSaved(): String = "$JOIN -s"

    /** `evilportal …`: the captive-portal verbs, including the fork's serial HTML upload. */
    fun evilPortalStart(html: String): String = "$EVIL_PORTAL -c start -w $html"
    fun evilPortalSetHtml(name: String): String = "$EVIL_PORTAL -c sethtml $name"
    fun evilPortalSetHtmlString(length: Int): String = "$EVIL_PORTAL -c sethtmlstr $length"
    fun evilPortalSetAp(slot: Int): String = "$EVIL_PORTAL -c setap $slot"

    /** `attack -t deauth -s <src> -d <dst>`: a single targeted deauth pair, no capture. */
    fun attackDeauthPair(sourceMac: String, targetMac: String): String =
        "$ATTACK -t deauth -s $sourceMac -d $targetMac"

    fun bleSpam(type: String): String = "$BLESPAM -t $type"
    fun attack(mode: String): String = "$ATTACK -t $mode"
    fun portScan(service: String): String = "$PORTSCAN -s $service"
    fun portScanAll(slot: Int): String = "$PORTSCAN -a -t $slot"
    fun analyzer(kind: String): String = "$ANALYZER -t $kind"
    fun sniffBt(type: String? = null): String = if (type == null) SNIFF_BT else "$SNIFF_BT -t $type"
    fun ls(directory: String = "/"): String = "$LS $directory"

    /** `update -s` — the only update path the firmware dispatches (it needs an SD card). */
    fun updateFromSd(): String = "$UPDATE -s"

    /** `wardrivepoi [label]` — tag a point of interest while a wardrive is running.
     *  null when the label cannot be quoted for the firmware's parser. */
    fun wardrivePoi(label: String? = null): String? =
        if (label.isNullOrBlank()) WARDRIVE_POI else quote(label)?.let { "$WARDRIVE_POI $it" }

    /** `stopscan` / `stopscan -f`. */
    fun stopscan(force: Boolean = false): String = if (force) "$STOPSCAN -f" else STOPSCAN

    /**
     * `sniffpmkid [-c <ch>][-d][-l]`. The flags change the firmware's scan mode, and with
     * it whether the radio stays where it was pinned — see [CaptureOps].
     */
    fun sniffPmkid(channel: Int = 0, deauth: Boolean = false, listOnly: Boolean = false): String =
        buildString {
            append(SNIFF_PMKID)
            if (channel > 0) append(" -c $channel")
            if (deauth) append(" -d")
            if (listOnly) append(" -l")
        }

    /**
     * `gpspoi -s|-m|-e`: begin a point-of-interest log, mark the position it is at now, write the log
     * out. The board's own three-step form; there is no separate "stop" for it.
     */
    fun gpsPoi(what: String): String = "$GPS_POI -$what"

    /** `gps [-g <what>]` / `gps -n <system>` — needs a board with a GPS module (`gps` cap). */
    fun gpsGet(what: String): String = "$GPS -g $what"
    fun gpsSetSystems(system: String): String = "$GPS -n $system"

    /**
     * `gps -n beidou -b`: the parser reads `-b` only inside the `-n beidou` branch, and
     * `-b` picks BD over GB. Bare `gps -b` is not a command — it reaches no branch at all.
     */
    fun gpsBeidouBd(): String = "$GPS -n beidou -b"

    /**
     * `gps -g nmea [-r|-i|-p]`: which of the module's sentences to print. No flag prints
     * the generated GGA + RMC pair; `-r` everything received, `-i` sentences the library
     * has no handler for, `-p` sentences the board could not parse.
     */
    fun gpsNmea(filter: String? = null): String =
        if (filter.isNullOrBlank()) "$GPS -g nmea" else "$GPS -g nmea -$filter"

    /**
     * `gps -t` — the board's own GPS tracker, which is what the firmware's `gpstracker` help line
     * describes but never starts: the tracker mode begins here and ends with `stopscan`, like the
     * other GPS modes the firmware starts as a scan (`gpsdata` even says so out loud). This is a
     * different thing from the app's phone-GPS track file, which never touches the wire.
     */
    fun gpsTracker(): String = "$GPS -t"

    /**
     * Quote one argument for the firmware's parser, or null when it cannot be quoted.
     * Delegates to [FirmwareArg], the app's one rule for handing text to
     * `CommandLine::parseCommand` (it splits on spaces, keeps quoted text intact, and has
     * no escape mechanism — so a value with both quote kinds or a control character is
     * refused instead of silently mangled).
     */
    fun quote(value: String): String? = FirmwareArg.wrap(value)

    /**
     * Verbs the app reaches only through a slot or an argument the user fills in, with one
     * live sample command each — [FirmwareCoverageTest] checks that sample against the
     * builder, so the map cannot rot into a comment.
     */
    val dynamic: Map<String, String> = linkedMapOf(
        SELECT to toggleAp(0),
        CLEARLIST to clearList("a"),
        LIST to listDump("b"),
        ADD to requireNotNull(addAp("AA:BB:CC:DD:EE:FF", 6, "lab ap")),
        SSID to ssidRemove(0),
        KARMA to karmaProbe(0),
        SPOOF_AT to spoofAirTag(0),
        FINDMY to findMyBeacon(0),
        FOXHUNT to foxhuntAp(0),
        CLONE_AP_MAC to cloneApMac(0),
        CLONE_STA_MAC to cloneStationMac(0),
        INFO to apInfo(0),
        GEOFENCE to geofenceClear(1),
        CSI_MOTION to csimotionStart(0),
        CHANNEL to channelSet(6),
        BRIGHTNESS to brightnessLevel(5),
        SETTINGS to settingsSet("ChanHop", true),
        JOIN to joinAp(0, "x"),
        EVIL_PORTAL to evilPortalSetAp(0),
        ATTACK to attackDeauthPair("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"),
        UPLOAD to uploadTo("wigle"),
        WARDRIVE_POI to requireNotNull(wardrivePoi("campus")),
        GPS to gpsSetSystems("all"),
        LS to ls("/spiffs"),
        REMOTE_ID to remoteId("track", 0),
        RECON to recon("ble"),
    )

    /**
     * Verbs the app sends without a catalog entry, from its own control flow. Each note
     * names the place that sends it, so coverage stays checkable.
     */
    val appInternal: Map<String, String> = linkedMapOf(
        STOPSCAN to "every live screen's Stop control and screen exit (MarauderViewModel.stopLiveActivity)",
        JSON_INFO to "board handshake on connect + the board card on Home",
        JSON_STATUS to "status poll while a scan, attack or mission runs",
        JSON_LIST to "live list polling (jsonlist <code>) and selection read-back",
        JSON_MODE to "JsonSerial on/off while switching between console and structured mode",
        JSON_BAUD to "the higher baud rate the capture stream needs (capstream boards)",
        SAVE to "Save chips on the AP / SSID list screens (save -a, save -s)",
        LOAD to "SD persistence entries (load -a, load -s)",
        REBOOT to "Reboot on Home and in the Device menu",
        UPDATE to "Update Firmware (SD boards only) in the Device menu",
        ANALYZER to "the live analyzer graphs",
    )
}
