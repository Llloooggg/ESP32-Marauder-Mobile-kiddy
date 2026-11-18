# SPEC-M1 — UI rework: entity lists + mission engine + artifacts + catalog tiers

Repo: `C:\Users\burzuf\Documents\Projects\ESP32-Marauder-Mobile-kiddy` (Kotlin/Compose, v1.3.4 base).
Goal: replace the "command menu" UX with a product flow: board → scan → AP card → one-tap capture → artifact → crack. Raw CLI mode is preserved under "Advanced". English only, keep existing theme/design system.

## Hard constraints
- You OWN: `app/src/main/java/com/marauder/mobile/ui/**`, `vm/**`, `data/**` (except don't move protocol classes), `crack/` **except `crack/CrackEngine.kt` (contract, import only)**, `AndroidManifest.xml` + new `res/xml/file_paths.xml`.
- Do NOT touch: `app/build.gradle.kts`, `settings.gradle.kts`, `extractor/**`, `protocol/**`, `esp/**`, `usb/**`, `capture/**` (read freely). Do NOT run gradle (the orchestrator builds).
- Firmware reference (read-only): `C:\Users\burzuf\Documents\Projects\ESP32Marauder-jsonserial\esp32_marauder\` — verify every command's exact syntax in `CommandLine.cpp` before adding it.
- Protocol layer already delivers: DeviceMessage (Info w/ caps, Status, Ap/Sta/Ssid/Ip/Probe/Airtag/Rid/Fence rows, Analyzer, FoxHunt, Csi, Drop, Cred, End...), capture frames (CaptureFrame: seq/type/payload + gap tracking), `settings -s SavePCAP enable` handled in VM.

## Firmware command facts (verified, use exactly)
- Active capture flow = `select -a <ap_index>` then `sniffpmkid -d -l -serial` (WIFI_SCAN_ACTIVE_LIST_EAPOL: sends deauth around target, captures PMKID/EAPOL, streams pcap via capstream). Global active (no list): `sniffpmkid -d -serial`. Passive: `sniffpmkid -serial`.
- `attack -t deauth -c` = station-targeted DoS flood, produces NO pcap (rename UI text accordingly: "Deauth Flood (targeted) — DoS").
- EAPOL capture signal (text): console line `Received EAPOL: <mac>`; beacons too. PMKID presence is determined client-side from the pcap later (extractor).
- `stopscan` stops any scan/attack. `-serial` valid for all scan/attack commands.
- caps from jsoninfo vocabulary: `wifi, capstream, bt, remoteid, foxhunt, recon, csi, gps, sd, screen` (absent cap ⇒ hide that feature: e.g. no `sd` → hide ls/save/load files; no `gps` → hide board-GPS-only items but keep app-fed wardrive; `screen`-only niceties hidden).

## Deliverables

### 1. Navigation (`ui/Navigation.kt`)
New routes; keep old ones reachable from Advanced:
`connect`, `home` (new root when connected), `scan`, `ap/{index}`, `mission/{id}`, `artifacts`, `artifact/{id}`, `crack/{artifactId}`, `wordlists`, `advanced` (entry) + existing `menu/{id}` subtree (only reachable from advanced), `console`, `analyzer/*`, `live/*`, `evil_portal`, `flash`, `about`.
ConnectionGate: CONNECTED → `home`; DISCONNECTED → `connect` (keep flash-screen exemption logic).

### 2. HomeScreen (`ui/screens/HomeScreen.kt`)
- Board card: board/fw/proto from `vm.info`, caps chips, free heap from `vm.deviceStatus` (VM must poll `jsonstatus` every 1s while connected — add to VM, reuse existing status plumbing). Buttons: "Flash firmware" (route flash; if board model isn't in FirmwareRepository profiles, show a "flash from PC" info note — check esp/FirmwareRepository + FlashScreen for the profile list), "Reboot".
- Active mission card when `vm.activeMission != null`: title, kind icon, counters (frames/bytes/EAPOL/drops), Open/Stop.
- Quick actions: "Scan networks" → scan; "Artifacts" → artifacts; "Wordlists" → wordlists.
- Category grid (each = submenu screen reusing MenuScreen infra, but data-driven from Catalog with tiers — see §6): Situational awareness / Wardrive & GPS / Radio direction finding / WiFi security / Bluetooth (anti-stalking + remoteid green; spam under LAB red) / Board & power.

### 3. ScanScreen (`ui/screens/ScanScreen.kt`) — replaces raw "Scan AP/STA" flow
- Big Start ("scanall -serial")/Stop button; while running VM polls `jsonlist a` every 2s (`vm.startApPolling()`/`stopApPolling()` — new VM funcs using existing refreshList plumbing; keep list fresh after scan ends too).
- AP card grid: ESSID, BSSID, channel, RSSI bar, security lock icon, packets; sort by RSSI/clients/packets; search box filter; live updates (StateFlow already there).
- EAPOL badge per AP: VM keeps per-MAC counts of `Received EAPOL: <mac>` console lines (extend data/LiveClassifier.kt: extract mac from that line; store in mission counters by bssid) — show chip "EAPOL×n" on matching card.
- Card tap → `ap/{index}`.

### 4. ApDetailScreen + actions bottom sheet
- Show AP entity fields + all stations from `vm.stations` (sorted, search).
- Bottom-sheet actions with policy gates:
  - **Capture Handshake / PMKID** (MODERATE): confirm dialog ("deauth frames will be sent — your own network only") → start Mission(CAPTURE): `stopscan` if running → `select -a idx` → `sniffpmkid -d -l -serial`.
  - **Passive EAPOL listen** (SAFE): mission `sniffpmkid -serial`.
  - **Deauth flood** (MODERATE): `attack -t deauth -c` after select; no capture artifacts.
  - **Fox hunt** / **Analyze channel** (SAFE) — verify foxhunt AP-target syntax from CommandLine.cpp.
- If AP has 0 known clients: show inline hint "handshake needs a client; PMKID may still work".

### 5. Mission engine (vm/MarauderViewModel.kt + vm/Mission.kt)
```
data class Mission(id, title, kind: Kind, mainCommand, startedAt, frames, bytes, seqGaps, ringDrops, eapolByMac: Map<String,Int>, artifactId: String?)
enum Kind { SCAN, SNIFF, CAPTURE, WARDRIVE, HUNT, ATTACK, PORTAL }
```
- `startMission(spec)`: stop current (stopscan), run setup commands, send main command (auto `-serial` for CAPTURE/WARDRIVE when `capstream` cap present — mirror existing startLiveActivity's flag logic).
- Wire existing capture-frame pipeline into the mission (frames/bytes/gap counters already exist in CaptureUiState — reuse).
- On stop/end: if kind==CAPTURE and sink got bytes → `ArtifactsRepository.add(...)` with meta (bssid/essid/title, counts incl. eapolByMac totals) + snackbar "Capture saved → Artifacts".
- Keep `startLiveActivity`/`live/{title}/{cmd}` untouched for Advanced raw menu use.
- Handle `@J drop` (already parsed): accumulate ringDrops; heap-low: if `vm.deviceStatus.free < 40k` while CAPTURE → auto `stopscan` + snackbar.

### 6. Catalog metadata (data/Catalog.kt)
- Add to `MenuItem`: `tier: Tier` (enum SAFE/MODERATE/HIGH, default SAFE) and `requiresCaps: Set<String>`.
- Menu rendering filters items by `vm.info.caps`. MODERATE items → single confirm AlertDialog showing command + "own networks only" line. HIGH items (BLE spam, spoofat, evil portal, karma, deauth floods…) → render under a "LAB — active interference" section header with two-step confirm (checkbox acknowledgement + confirm). Keep `dangerous` flag semantics working (or derive from tier).
- Bug fixes in the tree: in wifi_sniffers, "EAPOL/PMKID Scan" → "Passive EAPOL listen" (`sniffpmkid`) + NEW entry "Active PMKID/Handshake capture" (`sniffpmkid -d -serial`, MODERATE, needs select first — subtitle explains "pick an AP in Scan first"). "Deauth Targeted" → "Deauth Flood (targeted) — DoS only".
- Home category grids reference these same screens (single source of truth).

### 7. Artifacts (data/ArtifactsRepository.kt, ui/screens/ArtifactsScreen.kt, ui/screens/ArtifactDetailScreen.kt)
- Store: `context.filesDir/artifacts/` + `index.json` (kotlinx.serialization; model: id, createdAtMs, kind pcap|log|gpx|csv, title, fileName, size, meta map incl. bssid/essid, hashState: NONE|EXTRACTED(counts)|ERROR(msg), extractedLines path).
- Migration: first run — move existing files from `getExternalFilesDir("captures")` (old CaptureSink path) into artifacts store, record as artifacts (kind by extension).
- CaptureSink writes mission files directly into artifacts dir (adjust path in VM's sink setup — sink class itself unchanged).
- Sharing/export: FileProvider (`file_paths.xml` under files/ artifacts) → ACTION_SEND intent; plus ACTION_CREATE_DOCUMENT copy. Delete = remove file + index entry.
- Artifact detail: metadata, size/date, "Analyze hashes" → runs **ExtractionBridge** (interface `data/ExtractionBridge.kt` you define: `fun extract(file: File): HashExtractResult?` with counts of PMKID/M2; default no-op returning null with a toast "extractor not wired"; the orchestrator wires `:extractor` later), "Crack" → `crack/{id}` (enabled when hashState EXTRACTED with ≥1 line), share, delete.
- Also fold existing evil-portal creds + wardrive outputs into artifacts where cheap (kind csv/log) — don't break EvilPortalScreen behavior.

### 8. Cracker shell (ui/screens/CrackScreen.kt, vm/CrackViewModel.kt)
- Built ONLY against `crack/CrackEngine.kt` contract (import it; DI a `CrackEngine` instance — currently `NoopCrackEngine`).
- UI: target summary (essid/bssid, PMKID/M2 chip counts), wordlist multi-select (from WordlistRepository), backend chips AUTO/CPU/GPU, "Run bench" button (shows h/s or "engine unavailable"), Start/Stop, progress bar + rate + ETA, found banner "Password: xxx", history list (cracked artifacts persist result in artifact index meta).

### 9. Wordlists (data/WordlistRepository.kt, ui/screens/WordlistsScreen.kt)
- Assets seed: `assets/wordlists/probable-wpa-top4800.txt` (+ LICENSE file) copied to `filesDir/wordlists/` on first launch (keep LICENSE alongside; show name+size).
- Import via SAF (ACTION_OPEN_DOCUMENT, text/*), copy in, name = original.
- URL download: text field + progress (HttpURLConnection + redirects, mirror esp/FirmwareRepository.fetch pattern — copy code, don't import esp).
- List UI: rows w/ size, delete, pick default. Wordlist entries feed CrackConfig.wordlists (multi-select ordered).

### 10. Onboarding terms
First launch after first successful `Info`: full-screen dialog (Datastore flag in data/SettingsRepository.kt): "Authorised use only: your own networks/devices or written permission. The app enables active RF operations." Accept required. Settings entry to re-show.

### 11. Polish
- Keep ConsoleScreen & ListContent working (used by Advanced).
- Add bottom nav or persistent top app bar entries: Home / Scan / Artifacts / Settings-ish (board) — your choice, keep minimal churn.
- Unit tests (app/src/test): Mission state transitions (counters, end→artifact), ArtifactsRepository index round-trip, Catalog tier/caps filtering, WordlistRepository seeding logic (Robolectric NOT available — test pure logic only; keep logic in plain classes).

## Acceptance
`gradlew assembleDebug` must compile when orchestrator runs it (they will fix minor compile breaks). No changes to protocol/esp/usb semantics. All existing firmware commands still reachable via Advanced tree.
