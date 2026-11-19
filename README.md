<div align="center">

<img src="app/src/main/res/drawable-nodpi/marauder_skull.png" width="120" alt="Marauder logo" />

# Marauder Mobile

**An Android controller for the [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder).**
Drive the firmware entirely over USB — no PC, no server, no extra hardware.

by **Mohammed Ali** · GitHub [@0xsys](https://github.com/0xsys)

</div>

---

## About this build (`kiddy`)

This is **Marauder Mobile Kiddy** — the **`ESP32-Marauder-Mobile-kiddy`** build: a
working branch on top of Marauder Mobile, named after its repository. It installs
**alongside** the upstream app — the launcher entry is **Marauder Mobile Kiddy**
(truncated by some launchers), the installed id is `com.marauder.mobile.kiddy`
(the Kotlin code namespace stays `com.marauder.mobile`). Each install keeps its
own private data directory, so captures and wordlists do not mix; move files
between them with **Share** / **Export copy** in the Library.

What this build adds over upstream: a capture **library** (pcap / gpx / log /
csv on the phone), a **pcap → hashcat-22000 extractor** (PMKID + handshake
pairs, ANonce recovery from M3, resync of captures damaged in transit), a
**built-in cracker** with three engines behind one contract (JVM, a native C++
core, and a Vulkan compute engine) each gated by a known-answer test that runs on
the device, rate/ETA and a hash inspector, **BSSID-pinned** targeted operations
(every capture records the BSSID it was aimed at, and every index-addressed
firmware command is resolved from identity at press time or refused), WPA3/SAE
**detection with an honest verdict** rather than wasted wordlist time, a per-session
**journal** and one-tap **report export** (markdown + zip), and CSV exports of
every list.

## What it is

Marauder Mobile is a native Kotlin / Jetpack Compose app that turns an Android
phone into a full control surface for an ESP32 running the Marauder firmware. It
talks to the board over USB-OTG serial and speaks the firmware's **JSON serial
interface** (`jsoninfo` / `jsonstatus` / `jsonlist` / `jsonmode` + `analyzer`),
so instead of scraping human-readable CLI text it consumes clean, structured
`@J {…}` messages — letting you use the Marauder headlessly, without its screen.

The UI mirrors the on-device menus (same titles, same ordering): **WiFi →
Sniffers / Scanners / Attacks / General**, **Bluetooth → Sniffers / Attacks**,
**GPS**, **Device**. Every command opens its own **live results screen** that
streams in real time.

## Screenshots

<div align="center">

<img src="docs/screenshots/phone-esp32.jpg" width="460" alt="Marauder Mobile running on an Android phone connected to an ESP32 Marauder" />

</div>

<div align="center">

<img src="docs/screenshots/menu.png"    width="220" alt="Main menu with centered logo, live status panel and credit" />
&nbsp;
<img src="docs/screenshots/wifi.png"    width="220" alt="WiFi menu — sniffers, scanners, attacks, general" />
&nbsp;
<img src="docs/screenshots/console.png" width="220" alt="Raw serial console showing the jsoninfo handshake" />

</div>

## Requirements

- **An ESP32 running Marauder firmware** — that's it.
  No server, no desktop tool, no second device.
- An Android phone (Android 8.0 / **API 26+**) with **USB host / OTG** support.
- A USB-C / USB-OTG cable between the phone and the board.

Supported serial bridges: Silicon Labs CP210x, CH340/CH9102, FTDI, PL2303, and
Espressif native USB-CDC (ESP32-S2/S3/C3). The app can auto-launch when the board
is plugged in.

## Usage

1. Flash your ESP32 with a Marauder build that includes the JSON serial
   interface — see [Firmware](#firmware) below (available from
   [the fork](https://github.com/0xsys/ESP32Marauder) until it lands upstream).
2. Connect the board to your phone with a USB-OTG cable. Android offers to open
   **Marauder** and grants USB permission — or open the app first and tap
   **Connect**.
3. The app opens the port at **115200 8N1**, waits for the board to settle, then
   handshakes with `jsoninfo` and polls `jsonstatus`. The status panel shows
   board / firmware / capabilities, live scan mode, free heap and list counters.
4. Browse the menus. Each entry runs a real firmware command and opens a live view:
   - **Lists** — access points, stations, SSIDs, probes, IPs, AirTags
     (streamed via `jsonlist`).
   - **Analyzers** — Channel / BT graphs and the Channel Summary bar chart,
     streamed screen-free from the `asample` / `chan` messages.
   - **Console** — a raw serial terminal for anything not in the menus.

> ⚠️ The attack and spam features (deauth, beacon spam, BLE spam, …) are for
> **authorised testing only**. Use them exclusively on devices and networks you
> own or have explicit permission to test. You are responsible for complying with
> local law.

## Features

- 🧭 **Playbooks — the reason this build is called `kiddy`** — thirteen guided jobs
  ("get a handshake from one network and crack it", "wardrive the area", "evil portal
  with a page from the phone", "find the box physically"). Each one shows its steps, the
  firmware command behind every step, and what it produces afterwards; a job that
  addresses one network takes that network's live slot and channel from the board's
  current scan list when Run is pressed, and refuses to start if a value is missing.
- 📡 Full WiFi suite — sniffers, scanners, and attacks with live counters.
- 🔵 Bluetooth — BLE sniffers, AirTag detection, and BLE spam tools.
- 🛰️ GPS — data, NMEA stream, tracker, and points of interest.
- 📈 Live analyzers — Channel Analyzer, BT Analyzer, and Channel Summary.
- 🗂️ Structured device lists parsed straight from the firmware.
- 🖥️ Raw serial console.
- 🎨 **Light & dark themes** — toggle from the main screen; the choice persists.
- 🔌 Auto-detect & auto-connect on USB attach.
- 📦 **Artifact library** — captures, wardrive logs and GPX on the phone; one tap
  turns a pcap into hashcat-22000 lines (PMKID + M1/M2 extraction, pure Kotlin).
- 🔑 **Built-in WPA2 cracker** — hashcat-22000 semantics (PMKID and M1/M2), CPU
  and GPU back ends, KAT-tested. Ships with a built-in wordlist; add your own by
  URL or file picker. No root, no Termux.
- ⚙️ **Two native engines, each gated by its own known-answer test** — a C++ core
  on the phone's cores, and a Vulkan compute engine that runs the 4096 PBKDF2
  rounds per guess on the graphics cores. Neither is trusted because it compiled:
  both must reproduce hashcat's published vectors on *this* device, and if they
  cannot, the app says so and runs the engine it can prove.
- 🎯 **Target-pinned operations** — every targeted capture is bound to a BSSID
  checked against the scan ledger before anything is transmitted, and each
  capture records which BSSID it was aimed at.
- 🧾 **The firmware's whole command surface, and a test that keeps it that way** —
  `FirmwareCommands` is the census of every verb the board answers (63 CLI verbs from
  `CommandLine.h` plus the 5 JSON helpers), each with the syntax copied out of the
  firmware's own help strings, and `FirmwareCoverageTest` fails if any of them stops
  being reachable from the UI. Verbs that need a list index (`spoofat -t`, `findmy -t`,
  `foxhunt -b/-t/-f`, `karma -p`, `ssid -r`, `geofence clear`, `remoteid track`,
  `csimotion start`, `add -a -b`) prompt for it, show the exact command before sending
  it, and name the list the index comes from (`list -b`, the probe list, the IP list).
  Verbs the firmware has commented out (`scansta`, `btwardrive`, …) are never sent.
- 🎛️ **Board settings, read back** — the firmware's own switches (`ChanHop`,
  `SavePCAP`, `ForcePMKID`, `EPDeauth`, …) are listed from its `settings` dump and
  written with `settings -s <key> enable|disable`; only boolean settings are editable,
  because that is all the CLI accepts, and every write is followed by a fresh read, so
  a change the board did not apply is reported as failed.
- 🔐 **WPA3-aware, honestly** — SAE-only networks are detected and reported as
  uncrackable by design (their PMK is not PBKDF2-derived) rather than burned
  through a wordlist.
- 🛡️ **One consent surface, not one per command** — the authorised-use terms are
  accepted once, in the banner shown on first launch. Nothing in the catalog is
  hidden behind a mode switch or a second confirmation: every command the connected
  board can run is one tap away, and the tier colour on a card is only a statement
  of how loud that command is. What is transmitted, and against which BSSID, is
  written on the card itself.
- 🧷 **Capture reliability, fixed at the cause** — two firmware behaviours silently
  blank a PMKID/EAPOL capture, so the app deals with them before the run instead of
  explaining an empty pcap afterwards: a `sniffpmkid -c <ch>` run only *sets* the
  channel (the scan loop keeps hopping every 2 s unless the persisted `ChanHop`
  setting is off, so the app switches it off for the run and puts it back after),
  and any network left selected by an earlier targeted run puts the EAPOL sniffer
  into selected-only mode, where frames of every other AP are dropped before they
  are counted or buffered (the app deselects them and reads the list back to prove
  it). If the state cannot be proven, the capture is refused rather than started.
  The same source-level check also says what *cannot* be fixed: only `sniffpmkid`
  reads `-c` (every other scan verb goes through a dispatch path that ignores its
  arguments), so the app pins those modes with `channel -s <n>` plus the gated hop
  off — and for the modes whose hop loop is not gated at all (`scanall`, `sniffsae`,
  `sniffpwn`, `sniffpinescan`, `sniffmultissid`) and for `sniffpmkid -d` without
  `-l`, it says out loud that the board will walk the channels instead of letting a
  wrong-channel capture look like an empty one.

## Protocol (firmware ↔ app)

- **App → device:** plain firmware CLI commands + `\n`. JSON helpers:
  `jsoninfo`, `jsonstatus`, `jsonmode 0|1`, `jsonlist a|s|c|i|p|t`, and
  `analyzer -t wifi|bt|chan`.
- **Device → app:** every machine-readable line is tagged `@J ` followed by a
  JSON object keyed by `t` (`info`, `status`, `jsonmode`, `ap`, `sta`, `ssid`,
  `ip`, `probe`, `airtag`, `end`, `err`, `asample`, `chan`). Any other line is
  treated as ordinary console text.

See `protocol/LineParser.kt` and the firmware's `JsonSerial.cpp` for the source
of truth.

## Themes

The app ships a dark theme (default) and a light theme. Toggle it from the icon
in the main screen's top bar; the choice is saved with DataStore and restored on
next launch.

## Building

Requirements: **JDK 21**, the **Android SDK** (compileSdk 35) with the **NDK**
(`27.0.12077973`, pinned in `app/build.gradle.kts`) and **CMake** for the native
cracking engines, and the bundled Gradle wrapper (8.9). Point
`local.properties` at your SDK:

```properties
sdk.dir=/path/to/Android/sdk
```

**Debug build + unit tests:**

```bash
./gradlew :app:assembleDebug :app:testDebugUnitTest
```

Debug APKs land in `app/build/outputs/apk/debug/`, one per ABI
(`arm64-v8a`, `armeabi-v7a`, `x86_64`) plus a universal build. On a modern
phone install the `arm64-v8a` one — e.g. `app-arm64-v8a-debug.apk`.

**Release build:**

```bash
./gradlew :app:assembleRelease
```

Signed release APKs land at `app/build/outputs/apk/release/` (same per-ABI
split) when `keystore.properties` and the keystore it names are present —
which is the supported way to sideload this build. Without them the release
APKs stay unsigned and will not install.

Check what an APK really is before installing it (package id, version, ABIs,
signer):

```bash
"$ANDROID_SDK/build-tools/35.0.0/aapt2" dump badging app-arm64-v8a-release.apk
"$ANDROID_SDK/build-tools/35.0.0/apksigner" verify --print-certs app-arm64-v8a-release.apk
```

### Release signing

Release signing is driven by an optional `keystore.properties` at the project
root. It (and the keystore) are **git-ignored** and must never be committed. If
the file is absent, the release build still compiles — just unsigned.

Create a keystore and a matching properties file:

```bash
keytool -genkeypair -v \
  -keystore marauder-release.jks -alias marauder \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=Your Name, O=YourOrg, C=XX"
```

```properties
# keystore.properties  (project root; storeFile is resolved from here)
storeFile=marauder-release.jks
storePassword=your-store-password
keyAlias=marauder
keyPassword=your-key-password
```

> Keep the keystore and its passwords private — never put real credentials in
> this README, in `README`s, or anywhere in the repo. `keystore.properties` and
> `*.jks` are already git-ignored.

### Cracking engines and their known-answer gates

The cracker has three implementations behind one contract
(`app/src/main/java/com/marauder/mobile/crack/`): a JVM engine, a native C++ core
(`app/src/main/cpp/`, reached over JNI), and a Vulkan compute engine that runs
each guess's 4096 PBKDF2 rounds on the graphics device. Whichever runs, the
22000 line is parsed by the same Kotlin `CrackCore` and the MIC/PMKID comparison
is done by the same `verify_with_pmk` — the back ends differ only in where the
hashing runs, so a GPU run and a CPU run cannot report different things about
one hash.

Loading the `.so` is not enough to use it, and compiling the shader is not
enough to use the GPU. Both are gated by a known-answer test that runs on the
device itself (`NativeCrypto.nativeSelfTest()` / `nativeGpuSelfTest()`): the
native core must reproduce hashcat's published PMKID and handshake vectors, the
shader must reproduce the same PMKs this repo's own CPU code produces across
every ESSID/salt alignment and candidate length. If a gate fails, the engine is
refused and the crack screen states why, because a subtly wrong engine reports
"not cracked" for a password that is in the wordlist — the one outcome this app
must never present as an answer.

Those same gates are runnable on a development host, which is where the shader
and the batch loop are actually exercised (the phone only has to answer whether
*its* driver agrees too):

```bash
# native core + batch loop, no Android or driver needed
g++ -std=c++17 -O2 -Wall -Wextra -pthread -DMK_SELFTEST_MAIN \
    wpa_crypto.cpp selftest.cpp -o selftest && ./selftest

# Vulkan engine against a software driver (e.g. mesa-vulkan-drivers / llvmpipe),
# including CPU↔GPU agreement on one shared set of fixtures
g++ -std=c++17 -O2 -Wall -Wextra -pthread -DMK_GPU_HOST_TEST \
    wpa_crypto.cpp vulkan_engine.cpp gpu_host_test.cpp -o gpu_host_test -lvulkan && ./gpu_host_test
```

Shader sources are compiled into the native library as SPIR-V headers. After
changing a `.comp`, regenerate them (uses the NDK's `glslc`):

```powershell
tools\regen_shaders.ps1
```

### Lab tooling

The same extraction and cracking code is available as command-line tasks, so a
capture can be checked on a PC without a phone:

```bash
./gradlew :extractor:extractPcap -PtoolArgs="C:/tmp/cap.pcap -o C:/tmp/hashes.22000.txt"
./gradlew :extractor:crackHash  -PtoolArgs="C:/tmp/hashes.22000.txt C:/tmp/wordlist.txt"
```

Raw captures, real 22000 files and wordlists are git-ignored on purpose; only
synthetic fixtures and published vectors are committed.

## Project layout

```
app/src/main/java/com/marauder/mobile/
├── data/          # menu catalog, list types, settings (DataStore)
├── protocol/      # @J line parser + typed DeviceMessage model
├── usb/           # USB-serial transport
├── vm/            # MarauderViewModel (state + command orchestration)
├── ui/            # Compose screens, components, theme
└── MainActivity.kt
app/src/main/java/com/marauder/mobile/crack/   # engine contract + the three engines
app/src/main/cpp/                              # native core, JNI bridge, Vulkan engine
└── shader/        # Vulkan compute sources (regenerate headers with tools/regen_shaders.ps1)
extractor/                                     # pcap -> hashcat-22000 + verifier (pure Kotlin,
                                               # also the lab command-line tools)
protocol/                                      # LineParser, shared with tests
```

## Firmware

This app needs an ESP32 Marauder firmware that includes the **JSON serial
interface**. That support is added in my fork (submitted upstream via
[PR #1346](https://github.com/justcallmekoko/ESP32Marauder/pull/1346)):

- **Firmware fork that supports this app:** <https://github.com/0xsys/ESP32Marauder>
  — branch [`feature/json-serial-interface`](https://github.com/0xsys/ESP32Marauder/tree/feature/json-serial-interface).
  Grab a prebuilt `.bin` from its **Releases**, or build it from source.
- Upstream Marauder: <https://github.com/justcallmekoko/ESP32Marauder>

Until the interface is merged upstream, flash the build from the fork above.

## Credits

- **Mohammed Ali** — GitHub [@0xsys](https://github.com/0xsys)
- Repository: <https://github.com/0xsys/ESP32-Marauder-Mobile>
- ESP32 Marauder firmware by [justcallmekoko](https://github.com/justcallmekoko/ESP32Marauder)

## License

Released under the [MIT License](LICENSE) © 2026 Mohammed Ali.
