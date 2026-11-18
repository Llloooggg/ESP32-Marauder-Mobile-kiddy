# SPEC-M3 — native WPA2 cracker engine (C11/NDK) for hashcat mode 22000

Work dir: `C:\Users\burzuf\Documents\Projects\ESP32-Marauder-Mobile-kiddy\app\src\main\cpp\` (create it). Do NOT touch app Gradle files (orchestrator wires `externalNativeBuild` later), do NOT touch `crack/CrackEngine.kt` contract, ui/** or anything outside `cpp/`. Do NOT run gradle.

## Engine semantics (hashcat 22000-compatible)
Per guess `pass` (bytes, ≤63, raw UTF-8, no trim beyond line ending):
1. `PMK = PBKDF2-HMAC-SHA1(pass, SSID, 4096, 32)`.
2. PMKID check: `PMKID = HMAC-SHA1(PMK, "PMK Name" || AA || SPA)[0..15]` vs stored.
3. Handshake check: `PTK = PBKDF2-HMAC-SHA1(PMK, "Pairwise key expansion" || minmax(AA,SPA) || minmax(ANonce,SNonce), 1, 624 bits)`; KCK = first 16 bytes.
   Verify M2 MIC exactly per 22000/hccapx semantics: reconstructed 802.11 M2 frame (10 bytes FC/sub+dur+4 addr... exact construction per hccapx: 80211_HEADER_M2 with E type/subtype, zeroed DurID, replay counter field zeroed in EAPOL body, mic+keylen zeroed, length field set accordingly; fetch hccapx spec/hashcat docs if needed — then **validate against known-answer tests below; KAT is the source of truth, adjust until it matches**). MIC algos: keyver1 HMAC-MD5(KCK, frame)[0..15]; keyver2 AES-128-CMAC(KCK, frame)==mic[0..15]; keyver3 HMAC-SHA1(KCK, frame)[0..15]. mic_len 8 → compare 8 bytes.
4. Multiple hash records in one session: for each word, try every record; report first hit per record; records can be PMKID and M2 mixed.

## Code layout (pure C11, no exceptions, POSIX pthreads)
- `crypto/sha1.c,h` (public-domain style implementation), `crypto/hmac_sha1.c`, `crypto/pbkdf2_sha1.c` (optimized inner loop — the 4096-iteration core; unroll sensibly), `crypto/hmac_md5.c`, `crypto/aes.c` (compact AES-128 enc only), `crypto/aes_cmac.c`.
- `wpa/p22000.c,h` — parse `$22000$<hex>$` lines into struct (mirror hccapx v1 field layout, see SPEC-M2).
- `wpa/crack.c` — per-guess verify (PMKID/PTK/MIC).
- `engine/runner.c` — mmap wordlist reader (skip empty lines, strip \r\n, max len 63 → skip longer), thread pool (N threads), lock-free per-thread counters, 1 Hz progress window → callback, cancellation flag, resume offset (start from word offset arg; report done offset for checkpoints).
- `engine/bench.c` — fixed KAT record + 1000-word synthetic list, returns guesses/sec.
- `jni/bridge.c` — JNI (`#ifdef __ANDROID__`): see ABI below.
- `CMakeLists.txt` — builds static lib `marauder_crack` for both android (arm64-v8a, x86_64) and a host test exe target when not android toolchain.

## JNI ABI (create `app/src/main/java/com/marauder/mobile/crack/NativeBridge.kt` exactly)
```kotlin
package com.marauder.mobile.crack
object NativeBridge {
    init { System.loadLibrary("marauder_crack") }
    external fun bench(threads: Int): Long                 // guesses/s, 0 unavailable
    external fun run(hashLines: Array<String>, wordlists: Array<String>, backend: Int, threads: Int, startWord: Long, cb: JavaCallback): Boolean
    external fun cancel()
    interface JavaCallback { fun onProgress(done: Long, total: Long, rate: Double); fun onFound(hashIndex: Int, password: String); fun onDone(completed: Boolean) }
}
```
C side: `Java_com_marauder_mobile_crack_NativeBridge_run` etc. (jobjectArray→const char**, GetObjectClass/GetMethodID on cb for the 3 methods, GlobalRef, call from worker (attach thread once), progress at most ~4/s, `run` blocks until done/cancel; backend 0=AUTO 1=CPU (2=GPU → return false+onDone(false) for now)). Also write `NativeCrackEngine.kt` implementing the `CrackEngine` contract on top of NativeBridge (flow via callbackFlow on IO).

## Host verification (must run NOW on this PC — no device needed)
NDK host clang: `C:\Users\burzuf\AppData\Local\Android\Sdk\ndk\27.0.12077973\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe` (if NDK install still in progress, check `sdk\sdk` dir or wait/poll existence). Use CMake (`%LOCALAPPDATA%\Android\Sdk\cmake\3.22.1\bin\cmake.exe`) to build a host `test_engine.exe` (guard JNI out). Tests:
1. SHA1 "abc" vector; HMAC-SHA1 RFC2202; PBKDF2-HMAC-SHA1 RFC6070 vectors (c=1, c=4096).
2. AES-128 FIPS-197 vector; AES-CMAC RFC4493 vectors; HMAC-MD5 RFC2104/2202 vectors.
3. 22000 parse of official example lines: fetch `https://raw.githubusercontent.com/hashcat/hashcat/master/docs/hashcat-example-hashes.md`, extract a 22000 line (PMKID type and M2 type if present), embed verbatim.
4. **End-to-end KAT**: crack official example line (password `hashcat`, wordlist = a handful of words incl. "hashcat") → engine reports `hashcat`. This is THE gate: MIC/PTK/22000 semantics are only accepted when this passes. (The example hashes all use password `hashcat`.)
5. Print bench rate (x86 host sanity: expect ≥1k h/s single-thread).
Iterate until all pass; keep the test binary sources in cpp/host/.

## Style
C11, -O3, no malloc in hot loop (pre-alloc per-thread buffers), ARM: compile flags later; correctness first, NEON/vectorization explicitly NOT in this milestone (M3.5 later). Small public-domain-style crypto is fine (no GPL; hashcat/john are license-contaminated — implement from specs/KATs only, do NOT copy their code).
