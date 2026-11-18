# SPEC-M2 — pcap → hashcat 22000 extractor (pure Kotlin, module :extractor)

Module `:extractor` already scaffolded (Kotlin JVM 2.1, JUnit4). Contract classes exist: `extractor/src/main/kotlin/com/marauder/extractor/HashModels.kt` — read them, implement against them (you may add fields/helpers but keep `line`, `kind`, `essid`, `bssid`, `sta`, counts stable).

## Entry point
`object Extractor { fun extract(pcap: File): ExtractReport }` in `com.marauder.extractor`. Pure parsing — no crypto verification needed here, but the serialized bytes MUST be hashcat-22000 compatible.

## Source pcap facts (verified from ESP32 Marauder v1.20 firmware source — trust these)
- Global header: magic `0xa1b2c3d4` (LE, µs), version 2.4, snaplen, **linktype 105 (DLT_IEEE802_11)**. Timestamps are board `micros()` (monotonic junk) — ignore semantics.
- Every record payload = pure 802.11 frame starting at frame-control, **no radiotap**.
- **DATA frames include FCS (4 trailing bytes); MGMT frames have FCS stripped** in this firmware. Do not assume: implement FCS auto-detect (see below).
- EAPOL sniffer modes store only: EAPOL-Key data frames + beacons (beacon carries the ESSID + RSN IE). Raw sniff modes store everything — be lenient.
- Streams can be truncated/gapped (USB loss): must parse partial files gracefully; stop at first incomplete record.

## Parsing requirements
1. pcap reader: support magic variants (a1b2c3d4 / a1b23c4d µs; 4-byte-swapped magic → big-endian mode); iterate records (ts_sec, ts_usec, incl_len, orig_len). Guard incl_len ≤ 262144.
2. 802.11 parser: FC subtype; addr1/2/3 + addr4 when ToDS&FromDS; QoS header (subtype & 0x0C == 0x08) adds 2 bytes; frame body len from FC length field (bits 44-55) for auto-FCS:
   - DATA: body = [802.11 hdr][LLC/SNAP or QoS][RFC1042 encap: AA-AA-03 00-00-00 type(2)] → EAPOL (type 0x888E).
   - FCS rule: if exact byte layout + EAPOL `length` field (16-bit BE at eapol+2 for Key descriptor; EAPOL total = 4-byte header + length field value) accounts for `incl_len - hdr - body` == 4 → treat as FCS present; == 0 → absent; else mark frame as unparsed (note).
3. Beacon parse (MGMT subtype 8): SSID IE (id 0) → essid string (utf8 raw, printable fallback to hex); RSN IE (id 48)/WPA IE (221+00-50-F2-02): AKMP suite selector: 00-0F-AC:2 → TKIP (keyver 1), :4 → CCMP (keyver 2), :6 → PMF (keyver 2 mic16? keep 2). No RSN IE → keyver 0 → skip with note (not WPA2-Personal).
4. EAPOL-Key (RSN type 2 or WPA type 3): key_info 16-bit BE — version bits 0-2, bit7 ACK(0x0080), bit8 MIC(0x0100), bit9 SECURE(0x0200), key_index bits 6-7 for M1 (install bit etc — for M1/M2 classification only ACK/MIC/SECURE needed, matching firmware logic).
   - key_data_length BE (TKIP has extra fields — for keyver1, replay counter is 8 bytes but key_data follows RSN/WPA differences; support: RSN keylen field 0x0010 typical, replay(8)+iv(16)+mic(16)+len(2)+data).
   - **PMKID**: vendor IE inside EAPOL body: `dd <len> 00-0e-90 04 <keyidx:4> 00-10 <pmkid:16>` — scan the key_data region.
   - keyver mapping (hccapx numbering, MUST match hashcat): 1=HMAC-MD5 (TKIP), 2=AES-128-CMAC (CCMP), 3=HMAC-SHA1-128. mic_len = 16 normally; if EAPOL frame shows truncated mic (e.g. mic len 12) record micLenBytes accordingly.
5. Handshake assembly (WPA2-Personal 4-way): per (AA=BSSID, SPA) keep first valid M1 (ACK,!MIC) with matching replay R, and M2 (!ACK,MIC,replay R+1... replay semantics: M2 counter = M1 counter+1) → message_pair=2; AP nonce from M1 key_iv(16→ take first 32B region per hccapx: AP nonce is replay+iv region: **AP nonce = M1 key_iv first 32 bytes? NO: hccapx ap_nonce = bytes: replay(8)+iv(16)+? — the 32-byte nonce = M1.replay_counter(8) || M1.key_iv(16) || key_data_length(2) ... follow the official hccapx/22000 layout below, do not improvise**), STA nonce from M2 first 32 bytes of (replay||iv), mic from M2 (16B, truncated flag), eapol frame bytes = M2 frame body (LLC-stripped EAPOL, without 802.11 header? — again: use the canonical 22000 layout spec).
6. Canonical 22000 record = **hex of the hccapx v1 struct body** (187 bytes: version(1)=1, message_pair(1), ap_msg_num/... mic_error_correction(3), essid_len(1)+essid(32 zero-padded), pmkid(16), bssid(6), sta(6), keyver(1), mic_len(1), eapol_len(2 LE)+eapol frame(≤256), ap_nonce(32), sta_nonce(32), mic(32 zero-padded)... verify exact field order/sizes yourself against the official example file — see Testing). PMKID-only record: message_pair=255, eapol_len=0, pmkid set, nonces/mic zero.
7. Line format: `$22000$<hex-of-struct>$<hex-of-authenticator-optional?>` — confirm trailing authenticator part from official examples (some tools append a second `$` field; hashcat accepts `$22000$<hex>$...` — copy exact shape from example lines).

## Testing (JUnit4, extractor/src/test/kotlin/...)
1. **Authoritative layout check**: fetch `https://raw.githubusercontent.com/hashcat/hashcat/master/docs/hashcat-example-hashes.md` once, extract mode-22000 example lines (password `hashcat`, ESSID etc.), embed 2–3 verbatim in tests, decode them, assert field interpretation (essid/bssid/pmkid visible at your claimed offsets). Fix your struct layout until consistent. (If network is blocked: note it in a test `Assume`, and rely on synthetic tests.)
2. Synthetic pcap builder in test sources (write global hdr + records yourself):
   - beacon (bssid B1, essid "TestNet", RSN IE AKMP :4), EAPOL-Key with WLAN-PMKID IE → assert 1 PMKID record: message_pair 255, keyver 2, bytes at pmkid offset = fed value, line hex decodes to expected struct offsets.
   - M1 (from B1→STA, ACK, replay 7, iv nonce A) + M2 (STA→B1, replay 8, mic value M) → assert HANDSHAKE record, message_pair 2, eapol bytes = M2 EAPOL (LLC-stripped), nonces/mic/mic_error_correction offsets correct (mic_error_correction = ap ver/replay from M1).
   - FCS variants (data frame +4 FCS / mgmt without) both parse; corrupt/truncated pcap → graceful stop with notes.
3. Run: `gradlew :extractor:test` (you MAY run gradle for the :extractor module ONLY — never :app).

## Non-goals
WPA3/SAE (stub HashKind + TODO), no hash verification crypto (M3 engine does that), no pcap writing.
