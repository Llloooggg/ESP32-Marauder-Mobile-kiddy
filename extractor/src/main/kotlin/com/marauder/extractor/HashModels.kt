package com.marauder.extractor

/** What kind of WPA2 credential material a 22000 record carries. */
enum class HashKind { PMKID, HANDSHAKE }

/**
 * One extracted hashcat-mode-22000 credential. [line] is the hashcat input
 * line in the format module_22000.c natively parses (verified against the
 * hashcat v6.2.6 source):
 *  - PMKID:     `WPA*01*<pmkid:16B hex>*<ap mac>*<sta mac>*<essid hex>***`
 *  - handshake: `WPA*02*<mic:16B hex>*<ap mac>*<sta mac>*<essid hex>*<ap nonce:32B hex>*<M2 eapol frame hex>*<message pair:1B hex>`
 * Everything else is display metadata for the UI (parsed back out of the
 * record, not guessed).
 */
data class ExtractedHash(
    val kind: HashKind,
    val essid: String,
    val bssid: String,          // "aa:bb:cc:dd:ee:ff"
    val sta: String,            // supplicant MAC (real for PMKID, from M2 for handshakes)
    val messagePair: Int,       // 255 = PMKID-only, 2 = M1+M2 (AP-issued M1)
    val keyver: Int,            // 1 = HMAC-MD5, 2 = AES-128-CMAC, 3 = HMAC-SHA1-128
    val micLenBytes: Int,       // 16 or 8 (truncated MIC — reported, still crackable)
) {
    lateinit var line: String
        internal set
}

/** Result of running the extractor over one pcap file. */
data class ExtractReport(
    val hashes: List<ExtractedHash>,
    val recordsParsed: Int,     // pcap records consumed
    val eapolFrames: Int,       // EAPOL-Key frames seen
    val beacons: Int,           // beacon / probe-response frames seen (ESSID source)
    val notes: List<String>,    // human-readable diagnostics (loss, quirks)
    // --- why a capture yielded what it yielded (the UI shows these when 0 hashes) --
    val dataFrames: Int = 0,    // 802.11 data frames seen
    val m1Frames: Int = 0,      // AP messages carrying the ANonce
    val m2Frames: Int = 0,      // client messages carrying MIC + SNonce
    val m3Frames: Int = 0,      // AP messages with MIC (ANonce source when M1 is missing)
    val m4Frames: Int = 0,      // client ACKs (no key material)
    val pmkidFrames: Int = 0,   // frames whose key data held a PMKID
    val pairs: Int = 0,         // usable handshake pairs found
    val pairsNoApMessage: Int = 0, // M2s whose AP message (M1 or M3) never reached the capture
    val badRecords: Int = 0,    // broken pcap records skipped (capture frames lost in transit)
    val resyncs: Int = 0,       // times the record stream was found again
    val lostBytes: Int = 0,     // bytes skipped while resyncing
    val shortEapol: Int = 0,    // EAPOL frames too short to be usable
    val pairsNoSsid: Int = 0,   // credentials dropped because the SSID is unknown
    val ssidFromScan: Int = 0,  // credentials whose SSID came from the app's scan list
) {
    /** True when the capture holds anything the cracker can work on. */
    val usable: Boolean get() = hashes.isNotEmpty()
}
