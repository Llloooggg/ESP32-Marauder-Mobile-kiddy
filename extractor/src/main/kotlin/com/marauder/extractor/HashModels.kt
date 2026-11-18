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
    val beacons: Int,           // beacon frames seen (ESSID source)
    val notes: List<String>,    // human-readable diagnostics (loss, quirks)
)
