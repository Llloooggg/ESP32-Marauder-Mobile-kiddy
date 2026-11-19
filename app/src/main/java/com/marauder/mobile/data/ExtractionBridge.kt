package com.marauder.mobile.data

import java.io.File

/**
 * Hashes carved out of a capture file, ready for a cracker.
 *
 * [hashLines] are hashcat mode-22000 lines (`WPA*01*…` for a PMKID, `WPA*02*…`
 * for a handshake), one per target network found in the capture.
 *
 * The counters are what makes a "0 handshakes" result explainable: EAPOL frames
 * on the console is not the same thing as a crackable credential, and the
 * counters say which step the capture came up short on.
 */
data class HashExtractResult(
    val pmkidCount: Int,
    val handshakeSets: Int,
    val hashLines: List<String>,
    val note: String? = null,
    val notes: List<String> = emptyList(),
    val frames: Int = 0,            // pcap records read
    val eapolFrames: Int = 0,       // EAPOL-Key frames seen
    val beacons: Int = 0,           // beacons / probe responses (SSID source)
    val m1: Int = 0,                // AP messages with the ANonce
    val m2: Int = 0,                // client messages with MIC + SNonce
    val m3: Int = 0,                // AP messages with MIC (ANonce when M1 was missed)
    val m4: Int = 0,                // client ACKs (no key material)
    val badRecords: Int = 0,        // broken records: frames lost between board and phone
    val lostBytes: Int = 0,         // bytes skipped while getting the record stream back
) {
    val usable: Boolean get() = hashLines.isNotEmpty()
}

/**
 * Seam between the artifact library and the hash extractor. The extractor lives in
 * its own JVM module so it can be unit-tested without a device; until the build
 * wires that module into the app, [UnwiredExtractionBridge] answers `null` and the
 * UI says so plainly instead of pretending the capture was analysed.
 */
interface ExtractionBridge {
    /**
     * Returns null when extraction is unavailable. [knownEssids] (bssid → SSID as
     * the app's scan list saw it) is the fallback salt source for captures that
     * never caught a beacon — without an SSID no cracker can work at all.
     */
    fun extract(file: File, knownEssids: Map<String, String> = emptyMap()): HashExtractResult?
}

object UnwiredExtractionBridge : ExtractionBridge {
    override fun extract(file: File, knownEssids: Map<String, String>): HashExtractResult? = null
}
