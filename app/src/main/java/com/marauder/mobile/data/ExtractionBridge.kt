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
    // Which side put each EAPOL on the air. A capture can hold hundreds of EAPOL frames and still be
    // worthless: if every one came from an access point (usually retransmitted), the client never
    // answered and no handshake exists to rebuild. "EAPOL 246, 0 handshakes" hides that; this names it.
    val eapolFromAp: Int = 0,
    val eapolFromClient: Int = 0,
    val eapolRetried: Int = 0,      // Retry bit set: the sender was repeating itself at a silent peer
    /** EAPOL sent by an AP with no ANonce and no key data: neither an M1 nor an M4. */
    val apEmptyEapol: Int = 0,
    val badRecords: Int = 0,        // broken records: frames lost between board and phone
    val lostBytes: Int = 0,         // bytes skipped while getting the record stream back
    /** BSSIDs the extracted material actually belongs to, uppercase, sorted. */
    val networks: List<String> = emptyList(),
    // --- key management: WPA2-PSK (crackable) vs WPA3-SAE (not a password hash) ----
    /** BSSID → what that network advertised about its key management, human words. */
    val security: Map<String, String> = emptyMap(),
    /** BSSIDs whose only key-management option is SAE: mode 22000 cannot recover them. */
    val saeOnlyNetworks: List<String> = emptyList(),
    /** SAE (WPA3) authentication frames seen — direct evidence of dragonfly on air. */
    val saeAuthFrames: Int = 0,
) {
    val usable: Boolean get() = hashLines.isNotEmpty()

    /** Same claim the stored record makes, decided by the shared rule. */
    val eapolOnlyFromAp: Boolean
        get() = CaptureDiagnosis.eapolOnlyFromAp(eapolFrames, eapolFromClient)
}

/**
 * What a capture is allowed to claim, decided in one place so the console line, the artifact row and
 * the JSON record cannot tell different stories about the same bytes. A field run of this shape:
 * 246 EAPOL frames, all FromDS, 233 of them retransmitted, nothing from the client — the handshake
 * never started, and no wordlist or GPU changes that.
 */
object CaptureDiagnosis {
    /** Meta keys carrying the extractor's EAPOL direction counts (written by ArtifactsRepository). */
    const val META_EAPOL_TOTAL = "eapol"
    const val META_EAPOL_FROM_CLIENT = "eapol_client"
    const val META_EAPOL_FROM_AP = "eapol_ap"
    const val META_EAPOL_RETRIED = "eapol_retry"
    const val META_EAPOL_AP_EMPTY = "ap_empty"

    /**
     * True only when EAPOL was seen and the client side contributed nothing. A count that is unknown
     * (`null`, e.g. a record written by an older app version) answers false: the app does not claim
     * a client silence it cannot read back.
     */
    fun eapolOnlyFromAp(eapolFrames: Int, eapolFromClient: Int?): Boolean = eapolFrames > 0 && eapolFromClient == 0

    /** The same rule applied to a stored record's meta. */
    fun eapolOnlyFromAp(meta: Map<String, String>): Boolean {
        val total = meta[META_EAPOL_TOTAL]?.toIntOrNull() ?: return false
        return eapolOnlyFromAp(total, meta[META_EAPOL_FROM_CLIENT]?.toIntOrNull())
    }

    /**
     * One honest sentence about what extraction produced, with the counters behind the number. It
     * lives beside the rules above because it is where the app states its conclusion: a capture that
     * yielded nothing has to be told apart — no EAPOL at all, EAPOL from one side only, frames lost
     * in transit, a network whose key is not password-derived — and the sentence must not leave the
     * reader reaching for a bigger wordlist when the missing thing is a client frame.
     */
    fun explain(r: HashExtractResult): String {
        val counts = buildString {
            append("frames ${r.frames}, EAPOL ${r.eapolFrames} ")
            append("(M1 ${r.m1}, M2 ${r.m2}, M3 ${r.m3}, M4 ${r.m4}")
            if (r.apEmptyEapol > 0) append(", AP-empty ${r.apEmptyEapol}")
            append(")")
            // The case a wordlist can never fix: EAPOL was heard, but only from the AP side.
            if (r.eapolOnlyFromAp) {
                append(" — every EAPOL came from the AP")
                if (r.eapolRetried > 0) append(" (${r.eapolRetried} of them retransmitted)")
                append(", not one from the client")
            }
            if (r.badRecords > 0) append(", ${r.badRecords} record(s) lost in transit (+${r.lostBytes} B)")
        }
        return if (r.usable) {
            "Capture holds ${r.pmkidCount} PMKID, ${r.handshakeSets} handshake(s) — ready to crack [$counts]"
        } else {
            "No crackable credential in this capture — ${r.note ?: "no PMKID or handshake"} [$counts]"
        }
    }
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
