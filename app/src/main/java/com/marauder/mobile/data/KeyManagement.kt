package com.marauder.mobile.data

/**
 * Reading back, from an artifact's own metadata, what each network in the capture
 * claimed about its key management.
 *
 * Why this is stored instead of re-derived: whether a hash can be recovered at all
 * is decided by the network's AKM list, and hashcat mode 22000 tests
 * `PBKDF2-HMAC-SHA256(SSID, password)` — the WPA2-PSK PMK. WPA3-SAE derives its PMK
 * from the dragonfly exchange, so a captured SAE handshake is not a password hash
 * and no wordlist, rule or GPU can recover it. Re-discovering that by burning an
 * hour of phone time on a doomed run is exactly what this is here to prevent.
 */
object KeyManagement {

    /** `BSSID=label; BSSID=label` — one verdict per network the capture named. */
    const val META = "netsec"

    /** Space-separated BSSIDs whose only key management is SAE. */
    const val SAE_ONLY = "sae_only"

    /** Count of SAE (WPA3) authentication frames the capture held. */
    const val SAE_FRAMES = "sae_frames"

    data class Verdict(val bssid: String, val label: String, val saeOnly: Boolean)

    /** Per-network verdicts recorded by the extractor, in BSSID order. */
    fun verdicts(meta: Map<String, String>): List<Verdict> =
        (meta[META] ?: "").split("; ").mapNotNull { row ->
            val at = row.indexOf('=')
            if (at <= 0 || at == row.length - 1) return@mapNotNull null
            val label = row.substring(at + 1)
            Verdict(
                bssid = row.substring(0, at),
                label = label,
                saeOnly = label.contains("SAE only", ignoreCase = true),
            )
        }

    /** BSSIDs the extractor proved to be SAE-only. */
    fun saeOnly(meta: Map<String, String>): List<String> =
        (meta[SAE_ONLY] ?: "").split(' ').filter { it.isNotBlank() }

    /**
     * Plain-language warning for an SAE-only network, or null when there is nothing
     * to warn about. [aimed] is the BSSID the operation was pinned to: when the
     * network the user aimed at is the SAE-only one, the wording says so directly.
     */
    fun explainSae(saeOnly: List<String>, aimed: String?): String? {
        if (saeOnly.isEmpty()) return null
        val aimedHit = aimed != null && saeOnly.any { it.equals(aimed, ignoreCase = true) }
        val which = if (aimedHit) "The network you aimed at ($aimed)" else "A network in this capture"
        return which + " only offers WPA3-SAE. Its PMK comes from the dragonfly exchange, " +
            "not from PBKDF2(SSID, password), so the hashes in this capture are not password " +
            "hashes: a mode-22000 run cannot recover them, and the firmware's `sniffsae` " +
            "records the exchange as evidence rather than as a crackable credential. " +
            "Attacking such a network means the client side (evil portal, captive portal, " +
            "credential phishing), not offline cracking."
    }
}
