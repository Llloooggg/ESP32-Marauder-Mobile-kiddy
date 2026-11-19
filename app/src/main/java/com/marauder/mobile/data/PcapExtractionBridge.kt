package com.marauder.mobile.data

import com.marauder.extractor.Extractor
import com.marauder.extractor.HashKind
import com.marauder.extractor.NetworkSecurity
import com.marauder.extractor.SecurityMode
import java.io.File
import java.io.FileInputStream

/**
 * Real extraction bridge backed by the pure-Kotlin `:extractor` module: reads a
 * Marauder pcap from disk and turns every PMKID / handshake pair it finds into
 * hashcat mode-22000 lines. Truncated, gapped or non-pcap files never throw —
 * the extractor's counters and notes ride along in [HashExtractResult] so the
 * UI can explain a "0 handshakes" result instead of just reporting it.
 */
class PcapExtractionBridge : ExtractionBridge {

    override fun extract(file: File, knownEssids: Map<String, String>): HashExtractResult? {
        if (!file.isFile) return null
        return try {
            val report = FileInputStream(file).use { Extractor.extract(it, knownEssids) }
            HashExtractResult(
                pmkidCount = report.hashes.count { it.kind == HashKind.PMKID },
                handshakeSets = report.hashes.count { it.kind == HashKind.HANDSHAKE },
                hashLines = report.hashes.map { it.line },
                note = report.notes.joinToString("; ").ifEmpty { null },
                notes = report.notes,
                frames = report.recordsParsed,
                eapolFrames = report.eapolFrames,
                beacons = report.beacons,
                m1 = report.m1Frames,
                m2 = report.m2Frames,
                m3 = report.m3Frames,
                m4 = report.m4Frames,
                eapolFromAp = report.eapolFromAp,
                eapolFromClient = report.eapolFromClient,
                eapolRetried = report.eapolRetried,
                apEmptyEapol = report.apEmptyEapolFrames,
                badRecords = report.badRecords,
                lostBytes = report.lostBytes,
                networks = report.hashes.map { it.bssid.uppercase() }.distinct().sorted(),
                security = report.networks.associate { it.bssid.uppercase() to describe(it) },
                saeOnlyNetworks = report.networks
                    .filter { it.mode == SecurityMode.SAE_ONLY }
                    .map { it.bssid.uppercase() },
                saeAuthFrames = report.saeAuthFrames,
            )
        } catch (e: Exception) {
            // The extractor is defensive already; anything escaping here (e.g. an
            // I/O error mid-read) still must not crash the library UI.
            HashExtractResult(0, 0, emptyList(), "extract failed: ${e.message}")
        }
    }

    /**
     * One line per network, in plain words, saying whether a cracker can work on it
     * at all. Mode 22000 tests `PBKDF2-HMAC-SHA256(SSID, password)`; an SAE-only
     * network derives its PMK from the dragonfly exchange instead, so the honest
     * answer for those is "not crackable", never "try a bigger wordlist".
     */
    private fun describe(n: NetworkSecurity): String {
        val akm = if (n.akmLabels.isEmpty()) "" else " [${n.akmLabels.joinToString("+")}]"
        val human = when (n.mode) {
            SecurityMode.PSK -> "WPA2-Personal · crackable"
            SecurityMode.MIXED_PSK_SAE -> "WPA3 transition (PSK fallback) · crackable via the PSK side"
            SecurityMode.SAE_ONLY -> "WPA3-SAE only · offline cracking does not apply"
            SecurityMode.ENTERPRISE -> "802.1X / enterprise · no shared password to crack"
            SecurityMode.OWE -> "OWE (encrypted open network) · no password exists"
            SecurityMode.UNKNOWN -> "key management not visible in this capture"
        }
        val sae = if (n.saeAuthFrames > 0) " · ${n.saeAuthFrames} SAE frame(s) on air" else ""
        return "$human$akm$sae"
    }
}
