package com.marauder.mobile.data

import com.marauder.extractor.Extractor
import com.marauder.extractor.HashKind
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
                badRecords = report.badRecords,
                lostBytes = report.lostBytes,
            )
        } catch (e: Exception) {
            // The extractor is defensive already; anything escaping here (e.g. an
            // I/O error mid-read) still must not crash the library UI.
            HashExtractResult(0, 0, emptyList(), "extract failed: ${e.message}")
        }
    }
}
