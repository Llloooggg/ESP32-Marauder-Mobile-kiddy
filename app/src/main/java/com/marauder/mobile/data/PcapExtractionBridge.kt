package com.marauder.mobile.data

import com.marauder.extractor.Extractor
import com.marauder.extractor.HashKind
import java.io.File
import java.io.FileInputStream

/**
 * Real extraction bridge backed by the pure-Kotlin `:extractor` module: reads a
 * Marauder pcap from disk and turns every PMKID / M1+M2 pair it finds into
 * hashcat mode-22000 lines. Truncated, gapped or non-pcap files never throw —
 * the extractor's own diagnostics are surfaced through [HashExtractResult.note].
 */
class PcapExtractionBridge : ExtractionBridge {

    override fun extract(file: File): HashExtractResult? {
        if (!file.isFile) return null
        return try {
            val report = FileInputStream(file).use { Extractor.extract(it) }
            val lines = report.hashes.map { it.line }
            val note = report.notes.joinToString("; ").ifEmpty { null }
            HashExtractResult(
                pmkidCount = report.hashes.count { it.kind == HashKind.PMKID },
                handshakeSets = report.hashes.count { it.kind == HashKind.HANDSHAKE },
                hashLines = lines,
                note = note,
            )
        } catch (e: Exception) {
            // The extractor is defensive already; anything escaping here (e.g. an
            // I/O error mid-read) still must not crash the library UI.
            HashExtractResult(0, 0, emptyList(), "extract failed: ${e.message}")
        }
    }
}
