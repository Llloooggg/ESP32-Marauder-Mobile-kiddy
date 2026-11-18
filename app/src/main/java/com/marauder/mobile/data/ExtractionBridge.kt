package com.marauder.mobile.data

import java.io.File

/**
 * Hashes carved out of a capture file, ready for a cracker.
 *
 * [hashLines] are hashcat mode-22000 lines (`WPA*01*…` for a PMKID, `WPA*02*…`
 * for a handshake), one per target network found in the capture.
 */
data class HashExtractResult(
    val pmkidCount: Int,
    val handshakeSets: Int,
    val hashLines: List<String>,
    val note: String? = null,
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
    /** Returns null when extraction is unavailable or the file holds nothing usable. */
    fun extract(file: File): HashExtractResult?
}

object UnwiredExtractionBridge : ExtractionBridge {
    override fun extract(file: File): HashExtractResult? = null
}
