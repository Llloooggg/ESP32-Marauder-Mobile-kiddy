package com.marauder.mobile.vm

/** What a running mission is doing — drives icons, counters and stop semantics. */
enum class MissionKind { SCAN, SNIFF, CAPTURE, ATTACK, WARDRIVE, OTHER }

/**
 * One live firmware activity the app started and supervises (scan, capture,
 * attack…). The ViewModel owns exactly one active mission; starting a new one
 * stops the previous. Counters refresh live; [done] means the firmware stopped
 * running it (natural end) or the user did, after finalization.
 */
data class Mission(
    val id: Long,
    val title: String,
    val kind: MissionKind,
    val command: String,
    val startedAt: Long,
    /** Mark the mission finished once jsonstatus reports the firmware idle. */
    val stopOnIdle: Boolean = true,
    /** Bytes streamed into the capture file (CAPTURE/WARDRIVE only). */
    val bytes: Long = 0L,
    /** EAPOL frames observed on the console, keyed by the reporting MAC. */
    val eapol: Map<String, Int> = emptyMap(),
    /** Frame-sequence gaps (USB transport loss). */
    val missedFrames: Long = 0L,
    /** Packets the firmware ring dropped (its own loss report). */
    val ringDrops: Long = 0L,
    /** Artifact file registered when the capture was finalized, if any. */
    val artifactName: String? = null,
    val done: Boolean = false,
) {
    val eapolTotal: Int get() = eapol.values.sum()
}
