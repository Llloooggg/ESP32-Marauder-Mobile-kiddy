package com.marauder.mobile.data

/**
 * Does a capture actually belong to the network the operation was aimed at?
 *
 * A capture is aimed at one BSSID, but the frames the board happened to hear can
 * belong to any network on that channel — and with same-named access points, or a
 * firmware list that re-indexed mid-operation, the material can belong to a
 * different BSSID entirely. Saying so is the difference between "this network has
 * no handshake" and "we captured the wrong network".
 */
object CaptureAttribution {

    /** What kind of BSSID the firmware's list slot / the capture refers to. */
    sealed interface Verdict {
        /** The capture was never aimed at a specific network. */
        data object Unaimed : Verdict

        /** The aimed-at network is among the networks the hashes belong to. */
        data object Match : Verdict

        /** Hashes exist, but none of them belongs to the aimed-at network. */
        data class Mismatch(val aimed: String, val captured: List<String>) : Verdict

        /** Nothing was extracted, so attribution cannot be judged. */
        data object Unknown : Verdict
    }

    fun verdict(aimedBssid: String?, networks: List<String>): Verdict {
        val aimed = aimedBssid?.trim().orEmpty()
        if (aimed.isEmpty()) return Verdict.Unaimed
        if (networks.isEmpty()) return Verdict.Unknown
        val upper = networks.map { it.uppercase() }
        return if (aimed.uppercase() in upper) Verdict.Match
        else Verdict.Mismatch(aimed.uppercase(), upper)
    }

    /** One-line explanation the UI can show as-is. */
    fun explain(verdict: Verdict): String? = when (verdict) {
        Verdict.Unaimed, Verdict.Match -> null
        Verdict.Unknown -> null
        is Verdict.Mismatch ->
            "Aimed at ${verdict.aimed}, but the credential material in this capture belongs to: " +
                "${verdict.captured.joinToString()}. The board hears every network on the channel, so the " +
                "handshake it caught is not the one you were targeting — retarget and capture again, or " +
                "crack what is actually here."
    }
}
