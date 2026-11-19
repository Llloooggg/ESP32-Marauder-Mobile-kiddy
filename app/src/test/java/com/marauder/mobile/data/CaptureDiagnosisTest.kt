package com.marauder.mobile.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The rule behind the app's claim about who transmitted the EAPOL in a capture. It is one rule on
 * purpose: the console line, the artifact row and the stored record all read this, so they cannot
 * tell different stories about the same bytes. Two captures that both report "0 hashes" need
 * different advice, and the counters say which is which.
 */
class CaptureDiagnosisTest {

    @Test
    fun apOnlyEapolIsClaimedWhenTheClientContributedNothing() {
        // The shape of a real targeted run: 246 EAPOL frames, every one FromDS, not one from the
        // client. The advice has to name the client silence instead of offering a wordlist.
        assertTrue(CaptureDiagnosis.eapolOnlyFromAp(246, 0))
        assertTrue(CaptureDiagnosis.eapolOnlyFromAp(1, 0))
    }

    @Test
    fun oneClientFrameIsEnoughToStopTheClaim() {
        assertFalse(CaptureDiagnosis.eapolOnlyFromAp(246, 1))
    }

    @Test
    fun aCaptureWithNoEapolIsNotClientSilence() {
        // "Heard no EAPOL" and "heard EAPOL only from the AP" are different diagnoses and the app
        // must not merge them: the first says look at the channel, the second says look at the client.
        assertFalse(CaptureDiagnosis.eapolOnlyFromAp(0, 0))
    }

    @Test
    fun countsTheRecordDoesNotCarryNeverProduceTheClaim() {
        // Records written before these counters existed must not be read as proof of client silence.
        assertFalse(CaptureDiagnosis.eapolOnlyFromAp(246, null))
        assertFalse(CaptureDiagnosis.eapolOnlyFromAp(emptyMap()))
        assertFalse(CaptureDiagnosis.eapolOnlyFromAp(mapOf(CaptureDiagnosis.META_EAPOL_TOTAL to "246")))
        assertFalse(CaptureDiagnosis.eapolOnlyFromAp(mapOf(
            CaptureDiagnosis.META_EAPOL_TOTAL to "not a number",
            CaptureDiagnosis.META_EAPOL_FROM_CLIENT to "0",
        )))
    }

    @Test
    fun theRowReadsTheKeysTheRecordWrites() {
        val meta = mapOf(
            CaptureDiagnosis.META_EAPOL_TOTAL to "246",
            CaptureDiagnosis.META_EAPOL_FROM_AP to "246",
            CaptureDiagnosis.META_EAPOL_FROM_CLIENT to "0",
            CaptureDiagnosis.META_EAPOL_RETRIED to "233",
            CaptureDiagnosis.META_EAPOL_AP_EMPTY to "246",
        )
        assertTrue(CaptureDiagnosis.eapolOnlyFromAp(meta))
    }
}
