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

    // The sentence the app states as its conclusion. It is pinned because it is the product's
    // honesty interface: a capture that produced nothing has to be told apart, and the wording must
    // not leave the reader reaching for a bigger wordlist when what is missing is a client frame.

    @Test
    fun aCrackableCaptureSaysSoWithItsCounts() {
        val r = HashExtractResult(pmkidCount = 1, handshakeSets = 0, hashLines = listOf("WPA*01*aa"))
        val line = CaptureDiagnosis.explain(r)
        assertTrue(line, line.contains("ready to crack"))
        assertTrue(line, line.contains("1 PMKID"))
    }

    @Test
    fun anEmptyCaptureNamesWhatIsMissingRatherThanBlame() {
        val r = HashExtractResult(0, 0, emptyList(), frames = 1295, eapolFrames = 0)
        val line = CaptureDiagnosis.explain(r)
        assertTrue(line, line.contains("No crackable credential"))
        assertTrue(line, line.contains("no PMKID or handshake"))
        assertTrue(line, line.contains("frames 1295"))
        assertTrue("no EAPOL at all is not client silence: $line", !line.contains("not one from the client"))
    }

    @Test
    fun theApOnlyFieldShapeIsNamedInTheSentence() {
        // 358 KB, 1295 records, 246 EAPOL, one sender, 233 retransmissions: the real field capture.
        val r = HashExtractResult(
            0, 0, emptyList(),
            frames = 1295, eapolFrames = 246,
            eapolFromAp = 246, eapolFromClient = 0, eapolRetried = 233, apEmptyEapol = 246,
        )
        val line = CaptureDiagnosis.explain(r)
        assertTrue(line, line.contains("every EAPOL came from the AP"))
        assertTrue(line, line.contains("233 of them retransmitted"))
        assertTrue(line, line.contains("not one from the client"))
        assertTrue(line, line.contains("AP-empty 246"))
    }

    @Test
    fun lossInTransitIsPartOfTheSentenceAndClientSilenceIsNot() {
        val r = HashExtractResult(
            0, 0, emptyList(),
            frames = 100, eapolFrames = 4, eapolFromAp = 1, eapolFromClient = 3,
            badRecords = 3, lostBytes = 120,
        )
        val line = CaptureDiagnosis.explain(r)
        assertTrue(line, line.contains("3 record(s) lost in transit (+120 B)"))
        assertTrue("a client did answer here: $line", !line.contains("not one from the client"))
    }

    @Test
    fun aFileWithNoFramesIsNotReportedAsACaptureWithoutCredential() {
        // 24 bytes: the pcap global header and nothing else. The advice for this file is not
        // "try another wordlist" or "check the hardware" - it is "capture again".
        val r = HashExtractResult(0, 0, emptyList(), frames = 0, eapolFrames = 0)
        val line = CaptureDiagnosis.explain(r)
        assertTrue(line, line.contains("no 802.11 frames at all"))
        assertTrue("no cracker advice may be implied: $line", !line.contains("No crackable credential"))
    }

    @Test
    fun noFramesIsOnlyClaimedWhenTheCountIsActuallyZero() {
        assertTrue(CaptureDiagnosis.noFrames(0))
        assertFalse("one frame is a capture: ", CaptureDiagnosis.noFrames(1))
        assertFalse("an unknown count is not an empty file: ", CaptureDiagnosis.noFrames(null))
        assertTrue(CaptureDiagnosis.noFrames(mapOf(CaptureDiagnosis.META_FRAMES to "0")))
        assertFalse(CaptureDiagnosis.noFrames(mapOf(CaptureDiagnosis.META_FRAMES to "591")))
        assertFalse("a record written before this counter existed claims nothing: ", CaptureDiagnosis.noFrames(emptyMap()))
        assertFalse(CaptureDiagnosis.noFrames(mapOf(CaptureDiagnosis.META_FRAMES to "not a number")))
    }
}
