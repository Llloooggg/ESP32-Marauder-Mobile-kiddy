package com.marauder.mobile.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The one claim the app makes before the board has said anything.
 *
 * A USB port opening is a fact about the phone; whether a board is answering on it is a fact about
 * the board, and the two are easy to conflate into a UI that says "connected" while nothing works.
 * These tests pin the narrow version of the claim, because that is the version that stays true: the
 * app may report its own silence (zero bytes back after N asks) and the causes the hardware allows,
 * and may not call the board broken, since nothing measured here can prove that.
 */
class BoardSilenceTest {

    @Test
    fun anAnswerEndsTheClaimImmediately() {
        assertTrue(BoardSilence.isSilent(0, BoardSilence.GRACE_MS))
        // One line is enough: the link works, whatever else about the session is wrong.
        assertFalse(BoardSilence.isSilent(1, BoardSilence.GRACE_MS * 10))
    }

    @Test
    fun theGracePeriodCoversABoardTheCableJustReset() {
        // Opening the port asserts DTR/RTS, which resets an ESP32 through a bridge, so a board that is
        // merely booting has to stay unaccused for as long as a cold boot plus a first jsoninfo.
        assertTrue(BoardSilence.GRACE_MS >= 3_000L)
        assertFalse(BoardSilence.isSilent(0, BoardSilence.GRACE_MS - 1))
    }

    @Test
    fun theSentenceSaysWhatTheAppDidBeforeDrawingAnyConclusion() {
        val why = BoardSilence.explain(3, 115200, 4_000L)
        // Without the counts the user cannot tell "the board never answered" from "the app never
        // asked", and those need opposite fixes.
        assertTrue(why, why.contains("3 asks"))
        assertTrue(why, why.contains("115200"))
        assertTrue(why, why.contains("4s"))
    }

    @Test
    fun theSentenceNamesTheForkInRealHardwareWithoutNamingABoard() {
        // The cause was measured on one particular board, but the app drives many, and each exposes
        // its ports differently. Naming the fork (chip's own USB vs UART bridge) is what a user can
        // act on for any of them; naming a dev kit they do not own is noise, and a guess about a board
        // the app has never seen.
        val why = BoardSilence.explain(2, 921600, 4_000L)
        assertTrue(why, why.contains("chip's own USB"))
        assertTrue(why, why.contains("UART bridge"))
        assertTrue(why, why.contains("reset"))
        assertTrue(why, !why.contains("ESP32"))
    }

    @Test
    fun silenceIsNeverReportedAsABrokenBoard() {
        val why = BoardSilence.explain(1, 115200, 4_000L).lowercase()
        for (word in listOf("broken", "dead", "faulty", "defective")) {
            assertFalse("silence cannot prove the board is $word: $why", why.contains(word))
        }
    }
}
