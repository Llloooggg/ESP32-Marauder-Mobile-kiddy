package com.marauder.mobile.crack

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * After a run that tried every word: what the screen is allowed to suggest.
 *
 * "A bigger list" is advice about a password. If some records in the artifact cannot
 * be checked by any wordlist, the screen has to say so instead — otherwise the user
 * builds a bigger list for a hash that is not a hash.
 */
class CrackOutcomeTest {

    @Test
    fun everythingTestableSuggestsABiggerList() {
        val text = CrackOutcome.exhausted(testable = 3, total = 3)
        assertTrue(text, text.contains("bigger list"))
        assertTrue("no untestable count when there is nothing untestable", !text.contains("could be tested"))
    }

    @Test
    fun anUntestableRecordIsNamedInstead() {
        val text = CrackOutcome.exhausted(testable = 2, total = 5)
        assertTrue(text, text.contains("2 of 5"))
        assertTrue(text, text.contains("cannot be checked by any wordlist"))
        assertTrue("must not advise a bigger list for a hash that cannot be tested",
            !text.contains("bigger list"))
    }

    @Test
    fun zeroTestableSaysNothingWasChecked() {
        val text = CrackOutcome.exhausted(testable = 0, total = 4)
        assertTrue(text, text.contains("0 of 4"))
        assertTrue("no password advice when nothing could be checked", !text.contains("bigger list"))
    }

    /**
     * The field capture holds two independent client messages from one network; both
     * verify the same password. One card must say that plainly instead of showing the
     * password twice as if two passwords had been recovered.
     */
    @Test
    fun severalLinesThatVerifyOnePasswordAreNamedOnOneLine() {
        val text = CrackOutcome.verified(listOf(2, 5), total = 5)
        assertTrue(text, text.contains("2 of 5"))
        assertTrue(text, text.contains("#2, #5"))
    }

    @Test
    fun oneVerifyingLineOutOfManySaysOne() {
        val text = CrackOutcome.verified(listOf(3), total = 5)
        assertTrue(text, text.contains("1 of 5"))
        assertTrue(text, text.contains("#3"))
        assertTrue("must not imply a second line", !text.contains("#3,"))
    }

    @Test
    fun aSingleLineCaptureIsNotCountedAsAFraction() {
        val text = CrackOutcome.verified(listOf(1), total = 1)
        assertTrue(text, text.contains("the only hash line"))
        assertTrue("no '1 of 1' arithmetic on a one-line capture", !text.contains("1 of 1"))
    }
}
