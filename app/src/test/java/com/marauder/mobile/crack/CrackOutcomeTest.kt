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
}
