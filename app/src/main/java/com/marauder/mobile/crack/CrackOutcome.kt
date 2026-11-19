package com.marauder.mobile.crack

/**
 * The words after a run that tried every word and recovered nothing.
 *
 * "A bigger list is the next step" is only true if every captured hash was actually
 * testable. A handshake whose AP nonce never reached the capture, a PMKID of zeros, an
 * SSID that could not be read — those cannot be checked by any wordlist, no matter how
 * big, and saying otherwise sends the user to build a list for a hash that is not a
 * hash. The screen shows the per-line reasons; this is the one-line verdict above them.
 */
object CrackOutcome {

    /** [testable] of [total] lines were accepted by the cracker; see CrackCore.parse. */
    fun exhausted(testable: Int, total: Int): String {
        val untestable = (total - testable).coerceAtLeast(0)
        return if (untestable == 0) {
            "The list ran out without a match. A bigger list or rules is the next step."
        } else {
            "The list ran out: $testable of $total hash(es) could be tested; the rest cannot be " +
                "checked by any wordlist (reasons above)."
        }
    }
}
