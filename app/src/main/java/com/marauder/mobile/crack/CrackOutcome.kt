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

    /**
     * Under a recovered password: which of the extracted records actually verify it.
     *
     * One capture can hold several client messages from the same network, each its own
     * handshake attempt, so the same password is expected to verify more than one line.
     * Printing one result card per line made that look like the password had been found
     * twice; one card that names the lines says the same thing without the illusion.
     */
    fun verified(lines: List<Int>, total: Int): String {
        val which = lines.joinToString(", ") { "#$it" }
        return when {
            total <= 1 -> "verified by the only hash line (#$which)"
            lines.size == 1 -> "verified by 1 of $total hash lines (#$which)"
            else -> "verified by ${lines.size} of $total hash lines (#$which)"
        }
    }
}
