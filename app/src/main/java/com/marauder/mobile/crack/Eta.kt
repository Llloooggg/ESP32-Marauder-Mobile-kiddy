package com.marauder.mobile.crack

import kotlin.math.max
import kotlin.math.roundToLong

/**
 * A time left, and the sentence that says what it rests on.
 *
 * PBKDF2-HMAC-SHA1 with 4096 rounds is the whole price of one guess, and it is the same price on the
 * first word of a list as on the last: that is what makes an ETA out of a rate honest, and it is also
 * the whole content of the estimate — remaining guesses divided by a rate measured over the last
 * window of the run. Two things follow, and both are implemented here rather than in the screen:
 *
 *  * the estimate must be recomputed as the rate moves (a phone throttles, a GPU batch boundary
 *    makes the window jump), and it must never be reported before a rate exists;
 *  * a stopped run has a count that looks like a coverage claim. The engines read a batch of words
 *    before hashing it, so stopping can leave words already read that were never hashed — and a
 *    "TRIED 4.2 M" next to a stopped run is only true about guesses that actually cost 4096 rounds.
 */
object Eta {

    /** Seconds left, or null when nothing can be estimated: no rate sample yet, or nothing left. */
    fun seconds(remainingGuesses: Long, guessesPerSecond: Double): Long? {
        if (remainingGuesses <= 0L || guessesPerSecond <= 0.0) return null
        // A run with one guess and a fast rate still has time left; "0s" reads like a finished run.
        return max(1L, (remainingGuesses / guessesPerSecond).roundToLong())
    }

    /** The rate and the remaining count the estimate was built from, so the number is checkable. */
    fun basis(remainingGuesses: Long, guessesPerSecond: Double): String =
        String.format(
            "ETA is %,d guesses left divided by %,d guesses/s from the last measured window of this " +
                "run. A guess costs 4096 PBKDF2 rounds wherever it sits in the list, so the only part " +
                "of this that moves is the rate - the list itself does not.",
            remainingGuesses,
            guessesPerSecond.roundToLong(),
        )

    /**
     * What a stopped run did. [discardedWords] is what the engine had already read out of the wordlist
     * and never hashed, so the count on screen cannot be read as coverage of the list.
     */
    fun stopped(tried: Long, discardedWords: Int): String =
        if (discardedWords > 0)
            String.format(
                "stopped on request after %,d guesses that were actually hashed. %,d word(s) had already " +
                    "been read into the batch in flight and were never hashed, so the count on screen is " +
                    "guesses paid for, not list positions covered - the next run starts the lists from " +
                    "the beginning.",
                tried,
                discardedWords,
            )
        else
            String.format(
                "stopped on request after %,d guesses that were actually hashed; the next run starts the " +
                    "lists from the beginning.",
                tried,
            )
}
