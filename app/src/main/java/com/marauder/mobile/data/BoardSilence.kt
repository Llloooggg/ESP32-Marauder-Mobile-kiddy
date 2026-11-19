package com.marauder.mobile.data

/**
 * What it means when the cable is in, the port opened, and the board has said nothing.
 *
 * This is the most common way a session goes wrong and the easiest one to misreport: "Connected to
 * <device>" is a statement about the phone's USB stack, not about the board, and a UI that stops
 * there leaves the user with a spinner and no question to answer. Measured directly on a PC with the
 * same board: an FTDI port opened cleanly at 115200, commands were written to it, and not one byte
 * came back — because that firmware prints its console on the ESP32-S3's own USB, while the cable was
 * in the board's UART-bridge connector. The port was real and the board was fine; the two were not
 * connected to each other.
 *
 * So the rule here is deliberately narrow: silence is reported as silence, with the causes the
 * firmware and the hardware actually allow, and the board is never called dead or broken.
 */
object BoardSilence {

    /**
     * How long a fresh connection gets before it is called mute. Generous on purpose: the app asserts
     * DTR/RTS when it opens the port, which resets an ESP32 through a bridge, so a board that is
     * merely booting answers inside this window and is never accused.
     */
    const val GRACE_MS = 4_000L

    /**
     * The only thing the app can conclude from an open port: [linesFromBoard] bytes-free lines came
     * back in [waitedMs]. One line is enough to stop the claim — the link works, whatever else is
     * wrong with it.
     */
    fun isSilent(linesFromBoard: Int, waitedMs: Long): Boolean =
        linesFromBoard == 0 && waitedMs >= GRACE_MS

    /**
     * The sentence shown for a mute port. It states what the app did (so the user can tell a missing
     * answer from a command that was never sent), then the causes that are real across the boards this
     * app drives.
     *
     * Deliberately no board names and no connector counts: supported boards differ in how many USB
     * ports they expose and what each one is, and an app that guesses "try the other socket" about a
     * board it has never seen is guessing. What every board has is the same fork in the wire — the
     * chip's own USB, where a line rate is a formality, or a UART bridge, where it is real — and a
     * firmware build prints its console on exactly one of those two.
     */
    fun explain(asks: Int, baud: Int, waitedMs: Long): String =
        "the port is open and the board has not sent a single byte in ${waitedMs / 1000}s " +
            "($asks asks over $baud baud). A port that opens is not a board that answers. Every board " +
            "here has the same fork in the wire: the chip's own USB, where a line rate is a formality, " +
            "or a UART bridge, where the rate is real — and firmware prints its console on one of " +
            "those two, so a port on the other one opens and stays mute. A rate other than $baud, or a " +
            "board that needs its reset button, looks the same from here."
}
