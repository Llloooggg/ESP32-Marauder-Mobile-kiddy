package com.marauder.mobile.data

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The line-rate list is settings copy: a person is choosing a number, not reading a manual.
 *
 * Two things are checked here because both have been lost before. The first is length - the
 * descriptions used to run to three lines each, which turns a settings list into a wall. The second is
 * the one caveat that changes the choice: a board wired to its own USB (S2/S3 native) ignores the
 * value entirely, so a rate asked of it is answered and means nothing. A shorter sentence that drops
 * that caveat is worse than a long one, not better.
 */
class LineRateTextTest {

    @Test
    fun `every option says something short`() {
        for (option in LineRateOption.OPTIONS) {
            val text = option.hint
            assertTrue(
                "${option.label} hint is ${text.length} chars - too long for a settings row: $text",
                text.length <= 120,
            )
            assertTrue("${option.label} has no hint", text.isNotBlank())
        }
    }

    @Test
    fun `the rates that only matter over a UART bridge say so`() {
        // The caveat is the reason someone would pick or avoid a rate; it must survive shortening.
        val uartOnly = LineRateOption.OPTIONS.filter { it.rate != 0 }
        for (option in uartOnly) {
            assertTrue(
                "${option.label} must say what happens on the board's own USB: ${option.hint}",
                option.hint.contains("USB"),
            )
        }
    }

    @Test
    fun `the name a rate is offered by is not a sentence`() {
        for (option in LineRateOption.OPTIONS) {
            assertTrue("${option.label} is too long", option.label.length <= 24)
        }
    }
}
