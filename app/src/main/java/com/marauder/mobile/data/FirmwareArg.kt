package com.marauder.mobile.data

/**
 * Rules for handing an argument to the firmware's command parser
 * (`CommandLine::parseCommand`), so the app never sends something the firmware will
 * mis-read:
 *
 *  * it splits on spaces but keeps text inside `"` or `'` intact;
 *  * it has **no escaping**, so a value containing both quote kinds cannot be wrapped
 *    at all — it must be refused, not truncated or half-sent;
 *  * a control character (newline above all) would end the command line early and
 *    could leave part of the value to be parsed as a separate command, so those values
 *    are refused too.
 */
object FirmwareArg {

    /** [value] wrapped so the firmware keeps it as one argument, or null if impossible. */
    fun wrap(value: String): String? {
        if (value.isEmpty()) return null
        if (value.any { it.code < 0x20 || it.code == 0x7f }) return null
        return when {
            !value.contains('\'') -> "'$value'"
            !value.contains('"') -> "\"$value\""
            else -> null
        }
    }

    /** True when [value] can be handed over at all. */
    fun acceptable(value: String): Boolean = wrap(value) != null

    /**
     * The command as exactly one line, or null when it is not one. The wire protocol ends a command
     * at `\n`, so a pasted multi-line value would reach the board as several commands while the
     * app's console and journal show a single `>` line — what was transmitted and what the record
     * claims would stop matching. Refusing is what keeps the record true.
     */
    fun oneLine(command: String): String? {
        val trimmed = command.trim()
        if (trimmed.isEmpty()) return null
        if (trimmed.any { it == '\n' || it == '\r' || it.code < 0x20 || it.code == 0x7f }) return null
        return trimmed
    }

    /** How many commands the firmware would run if [command] were sent as it stands. */
    fun lineCount(command: String): Int = command.split('\n', '\r').count { it.isNotBlank() }.coerceAtLeast(1)
}
