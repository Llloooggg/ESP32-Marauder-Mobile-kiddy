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
}
