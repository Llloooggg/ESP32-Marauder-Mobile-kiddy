package com.marauder.mobile.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The firmware's parser honours quotes but has no escaping, so some values simply
 * cannot be sent. Sending a truncated or half-parsed password/host would be worse
 * than refusing, so the app refuses instead.
 */
class FirmwareArgTest {

    @Test
    fun `plain values are wrapped in apostrophes`() {
        assertEquals("'hunter2'", FirmwareArg.wrap("hunter2"))
        assertEquals("'my wifi key'", FirmwareArg.wrap("my wifi key"))
    }

    @Test
    fun `a value containing an apostrophe switches to double quotes`() {
        assertEquals("\"pa'ss\"", FirmwareArg.wrap("pa'ss"))
    }

    @Test
    fun `a value containing both quote kinds cannot be sent at all`() {
        assertNull(FirmwareArg.wrap("a\"b'c"))
        assertFalse(FirmwareArg.acceptable("a\"b'c"))
    }

    @Test
    fun `control characters are refused because they would end the command line`() {
        assertNull(FirmwareArg.wrap("line1\nline2"))
        assertNull(FirmwareArg.wrap("tab\there"))
        assertNull(FirmwareArg.wrap("del\u007Fhere"))
        assertNull(FirmwareArg.wrap(""))
        assertTrue(FirmwareArg.acceptable("p4ssw0rd!@#"))
    }

    // A whole command line, not one argument: the wire protocol ends a command at '\n', so text that
    // carries a break would reach the board as several commands while the app's console and journal
    // show a single `>` entry. The refusal is what keeps the record true.

    @Test
    fun `a command must be one line`() {
        assertEquals("scanall", FirmwareArg.oneLine("  scanall  "))
        assertNull(FirmwareArg.oneLine("scanall\nreboot"))
        assertNull(FirmwareArg.oneLine("scanall\r\nreboot"))
        assertNull(FirmwareArg.oneLine("evilportal -c sethtmlstr\nreboot"))
        assertNull(FirmwareArg.oneLine("channel\t-s 6"))   // a tab is a control character too
        assertNull(FirmwareArg.oneLine("   "))
    }

    @Test
    fun `the refusal counts what the board would actually run`() {
        assertEquals(2, FirmwareArg.lineCount("scanall\nreboot"))
        assertEquals(3, FirmwareArg.lineCount("scanall\r\nstopscan\nreboot"))
        // Blank fragments between breaks are not commands, and the smallest refusal is still one.
        assertEquals(2, FirmwareArg.lineCount("scanall\n\n\nreboot"))
        assertEquals(1, FirmwareArg.lineCount("\n\n  \n"))
    }
}
