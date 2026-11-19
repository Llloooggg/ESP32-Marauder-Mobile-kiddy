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
}
