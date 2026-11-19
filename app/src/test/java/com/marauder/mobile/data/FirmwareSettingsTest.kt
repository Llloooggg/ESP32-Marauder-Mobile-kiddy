package com.marauder.mobile.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Parsing of the board's own `settings` dump. The text below is what the firmware printed
 * over the serial line on our ESP32-S3 DevKitC (fw v1.20.0, json-serial proto 3), so the
 * parser is pinned to the real format, not an invented one.
 */
class FirmwareSettingsTest {

    private val dump = """
        #settings
        Settings
        ----------------------------------------------
        Name: ForcePMKID
        Type: bool
        Value: false

        Name: ForceProbe
        Type: bool
        Value: false

        Name: SavePCAP
        Type: bool
        Value: true

        Name: EnableLED
        Type: bool
        Value: true

        Name: EPDeauth
        Type: bool
        Value: false

        Name: ChanHop
        Type: bool
        Value: false

        Name: ClientSSID
        Type: String
        Value:

        Name: ClientPW
        Type: String
        Value: [redacted]

        Name: wu
        Type: String
        Value:
    """.trimIndent()

    @Test
    fun readsEverySettingInTheDump() {
        val parsed = FirmwareSettings.parse(dump)
        assertEquals(
            "names read: ${parsed.map { it.name }}",
            listOf("ForcePMKID", "ForceProbe", "SavePCAP", "EnableLED", "EPDeauth", "ChanHop", "ClientSSID", "ClientPW", "wu"),
            parsed.map { it.name },
        )
    }

    @Test
    fun booleansAreTheEditableOnesAndCarryTheirState() {
        val parsed = FirmwareSettings.parse(dump).associateBy { it.name }
        assertTrue(parsed.getValue("SavePCAP").enabled)
        assertFalse("ChanHop is off on this board by default", parsed.getValue("ChanHop").enabled)
        assertTrue("only bool settings can be written", parsed.getValue("SavePCAP").editable)
        assertFalse("a String setting has no `settings -s … enable` form", parsed.getValue("wu").editable)
    }

    @Test
    fun theBoardsOwnRedactionIsShownAsHiddenNotAsAnEmptySecret() {
        val pw = FirmwareSettings.parse(dump).first { it.name == "ClientPW" }
        assertTrue(pw.redacted)
        assertEquals("", pw.value)
        val ssid = FirmwareSettings.parse(dump).first { it.name == "ClientSSID" }
        assertFalse("an empty value is not a hidden one", ssid.redacted)
    }

    @Test
    fun aHalfReadBlockIsNeverTurnedIntoAToggle() {
        // A Name/Type pair whose Value line never arrived (a line lost on the link) must not
        // become a switch: the app would be writing a state it never read.
        val partial = "Name: ChanHop\nType: bool\nName: SavePCAP\nType: bool\nValue: true"
        val parsed = FirmwareSettings.parse(partial)
        assertEquals(listOf("SavePCAP"), parsed.map { it.name })
    }

    @Test
    fun chatterAroundTheDumpIsIgnored() {
        val noisy = """
            #settings
            Settings
            ----------------------------------------------
            Name: ChanHop
            Type: bool
            Value: true

            @J {"t":"status","mode":1}
        """.trimIndent()
        val parsed = FirmwareSettings.parse(noisy)
        assertEquals(1, parsed.size)
        assertTrue(parsed.first().enabled)
    }

    @Test
    fun readBackIsWhatDecidesWhetherAWriteHappened() {
        val before = FirmwareSettings.parse(dump)
        val after = FirmwareSettings.parse(dump.replace("Name: ChanHop\nType: bool\nValue: false", "Name: ChanHop\nType: bool\nValue: true"))
        assertTrue(FirmwareSettings.agrees(before, after, "ChanHop", true))
        assertFalse("the dump still says off, so the write did not land", FirmwareSettings.agrees(before, before, "ChanHop", true))
        assertFalse("a setting that vanished cannot be confirmed", FirmwareSettings.agrees(before, after, "Nope", true))
    }

    @Test
    fun writesUseTheFirmwaresOwnWords() {
        assertEquals("settings -s ChanHop disable", FirmwareCommands.settingsSet("ChanHop", false))
        assertEquals("settings -s ChanHop enable", FirmwareCommands.settingsSet("ChanHop", true))
        assertEquals("settings", FirmwareCommands.settingsDump())
        assertEquals(FirmwareSettings.WRITE_FAILED, "Could not successfully update setting")
    }
}
