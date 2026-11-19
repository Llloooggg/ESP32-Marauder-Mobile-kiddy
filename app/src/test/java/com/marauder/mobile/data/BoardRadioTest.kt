package com.marauder.mobile.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Reading the board's channel answer. The reply is a bare number with no label and no end marker,
 * and the board's built-in USB-CDC link loses characters under console load, so the parser has to
 * refuse rather than interpret: guessing a channel from prose is how a run ends up aimed at a
 * channel the board is not on.
 */
class BoardRadioTest {

    @Test
    fun aBareNumberLineIsTheChannel() {
        assertEquals(7, BoardRadio.parseChannelAnswer("7"))
        assertEquals(1, BoardRadio.parseChannelAnswer("1"))
        assertEquals(14, BoardRadio.parseChannelAnswer("14\r"))          // \r left by the wire
        assertEquals(36, BoardRadio.parseChannelAnswer("  36  "))         // stray spaces
        assertEquals(149, BoardRadio.parseChannelAnswer("149"))           // 5 GHz number, still a channel
    }

    @Test
    fun theFirstNumberLineIsTheAnswer() {
        // The reply is the line right after the command echo; a later number is console noise.
        assertEquals(7, BoardRadio.parseChannelAnswer("7\n42\n"))
        assertEquals(7, BoardRadio.parseChannelAnswer("\n\n7\n42\n"))
    }

    @Test
    fun proseNeverBecomesAChannel() {
        // "Set channel: 9" is a real firmware line (CommandLine.cpp:1105) and it is not an answer to
        // the read probe. Only a line made entirely of digits is one.
        assertNull(BoardRadio.parseChannelAnswer("Set channel: 9"))
        assertNull(BoardRadio.parseChannelAnswer("Not set"))
        assertNull(BoardRadio.parseChannelAnswer(""))
        assertNull(BoardRadio.parseChannelAnswer("\n   \n"))
        assertNull(BoardRadio.parseChannelAnswer("50:ff:20:90:5a:ef ESSMo"))  // bytes lost on the wire
    }

    @Test
    fun impossibleChannelNumbersAreRefused() {
        assertNull(BoardRadio.parseChannelAnswer("0"))
        assertNull(BoardRadio.parseChannelAnswer("256"))
        assertNull(BoardRadio.parseChannelAnswer("999999999999"))          // cannot even be an Int
    }

    @Test
    fun theProbeReadsTheChannelWithoutMovingTheRadio() {
        // `channel -s <n>` answers with the channel it has just moved to, so it cannot be used to
        // find out where the board was. The probe has to be the bare verb.
        assertEquals("channel", FirmwareCommands.currentChannel())
        assertFalse(FirmwareCommands.currentChannel().contains("-"))
        assertEquals("channel -s 6", FirmwareCommands.channelSet(6))
    }
}
