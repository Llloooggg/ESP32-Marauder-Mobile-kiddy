package com.marauder.extractor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The inspector is what answers "I put the real password in the list and it did
 * not match": a 22000 line can be well-formed and still worthless, and the
 * reason has to be visible.
 */
class CrackInspectTest {

    private val pmkidLine = "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***"

    private val handshakeLine =
        "WPA*02*024022795224bffca545276c3762686f*6466b38ec3fc*225edc49b7aa*54502d4c494e4b5f484153484341545f54455354*10e3be3b005a629e89de088d6a2fdc489db83ad4764f2d186b9cde15446e972e*0103007502010a00000000000000000148ce2ccba9c1fda130ff2fbbfb4fd3b063d1a93920b0f7df54a5cbf787b1617100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac028000*a2"

    private fun tokens(line: String) = line.split("*").toMutableList()

    @Test
    fun hashcatVectorsComeOutCrackable() {
        val pmkid = CrackCore.inspect(pmkidLine)
        assertEquals(HashKind.PMKID, pmkid.kind)
        assertEquals("hashcat-essid", pmkid.essidText)
        assertTrue(pmkid.problems.toString(), pmkid.problems.isEmpty())
        assertTrue(pmkid.crackable)

        val hs = CrackCore.inspect(handshakeLine)
        assertEquals(HashKind.HANDSHAKE, hs.kind)
        assertEquals("TP-LINK_HASHCAT_TEST", hs.essidText)
        assertEquals(2, hs.keyver)
        assertEquals(121, hs.eapolBytes)   // the full M2: 99-byte header + key data
        // The wiki line carries hcxtools' flag bits (0x80) on top of pair 2.
        assertEquals(0xa2, hs.messagePair)
        assertTrue(hs.notes.any { it.contains("message pair 2") })
        assertTrue(hs.notes.any { it.contains("flag 0x80") })
        assertTrue(hs.problems.toString(), hs.problems.isEmpty())
        assertTrue(hs.crackable)
    }

    @Test
    fun zeroAnonceIsNamedAsTheReasonNothingVerifies() {
        val t = tokens(handshakeLine)
        t[6] = "0".repeat(64)
        val i = CrackCore.parse(t.joinToString("*"))
        val insp = CrackCore.inspect(t.joinToString("*"))

        // A line whose AP nonce is zeros is not a credential: parse() refuses it, so
        // no engine spends a wordlist on it, and the inspector names the reason.
        assertNull(i)
        assertFalse(insp.crackable)
        assertTrue(insp.problems.any { it.contains("ANonce is all zeros") })
    }

    @Test
    fun aStoredFrameWithoutAMicFlagIsReportedAsTheWrongMessage() {
        val t = tokens(handshakeLine)
        // key-info bytes 5..6 of the stored EAPOL frame: ACK set, MIC clear = an M1/M4.
        val eapol = t[7]
        t[7] = eapol.substring(0, 10) + "0082" + eapol.substring(14)
        val insp = CrackCore.inspect(t.joinToString("*"))

        assertFalse(insp.crackable)
        assertTrue(insp.problems.any { it.contains("no MIC flag") })
        assertTrue(insp.notes.any { it.contains("M3") })
    }

    @Test
    fun emptySsidIsBlamedOnTheSalt() {
        val t = tokens(pmkidLine)
        t[5] = ""
        val insp = CrackCore.inspect(t.joinToString("*"))
        assertFalse(insp.crackable)
        assertTrue(insp.problems.any { it.contains("SSID") })
    }

    @Test
    fun zeroPmkidAndGarbageLinesAreReported() {
        val t = tokens(pmkidLine)
        t[2] = "0".repeat(32)
        assertTrue(CrackCore.inspect(t.joinToString("*")).problems.any { it.contains("PMKID is all zeros") })

        val junk = CrackCore.inspect("hashcat!")
        assertNull(junk.kind)
        assertFalse(junk.crackable)
        assertTrue(junk.problems.any { it.contains("not a hashcat-22000 line") })
    }
}
