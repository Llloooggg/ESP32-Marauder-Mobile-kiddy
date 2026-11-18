package com.marauder.extractor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Known-answer tests for the 22000 verification core, using hashcat's own
 * example vectors (hashcat wiki "Example Hashes", mode 22000, footnote 1:
 * password "hashcat!"). These are authoritative: they come from hashcat's
 * own self-test/crackable captures, not from our code.
 */
class CrackCoreTest {

    private val pmkidLine = "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***"

    private val handshakeLine =
        "WPA*02*024022795224bffca545276c3762686f*6466b38ec3fc*225edc49b7aa*54502d4c494e4b5f484153484341545f54455354*10e3be3b005a629e89de088d6a2fdc489db83ad4764f2d186b9cde15446e972e*0103007502010a0000000000000000000148ce2ccba9c1fda130ff2fbbfb4fd3b063d1a93920b0f7df54a5cbf787b16171000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac028000*a2"

    @Test
    fun officialPmkidVectorCracks() {
        val t = CrackCore.parse(pmkidLine)
        assertNotNull(t)
        assertEquals(HashKind.PMKID, t!!.kind)
        assertEquals("hashcat-essid", t.essidText)
        assertTrue(t.verify("hashcat!"))
        assertTrue(!t.verify("hashcat"))
        assertTrue(!t.verify("password123"))
    }

    @Test
    fun officialHandshakeVectorCracks() {
        val t = CrackCore.parse(handshakeLine)
        assertNotNull(t)
        assertEquals(HashKind.HANDSHAKE, t!!.kind)
        assertEquals(2, t.keyver)
        assertEquals("TP-LINK_HASHCAT_TEST", t.essidText)
        assertTrue(t.verify("hashcat!"))
        assertTrue(!t.verify("hashcat1"))
        assertTrue(!t.verify("Hashcat!"))
    }

    @Test
    fun malformedLinesAreRejectedNotThrown() {
        assertNull(CrackCore.parse(""))
        assertNull(CrackCore.parse("garbage"))
        assertNull(CrackCore.parse("WPA*03*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*6861***"))
        assertNull(CrackCore.parse("WPA*01*zz4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*6861***"))
        // PMKID with empty essid → nothing a cracker could verify
        assertNull(CrackCore.parse("WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4****"))
        // eapol too short for auth_packet (99-byte minimum)
        assertNull(CrackCore.parse("WPA*02*024022795224bffca545276c3762686f*6466b38ec3fc*225edc49b7aa*5450*" +
            "10e3be3b005a629e89de088d6a2fdc489db83ad4764f2d186b9cde15446e972e*010300*a2"))
    }

    @Test
    fun aesCmacRfc4493Vectors() {
        // RFC 4493 test vectors (AES-128 key 2b7e151628aed2a6abf7158809cf4f3c)
        fun unhex(s: String) = ByteArray(s.length / 2) {
            ((Character.digit(s[it * 2], 16) shl 4) or Character.digit(s[it * 2 + 1], 16)).toByte()
        }
        val key = unhex("2b7e151628aed2a6abf7158809cf4f3c")
        assertEquals("bb1d6929e95937287fa37d129b756746",
            WpaCrypto.aesCmac(key, ByteArray(0)).joinToString("") { "%02x".format(it) })
        val msg = unhex("6bc1bee22e409f96e93d7e117393172a")
        assertEquals("070a16b46b4d4144f79bdd9dd04a287c",
            WpaCrypto.aesCmac(key, msg).joinToString("") { "%02x".format(it) })
        val msg40 = unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411")
        assertEquals("dfa66747de9ae63030ca32611497c827",
            WpaCrypto.aesCmac(key, msg40).joinToString("") { "%02x".format(it) })
    }
}
