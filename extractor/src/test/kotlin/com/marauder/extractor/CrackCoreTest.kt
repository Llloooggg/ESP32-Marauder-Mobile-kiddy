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

    /**
     * The same handshake as the example above, in the layout the air really uses:
     * the supplicant nonce in the standard's KEY NONCE field (49..81) and the Key
     * IV/RSC/ID region (17..49) left empty — which is what this app's own extractor
     * writes, and what a live access point's frames were confirmed to look like.
     *
     * The MIC is recomputed for the rewritten frame with the JDK's own PBKDF2/HMAC,
     * independently of the code under test, so this pins the nonce placement rather
     * than agreeing with the implementation being checked.
     */
    @Test
    fun airLayoutHandshakeLineCracksToo() {
        val p = handshakeLine.split("*")
        val stored = unhex(p[7])
        val snonce = stored.copyOfRange(17, 49)
        val air = stored.copyOf().also { f ->
            java.util.Arrays.fill(f, 17, 49, 0)
            System.arraycopy(snonce, 0, f, 49, 32)
        }

        val essid = unhex(p[5])
        val pmk = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            .generateSecret(javax.crypto.spec.PBEKeySpec("hashcat!".toCharArray(), essid, 4096, 256)).encoded
        val pke = ByteArray(100)
        System.arraycopy("Pairwise key expansion\u0000".toByteArray(Charsets.ISO_8859_1), 0, pke, 0, 23)
        val (macLow, macHigh) = ordered(unhex(p[3]), unhex(p[4]))
        val (nonLow, nonHigh) = ordered(unhex(p[6]), snonce)
        System.arraycopy(macLow, 0, pke, 23, 6)
        System.arraycopy(macHigh, 0, pke, 29, 6)
        System.arraycopy(nonLow, 0, pke, 35, 32)
        System.arraycopy(nonHigh, 0, pke, 67, 32)
        val kck = javax.crypto.Mac.getInstance("HmacSHA1").apply {
            init(javax.crypto.spec.SecretKeySpec(pmk, "HmacSHA1"))
        }.doFinal(pke).copyOfRange(0, 16)
        val mic = javax.crypto.Mac.getInstance("HmacSHA1").apply {
            init(javax.crypto.spec.SecretKeySpec(kck, "HmacSHA1"))
        }.doFinal(air).copyOfRange(0, 16)

        val line = "WPA*02*" + hex(mic) + "*" + p[3] + "*" + p[4] + "*" + p[5] + "*" + p[6] + "*" + hex(air) + "*a2"
        val t = CrackCore.parse(line)
        assertNotNull(t)
        assertTrue("the SNonce in the standard's field must verify", t!!.verify("hashcat!"))
        assertTrue(!t.verify("hashcat1"))
    }

    private fun ordered(a: ByteArray, b: ByteArray): Pair<ByteArray, ByteArray> =
        if (compare(a, b) <= 0) Pair(a, b) else Pair(b, a)

    private fun compare(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    private fun unhex(s: String): ByteArray {
        require(s.length % 2 == 0)
        return ByteArray(s.length / 2) { ((Character.digit(s[it * 2], 16) shl 4) or Character.digit(s[it * 2 + 1], 16)).toByte() }
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

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

    @Test
    fun standardRsnHandshakeCracks() {
        // Simulate a genuine WPA2-AES AP (IEEE 802.11 RSN): KCK comes from the
        // PRF-384 first block — HMAC-SHA1(PMK, 0x00 || label || 0x00 || macs || nonces)
        // — and M2's MIC = AES-CMAC(KCK, EAPOL)[0..16). hashcat's aux kernels do
        // not try this combination; our kckStd variant must.
        val password = "s3cret-pass!"
        val essid = "RealWorldNet".toByteArray(Charsets.UTF_8)
        val aa = "001122334455"
        val spa = "66778899aabb"
        val anonce = "aa".repeat(32)
        val snonce = "11".repeat(32)
        val frame = "01030075" + "02" + "010a" + "0000" + "0000000000000001" +
            snonce + "0".repeat(96) + "0016" + "30140100000fac040100000fac040100000fac028000"

        fun unhex(s: String) = ByteArray(s.length / 2) {
            ((Character.digit(s[it * 2], 16) shl 4) or Character.digit(s[it * 2 + 1], 16)).toByte()
        }
        fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

        val pmk = WpaCrypto.pbkdf2Sha1(password, essid, 4096, 32)
        val kdfMsg = byteArrayOf(0) +
            "Pairwise key expansion".toByteArray(Charsets.ISO_8859_1) + byteArrayOf(0) +
            unhex(aa) + unhex(spa) + unhex(snonce) + unhex(anonce) // min(snonce)<max(anonce), aa<spa
        val kck = WpaCrypto.hmac("HmacSHA1", pmk, kdfMsg).copyOfRange(0, 16)
        val mic = WpaCrypto.aesCmac(kck, unhex(frame))

        val line = "WPA*02*${hex(mic)}*$aa*$spa*${hex(essid)}*$anonce*$frame*02"
        val t = CrackCore.parse(line)
        assertNotNull(t)
        assertEquals(2, t!!.keyver)
        assertTrue(t.verify(password))
        assertTrue(!t.verify("s3cret-pass"))
        assertTrue(!t.verify("wrong-password"))
    }
}
