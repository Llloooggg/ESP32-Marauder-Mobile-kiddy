package com.marauder.extractor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.io.ByteArrayInputStream

/**
 * Synthetic-pcap tests for the Extractor. Frame layouts mirror what the
 * Marauder firmware writes: bare 802.11 frames (linktype 105), MGMT frames
 * without FCS, DATA frames with FCS (both variants are exercised).
 *
 * The PMKID test uses the official hashcat mode-22000 self-test vector:
 * essid "hashcat-essid", password "hashcat!",
 * PMKID 4d4fe7aac3a2cecab195321ceb99a7d0 for fc:69:0c:15:82:64 → f4:74:7f:87:f9:f4.
 */
class ExtractorTest {

    companion object {
        private fun le32Bytes(v: Int) = byteArrayOf(v.toByte(), (v ushr 8).toByte(), (v ushr 16).toByte(), (v ushr 24).toByte())
        private fun be32Bytes(v: Int) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
    }

    // ---- fixtures ---------------------------------------------------------------

    private val apMac = hexBytes("fc690c158264")   // AA (authenticator / BSSID)
    private val staMac = hexBytes("f4747f87f9f4")  // SPA (supplicant)
    private val apMacHex = "fc690c158264"
    private val staMacHex = "f4747f87f9f4"
    private val ssid = "hashcat-essid".toByteArray(Charsets.UTF_8)
    private val ssidHex = "686173686361742d6573736964"

    private class PcapBuilder(val linktype: Int = 105, val bigEndian: Boolean = false) {
        private val out = java.io.ByteArrayOutputStream()

        init {
            // global header (24B): magic, version_major(u16 2), version_minor(u16 4),
            // thiszone 0, sigfigs 0, snaplen, network (all u32 LE unless bigEndian flag)
            out.write(if (bigEndian) be32Bytes(0xA1B2C3D4.toInt()) else le32Bytes(0xA1B2C3D4.toInt()))
            out.write(byteArrayOf(2, 0, 4, 0)) // version 2.4
            out.write(le32Bytes(0)); out.write(le32Bytes(0)); out.write(le32Bytes(0x40000))
            out.write(if (bigEndian) be32Bytes(linktype) else le32Bytes(linktype))
        }

        fun frame(payload: ByteArray, truncateTo: Int = -1) {
            // record header: ts_sec, ts_usec, incl_len, orig_len
            val len = if (bigEndian) be32Bytes(payload.size) else le32Bytes(payload.size)
            out.write(le32Bytes(0)); out.write(le32Bytes(0))
            out.write(len); out.write(len)
            val end = if (truncateTo in 0 until payload.size) truncateTo else payload.size
            out.write(payload, 0, end)
        }

        fun bytes(): ByteArray = out.toByteArray()
    }

    private fun beacon(ssid: ByteArray, ccmp: Boolean = true): ByteArray {
        val ie = ArrayList<Byte>()
        ie.add(0); ie.add(ssid.size.toByte()); ie.addAll(ssid.toList())
        // RSN: version 1, group cipher, 1 pairwise, 1 AKM (PSK 00-0F-AC-02)
        val rsn = if (ccmp) hexBytes("0001 000fac04 0001 000fac04 0001 000fac02")
        else hexBytes("0001 000fac01 0001 000fac01 0001 000fac02")
        ie.add(48); ie.add(rsn.size.toByte()); ie.addAll(rsn.toList())
        // fixed part: fc, dur, addr1=bcast, addr2=BSSID, addr3=BSSID, seqctl(2), ts(8), interval(2), caps(2)
        val fixed = hexBytes("8000 0000") + ByteArray(6) { 0xFF.toByte() } + apMac + apMac +
            hexBytes("0000") + ByteArray(8) + hexBytes("6400 0100")
        return fixed + ie.toByteArray()
    }

    /**
     * EAPOL-Key frame exactly as hashcat's `struct auth_packet` (module_22000.c)
     * lays it out: version@0 type@1 len@2-3 desc@4 keyinfo@5-6 keylen@7-8
     * replay@9-16 nonce@17-48 iv@49-64 rsc@65-72 keyid@73-80 mic@81-96
     * keydata_len@97-98 keydata@99.
     */
    private fun eapolKey(keyInfo: Int, replay: Long, nonce: ByteArray, body: ByteArray, mic: ByteArray? = null): ByteArray {
        require(nonce.size == 32)
        val f = ByteArray(99 + body.size)
        f[0] = 1; f[1] = 3 // EAPOL version 1, type key
        val bodyLen = f.size - 4
        f[2] = (bodyLen ushr 8).toByte(); f[3] = bodyLen.toByte()
        f[4] = 2 // descriptor type: EAPOL-Key
        f[5] = (keyInfo ushr 8).toByte(); f[6] = keyInfo.toByte()
        f[7] = 0; f[8] = 16 // key length
        for (i in 0 until 8) f[9 + i] = (replay ushr (56 - 8 * i)).toByte()
        System.arraycopy(nonce, 0, f, 17, 32)
        // iv/rsc/keyid @49..80 left zero
        if (mic != null) System.arraycopy(mic, 0, f, 81, 16)
        f[97] = (body.size ushr 8).toByte(); f[98] = body.size.toByte()
        System.arraycopy(body, 0, f, 99, body.size)
        return f
    }

    /** 802.11 QoS DATA frame carrying an EAPOL-Key payload. fcLo=0x88, fcHi: 0x01 ToDS / 0x02 FromDS. */
    private fun dataEapol(eapol: ByteArray, fcLo: Int, fcHi: Int, addr1: ByteArray, addr2: ByteArray, withFcs: Boolean): ByteArray {
        val l3 = 26 // QoS data: 24B header + 2B QoS control, then LLC/SNAP (8B)
        val f = ByteArray(if (withFcs) l3 + 8 + eapol.size + 4 else l3 + 8 + eapol.size)
        f[0] = fcLo.toByte(); f[1] = fcHi.toByte()
        System.arraycopy(addr1, 0, f, 4, 6)
        System.arraycopy(addr2, 0, f, 10, 6)
        System.arraycopy(addr2, 0, f, 16, 6) // addr3 = BSSID
        f[24] = 0; f[25] = 0 // QoS control
        f[l3] = 0xAA.toByte(); f[l3 + 1] = 0xAA.toByte(); f[l3 + 2] = 3
        f[l3 + 6] = 0x88.toByte(); f[l3 + 7] = 0x8E.toByte()
        System.arraycopy(eapol, 0, f, l3 + 8, eapol.size)
        return f
    }

    private fun run(bytes: ByteArray) = Extractor.extract(ByteArrayInputStream(bytes))

    // ---- PMKID -------------------------------------------------------------------

    private val officialPmkidHex = "4d4fe7aac3a2cecab195321ceb99a7d0"
    private val officialPmkid = hexBytes(officialPmkidHex)

    private fun pmkidM1(pmkid: ByteArray, legacy: Boolean = false): ByteArray {
        val ie = if (legacy) hexBytes("dd 18 000e9004 00000001 0010") + pmkid
        else hexBytes("dd 16 000fac06") + pmkid
        // M1: key_info = version2(0x0002) | ACK(0x0080)
        return eapolKey(keyInfo = 0x0082, replay = 1, nonce = ByteArray(32), body = ie)
    }

    @Test
    fun pmkidProducesOfficialHashcatLine() {
        val pcap = PcapBuilder()
        pcap.frame(beacon(ssid))
        pcap.frame(dataEapol(pmkidM1(officialPmkid), fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        val rep = run(pcap.bytes())

        assertEquals(1, rep.hashes.size)
        val h = rep.hashes[0]
        assertEquals(HashKind.PMKID, h.kind)
        assertEquals("hashcat-essid", h.essid)
        assertEquals("fc:69:0c:15:82:64", h.bssid)
        assertEquals("f4:74:7f:87:f9:f4", h.sta)
        assertEquals(255, h.messagePair)
        assertEquals(2, h.keyver)
        assertEquals(1, rep.beacons)
        assertEquals(1, rep.eapolFrames)
        assertEquals("WPA*01*$officialPmkidHex*$apMacHex*$staMacHex*$ssidHex***", h.line)
    }

    @Test
    fun pmkidMatchesJvmCryptoOfOfficialVector() {
        // PBKDF2-HMAC-SHA1("hashcat!", essid, 4096, 32) → PMK,
        // HMAC-SHA1(key=PMK, "PMK Name"+AA+SPA)[0..16) must equal the official
        // hashcat self-test PMKID. Cross-checks the fixture, not the parser.
        val pmk = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            .generateSecret(PBEKeySpec("hashcat!".toCharArray(), ssid, 4096, 256)).encoded
        val mac = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(pmk, "HmacSHA1")) }
        val tag = mac.doFinal("PMK Name".toByteArray(Charsets.UTF_8) + apMac + staMac)
        assertEquals(officialPmkidHex, tag.take(16).joinToString("") { "%02x".format(it) })
    }

    @Test
    fun pmkidLegacyVendorIeIsAccepted() {
        val pcap = PcapBuilder()
        pcap.frame(beacon(ssid))
        pcap.frame(dataEapol(pmkidM1(officialPmkid, legacy = true), fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        val rep = run(pcap.bytes())
        assertEquals(1, rep.hashes.size)
        assertTrue(rep.hashes[0].line.contains(officialPmkidHex))
    }

    @Test
    fun pmkidDuplicateIsDedupedAndDataWithoutFcsStillParses() {
        val pcap = PcapBuilder()
        pcap.frame(beacon(ssid))
        pcap.frame(dataEapol(pmkidM1(officialPmkid), fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        pcap.frame(dataEapol(pmkidM1(officialPmkid), fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = false))
        val rep = run(pcap.bytes())
        assertEquals(1, rep.hashes.size)
    }

    @Test
    fun pmkidWithoutBeaconYieldsNoteNotHash() {
        val pcap = PcapBuilder()
        pcap.frame(dataEapol(pmkidM1(officialPmkid), fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        val rep = run(pcap.bytes())
        assertEquals(0, rep.hashes.size)
        assertTrue(rep.notes.any { it.contains("no beacon seen") })
    }

    // ---- M1 + M2 handshake ---------------------------------------------------------

    private val anonce = hexBytes("581cbc35776079d2e2c4b7719fc77a77d8724a622d2b779a479d8a2dfd028c80")

    private fun rsnIe() = hexBytes("dd 14 000fac01 000f 00000fac04 00000fac02 0001 0000")
    private fun m2Body() = rsnIe() + hexBytes("dd 12 000fac04 0001 00000fac04")

    @Test
    fun m1m2PairProducesHandshakeLineAndCorrectMic() {
        val password = "hashcat!"
        val snonce = ByteArray(32) { (it + 1).toByte() }

        val m1 = eapolKey(keyInfo = 0x0082, replay = 13, nonce = anonce, body = rsnIe())
        // Build M2 with the MIC computed by the same crypto the cracker will use
        // (keyver 2 = AES-128-CMAC over the zero-MIC frame with KCK derived from PMK),
        // then patch it in — the extractor must surface exactly these 16 bytes.
        val m2 = eapolKey(keyInfo = 0x0102, replay = 14, nonce = snonce, body = m2Body(), mic = ByteArray(16))
        val mic = keyver2Mic(m2, password, anonce, snonce)
        System.arraycopy(mic, 0, m2, 81, 16)

        val pcap = PcapBuilder()
        pcap.frame(beacon(ssid))
        // M1 AP→STA: QoS data + FromDS (fcHi=0x02); M2 STA→AP: QoS data + ToDS (fcHi=0x01)
        pcap.frame(dataEapol(m1, fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        pcap.frame(dataEapol(m2, fcLo = 0x88, fcHi = 0x01, addr1 = apMac, addr2 = staMac, withFcs = true))

        val rep = run(pcap.bytes())
        assertEquals(1, rep.hashes.size)
        val h = rep.hashes[0]
        assertEquals(HashKind.HANDSHAKE, h.kind)
        assertEquals("hashcat-essid", h.essid)
        assertEquals("fc:69:0c:15:82:64", h.bssid)
        assertEquals("f4:74:7f:87:f9:f4", h.sta)
        assertEquals(2, h.messagePair)
        assertEquals(2, h.keyver) // key_info version bits in M2 (WPA2-AES → CMAC)

        // The line must carry: mic, aa, spa, essid, anonce, full M2 frame, mp=02
        val parts = h.line.split("*")
        assertEquals("WPA", parts[0])
        assertEquals("02", parts[1])
        assertEquals(mic.joinToString("") { "%02x".format(it) }, parts[2])
        assertEquals(apMacHex, parts[3])
        assertEquals(staMacHex, parts[4])
        assertEquals(ssidHex, parts[5])
        assertEquals(hexOf(anonce), parts[6])
        assertEquals(hexOf(m2), parts[7])
        assertEquals("02", parts[8])
        // hashcat requires a full 64-hex anonce and an eapol of at least 99 bytes
        assertEquals(64, parts[6].length)
        assertTrue(parts[7].length >= 99 * 2)
    }

    @Test
    fun m2WithoutM1IsNotedNotCracked() {
        val snonce = ByteArray(32)
        val m2 = eapolKey(keyInfo = 0x0102, replay = 14, nonce = snonce, body = m2Body(), mic = ByteArray(16))
        val pcap = PcapBuilder()
        pcap.frame(beacon(ssid))
        pcap.frame(dataEapol(m2, fcLo = 0x88, fcHi = 0x01, addr1 = apMac, addr2 = staMac, withFcs = true))
        val rep = run(pcap.bytes())
        assertEquals(0, rep.hashes.size)
        assertTrue(rep.notes.any { it.contains("without its M1") })
    }

    // ---- robustness -----------------------------------------------------------------

    @Test
    fun truncatedCaptureParsesWhatFits() {
        val pcap = PcapBuilder()
        pcap.frame(beacon(ssid))
        val full = dataEapol(pmkidM1(officialPmkid), fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true)
        pcap.frame(full, truncateTo = full.size / 2)
        val rep = run(pcap.bytes())
        assertEquals(1, rep.recordsParsed)
        assertEquals(0, rep.hashes.size)
        assertTrue(rep.notes.any { it.contains("truncated") })
    }

    @Test
    fun bigEndianPcapAndOddLinktypeStillParse() {
        val pcap = PcapBuilder(linktype = 113, bigEndian = true)
        pcap.frame(beacon(ssid))
        pcap.frame(dataEapol(pmkidM1(officialPmkid), fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        val rep = run(pcap.bytes())
        assertEquals(1, rep.hashes.size)
        assertTrue(rep.notes.any { it.contains("linktype 113") })
    }

    @Test
    fun nonPcapInputReportsGracefully() {
        val rep = run("this string is definitely not a pcap file".toByteArray())
        assertEquals(0, rep.recordsParsed)
        assertTrue(rep.notes.any { it.contains("not a libpcap file") })
    }

    // ---- byte helpers ------------------------------------------------------------

    private fun hexBytes(s: String): ByteArray {
        val clean = s.replace(" ", "")
        return ByteArray(clean.length / 2) {
            ((Character.digit(clean[it * 2], 16) shl 4) or Character.digit(clean[it * 2 + 1], 16)).toByte()
        }
    }

    private fun hexOf(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    // ---- JVM-crypto helpers used to cross-check extracted bytes -----------------------
    // KCK derivation exactly as hashcat 22000: PMK = PBKDF2-HMAC-SHA1(pass, essid, 4096),
    // kde = HMAC-MD5(PMK, "Pairwise key expansion\0" || min(aa,spa) || max(aa,spa)
    //        || min(nonce) || max(nonce)), KCK = kde[0..16).

    private fun pairwiseKeyExpansion(pmk: ByteArray, anonce: ByteArray, snonce: ByteArray): ByteArray {
        val (macLow, macHigh) = if (lexLessOrEqual(apMac, staMac)) Pair(apMac, staMac) else Pair(staMac, apMac)
        val (nonLow, nonHigh) = if (lexLessOrEqual(anonce, snonce)) Pair(anonce, snonce) else Pair(snonce, anonce)
        val pke = ByteArray(99)
        System.arraycopy("Pairwise key expansion\u0000".toByteArray(Charsets.ISO_8859_1), 0, pke, 0, 23)
        System.arraycopy(macLow, 0, pke, 23, 6)
        System.arraycopy(macHigh, 0, pke, 29, 6)
        System.arraycopy(nonLow, 0, pke, 35, 32)
        System.arraycopy(nonHigh, 0, pke, 67, 32)
        return pke
    }

    private fun pmkOf(pass: String): ByteArray =
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            .generateSecret(PBEKeySpec(pass.toCharArray(), ssid, 4096, 256)).encoded

    private fun kck(pmk: ByteArray, anonce: ByteArray, snonce: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacMD5").apply { init(SecretKeySpec(pmk, "HmacMD5")) }
        return mac.doFinal(pairwiseKeyExpansion(pmk, anonce, snonce)).copyOfRange(0, 16)
    }

    private fun lexLessOrEqual(a: ByteArray, b: ByteArray): Boolean {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d < 0
        }
        return a.size <= b.size
    }

    private fun keyver2Mic(m2: ByteArray, password: String, anonce: ByteArray, snonce: ByteArray): ByteArray {
        val k = kck(pmkOf(password), anonce, snonce)
        val msg = m2.copyOf().also { java.util.Arrays.fill(it, 81, 97, 0) }
        return aesCmac(k, msg)
    }

    private fun aesCmac(key: ByteArray, msg: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        val l = cipher.doFinal(ByteArray(16))

        fun shl1(b: ByteArray): ByteArray {
            val out = ByteArray(16)
            for (i in 0 until 15) out[i] = ((b[i].toInt() shl 1) or ((b[i + 1].toInt() and 0x80) shr 7)).toByte()
            out[15] = ((b[15].toInt() shl 1)).toByte()
            return out
        }

        val k1 = shl1(l).also { if (l[0].toInt() and 0x80 != 0) it[15] = (it[15].toInt() xor 0x87).toByte() }
        val k2 = shl1(k1).also { if (k1[0].toInt() and 0x80 != 0) it[15] = (it[15].toInt() xor 0x87).toByte() }

        fun xorIn(x: ByteArray, y: ByteArray) = ByteArray(16) { (x[it].toInt() xor y[it].toInt()).toByte() }

        val n = if (msg.isEmpty()) 1 else (msg.size + 15) / 16
        val lastComplete = msg.isNotEmpty() && msg.size % 16 == 0
        var x = ByteArray(16)
        for (i in 0 until n) {
            val start = i * 16
            val avail = maxOf(0, minOf(16, msg.size - start))
            val block = ByteArray(16).also { System.arraycopy(msg, start, it, 0, avail) }
            val y = if (i == n - 1) {
                if (lastComplete) xorIn(block, k1)
                else {
                    val padded = block.also { if (avail < 16) it[avail] = 0x80.toByte() else it[15] = (it[15].toInt() or 0x80).toByte() }
                    xorIn(padded, k2)
                }
            } else block
            x = cipher.doFinal(xorIn(x, y))
        }
        return x
    }
}
