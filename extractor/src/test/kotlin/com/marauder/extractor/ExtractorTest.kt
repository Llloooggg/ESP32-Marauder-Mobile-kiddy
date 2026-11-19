package com.marauder.extractor

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
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

        /** Raw bytes written with no record header: models a block lost in transit. */
        fun raw(bytes: ByteArray) { out.write(bytes) }

        fun bytes(): ByteArray = out.toByteArray()
    }

    /**
     * Beacon (fc 0x8000) advertising an RSN element whose body is built by [rsnBody].
     * Fixed part: fc, dur, addr1=bcast, addr2=BSSID, addr3=BSSID, seqctl(2), ts(8),
     * interval(2), caps(2).
     */
    private fun beacon(ssid: ByteArray, ccmp: Boolean = true): ByteArray {
        val cipher = if (ccmp) "000fac04" else "000fac01"
        return beaconWithRsn(ssid, rsnBody(akms = listOf("000fac02"), pairwise = listOf(cipher), group = cipher))
    }

    private fun beaconWithRsn(ssid: ByteArray, rsnBody: ByteArray): ByteArray {
        val ie = ArrayList<Byte>()
        ie.add(0); ie.add(ssid.size.toByte()); ie.addAll(ssid.toList())
        ie.add(48); ie.add(rsnBody.size.toByte()); ie.addAll(rsnBody.toList())
        val fixed = hexBytes("8000 0000") + ByteArray(6) { 0xFF.toByte() } + apMac + apMac +
            hexBytes("0000") + ByteArray(8) + hexBytes("6400 0100")
        return fixed + ie.toByteArray()
    }

    /**
     * RSN element body: version(2) group cipher(4) pairwise count(2) [suites]
     * akm count(2) [suites] capability(2).
     *
     * The version and both counts are little-endian, which is what a real beacon puts
     * on air (802.11 element bodies are LE; only the suite selectors read as
     * OUI-then-selector). An earlier version of these fixtures wrote them big-endian —
     * the same mistake the parser made — so the tests proved the parser right about a
     * format that does not exist. A real capture of a live WPA3-transition AP is what
     * exposed it: every real RSN element looked "cut short" and the network was
     * reported as "key management unknown".
     */
    private fun rsnBody(
        akms: List<String>,
        pairwise: List<String> = listOf("000fac04"),
        group: String = "000fac04",
        cap: String = "0000",
    ): ByteArray = hexBytes(
        le16Hex(1) + group + le16Hex(pairwise.size) + pairwise.joinToString("") +
            le16Hex(akms.size) + akms.joinToString("") + cap
    )

    private fun le16Hex(v: Int) = "%02x%02x".format(v and 0xFF, (v ushr 8) and 0xFF)

    /**
     * A key-data element (KDE) as the handshake really carries it: element id 221,
     * OUI 00-0F-AC, one type byte, then the payload. The length is derived, so a
     * fixture cannot claim a length its bytes do not add up to.
     */
    private fun kde(type: Int, payload: ByteArray): ByteArray {
        val body = hexBytes("000fac%02x".format(type)) + payload
        return byteArrayOf(221.toByte(), body.size.toByte()) + body
    }

    /**
     * EAPOL-Key descriptor as IEEE 802.11 lays it out, offsets counted from the EAPOL
     * header start: version@0 type@1 body-length@2-3 descriptor-type@4 key-info@5-6
     * key-length@7-8 replay@9-16 Key IV@17-32 Key RSC@33-40 Key ID@41-48
     * KEY NONCE@49-80 Key MIC@81-96 key-data-length@97-98 key data@99.
     *
     * The Key IV / RSC / ID region is filled with a recognisable non-zero pattern on
     * purpose. The nonce is NOT at 17: reading it there produced 22000 lines whose
     * "ANonce" was the IV, and such a line can never be cracked, whatever the password.
     * Zero-filled fixtures hid that bug; a real capture of a live AP did not. If the
     * offset regresses, the ANonce assertions below pick it up immediately.
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
        for (i in 0 until 32) f[17 + i] = (0x40 + i).toByte() // Key IV + RSC + ID
        System.arraycopy(nonce, 0, f, 49, 32)
        if (mic != null) System.arraycopy(mic, 0, f, 81, 16)
        f[97] = (body.size ushr 8).toByte(); f[98] = body.size.toByte()
        System.arraycopy(body, 0, f, 99, body.size)
        return f
    }

    /** The recognisable IV/RSC/ID pattern [eapolKey] writes at 17..49. */
    private val ivRegionHex = (0 until 32).joinToString("") { "%02x".format(0x40 + it) }

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
        val ie = if (legacy) legacyPmkidKde(pmkid) else kde(6, pmkid)
        // M1 as a real AP sends it: version 2 bits + Install + Ack, MIC clear.
        return eapolKey(keyInfo = 0x008a, replay = 1, nonce = ByteArray(32), body = ie)
    }

    /**
     * WPA1-era vendor PMKID element (OUI 00-0E-90, subtype 4) in the form this parser
     * accepts: OUI, subtype, four bytes, a 0x0010 field, then the 16 PMKID bytes.
     *
     * UNVERIFIED against the air: no capture in this lab has ever carried this
     * element, and the RSN form above (00-0F-AC, type 6) is the one real captures
     * confirmed. This fixture pins the parser's current behaviour so a future change
     * is deliberate rather than accidental — it is NOT evidence about how a real
     * WPA1 access point writes the field.
     */
    private fun legacyPmkidKde(pmkid: ByteArray): ByteArray {
        require(pmkid.size == 16)
        return byteArrayOf(221.toByte(), (4 + 6 + 16).toByte()) +
            hexBytes("000e9004 01000000 0010") + pmkid
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
        assertEquals(1, rep.pairsNoSsid)
        assertTrue(rep.notes.any { it.contains("SSID is unknown") })
    }

    // ---- M1 + M2 handshake ---------------------------------------------------------

    private val anonce = hexBytes("581cbc35776079d2e2c4b7719fc77a77d8724a622d2b779a479d8a2dfd028c80")

    /**
     * Key data carried by a real M1/M2: the RSN information KDE — element 221 with
     * OUI 00-0F-AC and type 1, wrapping the RSN element (id 48) with its own id and
     * length, exactly as it appears on air.
     */
    private fun m1KeyData(akms: List<String> = listOf("000fac02")): ByteArray {
        val body = rsnBody(akms = akms)
        return kde(1, byteArrayOf(48, body.size.toByte()) + body)
    }

    private fun m2Body() = m1KeyData()

    @Test
    fun m1m2PairProducesHandshakeLineAndCorrectMic() {
        val password = "hashcat!"
        val snonce = ByteArray(32) { (it + 1).toByte() }

        val m1 = eapolKey(keyInfo = 0x0082, replay = 13, nonce = anonce, body = m1KeyData())
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
        assertEquals(0, h.messagePair)   // hcxtools MESSAGE_PAIR_M12E2
        assertEquals(2, h.keyver) // key_info version bits in M2 (WPA2-AES → CMAC)

        // The line must carry: mic, aa, spa, essid, anonce, full M2 frame, mp=00
        val parts = h.line.split("*")
        assertEquals("WPA", parts[0])
        assertEquals("02", parts[1])
        assertEquals(mic.joinToString("") { "%02x".format(it) }, parts[2])
        assertEquals(apMacHex, parts[3])
        assertEquals(staMacHex, parts[4])
        assertEquals(ssidHex, parts[5])
        assertEquals(hexOf(anonce), parts[6])
        // hcxtools convention: Key MIC field zeroed inside the stored eapol
        val m2Zeroed = m2.copyOf().also { java.util.Arrays.fill(it, 81, 97, 0) }
        assertEquals(hexOf(m2Zeroed), parts[7])
        assertEquals("00", parts[8])
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
        assertEquals(1, rep.pairsNoApMessage)
        assertTrue(rep.notes.any { it.contains("no matching AP message") })
    }

    // --- the M1/M3/M4 identification trap --------------------------------------
    //
    // M1 and M4 share the same key-info bits (Ack set, MIC clear). Taking an M4
    // for an M1 was the classic way to end up with a capture of 100+ EAPOL frames
    // that yields nothing crackable: the "ANonce" is a field of zeros.

    /** M4: Ack set, MIC clear, no nonce and no key data (it is a bare ACK). */
    private fun m4Frame(replay: Long): ByteArray =
        eapolKey(keyInfo = 0x0082, replay = replay, nonce = ByteArray(32), body = ByteArray(0))

    @Test
    fun m4IsNeverUsedAsTheApMessage() {
        val pcap = PcapBuilder()
        pcap.frame(beacon(ssid))
        // The ACK arrives first: an extractor that classifies by key-info bits alone
        // would store its zero nonce and use it as the AP nonce.
        pcap.frame(dataEapol(m4Frame(1), fcLo = 0x88, fcHi = 0x01, addr1 = apMac, addr2 = staMac, withFcs = true))
        pcap.frame(dataEapol(eapolKey(keyInfo = 0x0082, replay = 1, nonce = anonce, body = m1KeyData()),
            fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        val snonce = ByteArray(32) { (it + 7).toByte() }
        val m2 = eapolKey(keyInfo = 0x0102, replay = 1, nonce = snonce, body = m2Body(), mic = ByteArray(16))
        System.arraycopy(keyver2Mic(m2, "hashcat!", anonce, snonce), 0, m2, 81, 16)
        pcap.frame(dataEapol(m2, fcLo = 0x88, fcHi = 0x01, addr1 = apMac, addr2 = staMac, withFcs = true))

        val rep = run(pcap.bytes())
        assertEquals(1, rep.hashes.size)
        assertEquals(1, rep.m1Frames)
        assertEquals(1, rep.m4Frames)
        val parts = rep.hashes[0].line.split("*")
        assertEquals(hexOf(anonce), parts[6])            // the real ANonce, not zeros
        assertEquals("00", parts[8])                     // M1+M2
        assertTrue(CrackCore.parse(rep.hashes[0].line)!!.verify("hashcat!"))
    }

    @Test
    fun m2WithOnlyAnM4ExplainsWhyNothingIsCrackable() {
        val pcap = PcapBuilder()
        pcap.frame(beacon(ssid))
        pcap.frame(dataEapol(m4Frame(2), fcLo = 0x88, fcHi = 0x01, addr1 = apMac, addr2 = staMac, withFcs = true))
        pcap.frame(dataEapol(eapolKey(keyInfo = 0x0102, replay = 2, nonce = ByteArray(32), body = m2Body(),
            mic = ByteArray(16)), fcLo = 0x88, fcHi = 0x01, addr1 = apMac, addr2 = staMac, withFcs = true))

        val rep = run(pcap.bytes())
        assertEquals(0, rep.hashes.size)
        assertEquals(1, rep.m4Frames)
        assertTrue(rep.notes.any { it.contains("no matching AP message") })
        assertTrue(rep.notes.any { it.contains("M4") })
    }

    /**
     * When the AP's M1 never reached the capture but its M3 did, the ANonce is
     * still there (M3 carries it) and the M2's MIC verifies against it —
     * hcxtools' MESSAGE_PAIR_M32E2. This is what makes a lossy capture crackable.
     */
    @Test
    fun m3RescuesTheHandshakeWhenTheM1WasMissed() {
        val snonce = ByteArray(32) { (it + 3).toByte() }
        val m2 = eapolKey(keyInfo = 0x0102, replay = 1, nonce = snonce, body = m2Body(), mic = ByteArray(16))
        val mic = keyver2Mic(m2, "hashcat!", anonce, snonce)
        System.arraycopy(mic, 0, m2, 81, 16)
        // M3: Ack + MIC set, from the AP, carrying the same ANonce.
        val m3 = eapolKey(keyInfo = 0x0182, replay = 2, nonce = anonce, body = m1KeyData(), mic = ByteArray(16))

        val pcap = PcapBuilder()
        pcap.frame(beacon(ssid))
        pcap.frame(dataEapol(m2, fcLo = 0x88, fcHi = 0x01, addr1 = apMac, addr2 = staMac, withFcs = true))
        pcap.frame(dataEapol(m3, fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))

        val rep = run(pcap.bytes())
        assertEquals(1, rep.hashes.size)
        assertEquals(0, rep.m1Frames)
        assertEquals(1, rep.m3Frames)
        val h = rep.hashes[0]
        assertEquals(2, h.messagePair)                        // MESSAGE_PAIR_M32E2
        assertEquals(hexOf(anonce), h.line.split("*")[6])     // ANonce taken from the M3
        // Still the same credential: the cracker verifies the M2 MIC we stored.
        assertTrue(CrackCore.parse(h.line)!!.verify("hashcat!"))
    }

    // --- ESSID fallback and stream damage ---------------------------------------

    @Test
    fun scanListSsidRescuesCredentialWithoutBeacon() {
        val pcap = PcapBuilder()
        pcap.frame(dataEapol(pmkidM1(officialPmkid), fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        val rep = Extractor.extract(ByteArrayInputStream(pcap.bytes()), mapOf("fc:69:0c:15:82:64" to "hashcat-essid"))

        assertEquals(1, rep.hashes.size)
        assertEquals(1, rep.ssidFromScan)
        assertTrue(rep.hashes[0].line.contains(ssidHex))
        assertTrue(rep.notes.any { it.contains("scan list") })
    }

    /**
     * A chunk dropped in transit (the ring overflowing or the USB link losing a
     * capstream block) desyncs the pcap record stream. Everything after the hole
     * used to be lost; now the reader finds the next record the firmware could
     * have written and keeps going.
     */
    @Test
    fun resyncsAfterALostChunk() {
        val junkBytes = 137
        val pcap = PcapBuilder()
        pcap.frame(beacon(ssid))
        pcap.raw(ByteArray(junkBytes) { 0x41 })        // the hole a lost capstream block leaves
        // The credential that arrived after the hole is the one that matters: without a
        // resync the reader stops at the junk and never sees it.
        pcap.frame(dataEapol(pmkidM1(officialPmkid), fcLo = 0x88, fcHi = 0x02,
            addr1 = staMac, addr2 = apMac, withFcs = true))
        val rep = run(pcap.bytes())

        assertEquals(1, rep.hashes.size)                 // the post-gap credential survived
        assertEquals(1, rep.badRecords)
        assertTrue(rep.lostBytes >= junkBytes)
        assertTrue(rep.resyncs >= 1)
        assertTrue(rep.notes.any { it.contains("lost in transit") })
    }

    @Test
    fun chipPaddingAfterTheEapolIsTolerated() {
        val frame = dataEapol(pmkidM1(officialPmkid), fcLo = 0x88, fcHi = 0x02,
            addr1 = staMac, addr2 = apMac, withFcs = false) + byteArrayOf(0, 0)
        val pcap = PcapBuilder()
        pcap.frame(beacon(ssid))
        pcap.frame(frame)
        val rep = run(pcap.bytes())
        assertEquals(1, rep.hashes.size)
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

    // ---- end to end: capture bytes → 22000 line → recovered password -------------------
    //
    // This is the offline stand-in for a live capture (no radio, no deauth): the frames
    // are laid out exactly as the board writes them, and the credential is produced by
    // real PBKDF2/MIC maths over a known password. So the whole chain the app runs —
    // pcap → hashcat line → cracker recovers the password — is exercised end to end.
    // The SSID is a realistic one because it IS the PBKDF2 salt: a wrong salt is the
    // classic way a hash "never cracks" even with the right password.

    private val e2eSsid = "Nostromo".toByteArray(Charsets.UTF_8)
    private val e2ePass = "NostromoTest!23"

    private fun pmkFor(pass: String, salt: ByteArray): ByteArray =
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            .generateSecret(PBEKeySpec(pass.toCharArray(), salt, 4096, 256)).encoded

    private fun micOverKde100(m2: ByteArray, pass: String, salt: ByteArray, an: ByteArray, sn: ByteArray): ByteArray {
        val kde = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(pmkFor(pass, salt), "HmacSHA1")) }
            .doFinal(pairwiseKeyExpansion(an, sn)).copyOfRange(0, 16)
        return Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(kde, "HmacSHA1")) }.doFinal(m2)
            .copyOfRange(0, 16)
    }

    @Test
    fun capturedPcapYieldsAPmkidLineThatCracksToTheKnownPassword() {
        val pmkid = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(pmkFor(e2ePass, e2eSsid), "HmacSHA1")) }
            .doFinal("PMK Name".toByteArray(Charsets.ISO_8859_1) + apMac + staMac).copyOfRange(0, 16)

        val pcap = PcapBuilder()
        pcap.frame(beacon(e2eSsid))
        pcap.frame(dataEapol(pmkidM1(pmkid), fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        val rep = run(pcap.bytes())

        assertEquals(1, rep.hashes.size)
        val target = CrackCore.parse(rep.hashes[0].line)
        assertNotNull(target)
        assertEquals("Nostromo", target!!.essidText)
        assertTrue("the known password must recover this hash", target.verify(e2ePass))
        assertFalse("one character off must not match", target.verify("NostromoTest!24"))
        assertFalse("the right password under a different salt must not match",
            CrackCore.parse(rep.hashes[0].line.replace(hexOf(e2eSsid), hexOf("Nostromp".toByteArray())))!!.verify(e2ePass))
    }

    @Test
    fun capturedPcapYieldsAHandshakeLineThatCracksToTheKnownPassword() {
        val snonce = ByteArray(32) { (it + 3).toByte() }
        val m1 = eapolKey(keyInfo = 0x0082, replay = 21, nonce = anonce, body = m1KeyData())
        val m2 = eapolKey(keyInfo = 0x0102, replay = 22, nonce = snonce, body = m2Body(), mic = ByteArray(16))
        System.arraycopy(micOverKde100(m2, e2ePass, e2eSsid, anonce, snonce), 0, m2, 81, 16)

        val pcap = PcapBuilder()
        pcap.frame(beacon(e2eSsid))
        pcap.frame(dataEapol(m1, fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        pcap.frame(dataEapol(m2, fcLo = 0x88, fcHi = 0x01, addr1 = apMac, addr2 = staMac, withFcs = true))
        val rep = run(pcap.bytes())

        assertEquals(1, rep.hashes.size)
        val target = CrackCore.parse(rep.hashes[0].line)
        assertNotNull(target)
        assertEquals(HashKind.HANDSHAKE, target!!.kind)
        assertEquals("Nostromo", target.essidText)
        assertEquals(1, rep.pairs)
        assertTrue("the known password must recover this handshake", target.verify(e2ePass))
        assertFalse("a near miss must not match", target.verify("nostromoTest!23"))
    }

    @Test
    fun crackedTargetsExposeTheirMaterialToNativeEnginesInTlvForm() {
        // The native engines get the same pre-computed buffers CrackCore.verifyWithPmk
        // uses; if these buffers were wrong the native engines would silently report
        // "not found" for a password that really is correct.
        val pmkid = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(pmkFor(e2ePass, e2eSsid), "HmacSHA1")) }
            .doFinal("PMK Name".toByteArray(Charsets.ISO_8859_1) + apMac + staMac).copyOfRange(0, 16)
        val pcap = PcapBuilder()
        pcap.frame(beacon(e2eSsid))
        pcap.frame(dataEapol(pmkidM1(pmkid), fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        val line = run(pcap.bytes()).hashes[0].line

        val target = CrackCore.parse(line)!!
        val m = target.material()
        assertEquals(1, m.kind)
        assertArrayEquals(e2eSsid, m.salt)
        assertEquals(16, m.expected.size)
        // The tag to match is the PMKID itself, and the HMAC input over which it is
        // computed is "PMK Name" + AA + SPA — exactly the pair hashcat works with.
        assertArrayEquals(pmkid, m.expected)
        assertEquals("PMK Name", String(m.pmkidData, 0, 8, Charsets.ISO_8859_1))
        assertArrayEquals(apMac + staMac, m.pmkidData.copyOfRange(8, m.pmkidData.size))
        assertEquals(20, m.pmkidData.size)
        assertTrue(m.micMsgs.isEmpty())

        val blob = Material.write(listOf(m))
        assertEquals("MKMT", String(blob, 0, 4, Charsets.ISO_8859_1))
        assertEquals(2, blob[7].toInt())                       // version (big-endian u32)
        assertEquals(1, blob[11].toInt())                      // one target
        assertTrue(blob.size > 40)
    }

    /**
     * The native engines verify exactly what the Kotlin verifier verifies. A 22000
     * line can hold its supplicant nonce in either of two EAPOL layouts, so every
     * layout the parser considers plausible has to reach the native side: otherwise
     * the same hash cracks on one engine and comes back "not found" on the other.
     */
    @Test
    fun materialCarriesEveryNonceLayoutTheNativeEnginesMustTry() {
        val snonce = ByteArray(32) { (it + 5).toByte() }
        val m2 = eapolKey(keyInfo = 0x010a, replay = 4, nonce = snonce, body = m2Body(), mic = ByteArray(16))

        // A frame as it appears on air: the Key IV/RSC/ID region is empty on a CCMP
        // handshake, so the descriptor says where the nonce is — one thing to try.
        val air = m2.copyOf().also { java.util.Arrays.fill(it, 17, 49, 0) }
        // A frame where both regions hold bytes (a TKIP handshake carries a real Key
        // IV): the blob no longer says which layout produced it, so both must travel.
        val both = m2.copyOf()

        val airMaterial = CrackCore.parse(lineWithMic(air, anonce))!!.material()
        val bothMaterial = CrackCore.parse(lineWithMic(both, anonce))!!.material()
        assertEquals("a descriptor that says where the nonce is gives one set", 1, airMaterial.pkeSets.size)
        assertEquals("a descriptor that could be either layout gives both", 2, bothMaterial.pkeSets.size)
        assertArrayEquals("the standard placement is tried first in both cases",
            airMaterial.pkeSets[0].p100, bothMaterial.pkeSets[0].p100)
        assertTrue("the second set expands the other nonce placement",
            !bothMaterial.pkeSets[0].p100.contentEquals(bothMaterial.pkeSets[1].p100))
        assertEquals(airMaterial.micMsgs.size, bothMaterial.micMsgs.size)

        val blob = Material.write(listOf(airMaterial, bothMaterial))
        assertEquals(2, blob[11].toInt())
        assertTrue(blob.size > 200)
    }

    /** A 22000 handshake line carrying [eapol] as its stored blob, salted with the test SSID. */
    private fun lineWithMic(eapol: ByteArray, anonceField: ByteArray): String =
        "WPA*02*${"01".repeat(16)}*$apMacHex*$staMacHex*$ssidHex*${hexOf(anonceField)}*${hexOf(eapol)}*a2"

    // ---- byte helpers ------------------------------------------------------------

    private fun hexBytes(s: String): ByteArray {
        val clean = s.replace(" ", "")
        return ByteArray(clean.length / 2) {
            ((Character.digit(clean[it * 2], 16) shl 4) or Character.digit(clean[it * 2 + 1], 16)).toByte()
        }
    }

    private fun hexOf(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    // ---- JVM-crypto helpers used to cross-check extracted bytes -----------------------
    // hashcat 22000 keyver-2 semantics (OpenCL aux2): PMK = PBKDF2-HMAC-SHA1(pass, essid, 4096),
    // KDE = HMAC-SHA1(PMK, label||macs||nonces||0), MIC = HMAC-SHA1(KDE[0..16), EAPOL w/ zero MIC)[0..16).

    private fun pairwiseKeyExpansion(anonce: ByteArray, snonce: ByteArray): ByteArray {
        val (macLow, macHigh) = if (lexLessOrEqual(apMac, staMac)) Pair(apMac, staMac) else Pair(staMac, apMac)
        val (nonLow, nonHigh) = if (lexLessOrEqual(anonce, snonce)) Pair(anonce, snonce) else Pair(snonce, anonce)
        val pke = ByteArray(100) // byte 99 stays 0 (hashcat pads the 99-byte PKE to 100)
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

    private fun lexLessOrEqual(a: ByteArray, b: ByteArray): Boolean {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d < 0
        }
        return a.size <= b.size
    }

    private fun keyver2Mic(m2: ByteArray, password: String, anonce: ByteArray, snonce: ByteArray): ByteArray {
        val kde = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(pmkOf(password), "HmacSHA1")) }
            .doFinal(pairwiseKeyExpansion(anonce, snonce)).copyOfRange(0, 16)
        return Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(kde, "HmacSHA1")) }.doFinal(m2)
            .copyOfRange(0, 16)
    }

    // ---- key management: WPA2-PSK vs WPA3-SAE -----------------------------------------
    // A mode-22000 line only makes sense when the network derives its PMK with
    // PBKDF2(SSID, password). The extractor's job is to say which networks that is
    // true for, read from the network's own RSN element and its authentication
    // frames — never assumed from "it looked like a WPA2 handshake".

    /** Beacon whose RSN AKM list holds [suites] (each 4 bytes, hex, space-separated). */
    private fun beaconAkm(ssid: ByteArray, suites: String): ByteArray =
        beaconWithRsn(ssid, rsnBody(akms = suites.split(" ").filter { it.isNotBlank() }))

    /**
     * 802.11 Authentication frame: fixed body is algorithm(2) seq(2) status(2) at 24.
     * algorithm 3 = SAE (the WPA3 dragonfly commit/confirm); frame control byte 0xB0.
     */
    private fun authFrame(algorithm: Int, seq: Int, status: Int, addr1: ByteArray, addr2: ByteArray): ByteArray {
        val f = ByteArray(30)
        f[0] = 0xB0.toByte() // type management (0), subtype authentication (11) -> 11<<4
        System.arraycopy(addr1, 0, f, 4, 6)
        System.arraycopy(addr2, 0, f, 10, 6)
        System.arraycopy(addr2, 0, f, 16, 6)
        f[24] = algorithm.toByte(); f[25] = (algorithm ushr 8).toByte()
        f[26] = seq.toByte(); f[27] = (seq ushr 8).toByte()
        f[28] = status.toByte(); f[29] = (status ushr 8).toByte()
        return f
    }

    /** (Re)Association Request: fcLo 0x00, element list begins at 34. */
    private fun assocRequest(rsn: ByteArray, addr1: ByteArray, addr2: ByteArray): ByteArray {
        val ie = hexBytes("01 02 8c 12") + rsn // supported rates (len 2) then the RSN element
        val f = ByteArray(34 + ie.size)
        f[0] = 0x00
        System.arraycopy(addr1, 0, f, 4, 6)   // addr1 = the AP this request is addressed to
        System.arraycopy(addr2, 0, f, 10, 6)  // addr2 = the client
        System.arraycopy(addr1, 0, f, 16, 6)  // addr3 = BSSID
        System.arraycopy(ie, 0, f, 34, ie.size)
        return f
    }

    /** RSN element (id 48) whose AKM list holds [suites]; body = 16 bytes + 4 per suite. */
    private fun rsnElement(suites: String): ByteArray {
        val body = rsnBody(akms = suites.split(" ").filter { it.isNotBlank() })
        return byteArrayOf(48, body.size.toByte()) + body
    }

    @Test
    fun saeOnlyAkmIsReportedAsNotCrackable() {
        val pcap = PcapBuilder()
        pcap.frame(beaconAkm(ssid, "000fac08"))
        pcap.frame(dataEapol(pmkidM1(officialPmkid), fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        val rep = run(pcap.bytes())

        assertEquals(SecurityMode.SAE_ONLY, rep.networks.single().mode)
        assertEquals(listOf("SAE"), rep.networks.single().akmLabels)
        assertEquals(1, rep.hashes.size)
        assertEquals(SecurityMode.SAE_ONLY, rep.hashes[0].security)
        assertEquals(1, rep.saeOnlyHashes)
        assertTrue(rep.notes.any { it.contains("WPA3-SAE only") })
    }

    @Test
    fun pskAndSaeTogetherIsTransitionModeStillWorthAttacking() {
        val pcap = PcapBuilder()
        pcap.frame(beaconAkm(ssid, "000fac02 000fac08"))
        pcap.frame(dataEapol(pmkidM1(officialPmkid), fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        val rep = run(pcap.bytes())

        assertEquals(SecurityMode.MIXED_PSK_SAE, rep.networks.single().mode)
        assertEquals(SecurityMode.MIXED_PSK_SAE, rep.hashes[0].security)
        assertEquals(0, rep.saeOnlyHashes)
        assertTrue(rep.notes.none { it.contains("WPA3-SAE only") })
    }

    @Test
    fun ftPskNetworkIsStillPskNotSae() {
        // WPA*03/04 (FT / OKC) records are a roaming artefact, not WPA3: the AKM
        // list here says FT-PSK, so mode 22000 applies.
        val pcap = PcapBuilder()
        pcap.frame(beaconAkm(ssid, "000fac04"))
        pcap.frame(dataEapol(pmkidM1(officialPmkid), fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        val rep = run(pcap.bytes())
        assertEquals(SecurityMode.PSK, rep.networks.single().mode)
        assertEquals(SecurityMode.PSK, rep.hashes[0].security)
    }

    @Test
    fun saeAuthFramesAreCountedAndAttributedToTheAp() {
        val commit = authFrame(algorithm = 3, seq = 1, status = 0, addr1 = apMac, addr2 = staMac)
        val confirm = authFrame(algorithm = 3, seq = 2, status = 0, addr1 = staMac, addr2 = apMac)
        val pcap = PcapBuilder()
        pcap.frame(beaconAkm(ssid, "000fac08"))
        pcap.frame(commit)
        pcap.frame(confirm)
        pcap.frame(authFrame(algorithm = 0, seq = 1, status = 0, addr1 = apMac, addr2 = staMac)) // open system: not SAE
        val rep = run(pcap.bytes())

        assertEquals(2, rep.saeAuthFrames)
        val net = rep.networks.first { it.bssid == "fc:69:0c:15:82:64" }
        assertEquals(2, net.saeAuthFrames)
        assertEquals(SecurityMode.SAE_ONLY, net.mode)
        assertTrue(rep.notes.any { it.contains("SAE authentication frame") })
    }

    @Test
    fun saeExchangeWithoutAnyRsnElementStillMarksTheNetworkSae() {
        // No beacon at all: the dragonfly exchange on air is the only evidence, and
        // "SAE seen" must not be silently reported as unknown/WPA2.
        val pcap = PcapBuilder()
        pcap.frame(authFrame(algorithm = 3, seq = 1, status = 0, addr1 = apMac, addr2 = staMac))
        val rep = run(pcap.bytes())
        assertEquals(1, rep.saeAuthFrames)
        val net = rep.networks.first { it.saeAuthFrames > 0 }
        assertEquals(SecurityMode.SAE_ONLY, net.mode)
        assertEquals(1, net.saeAuthFrames)
    }

    @Test
    fun implausibleSaeFrameIsCountedButNotAttributed() {
        // seq 0 is not a valid SAE transaction sequence: attributing it would put
        // the frames under the wrong endpoint.
        val pcap = PcapBuilder()
        pcap.frame(authFrame(algorithm = 3, seq = 0, status = 0, addr1 = apMac, addr2 = staMac))
        val rep = run(pcap.bytes())
        assertEquals(1, rep.saeAuthFrames)
        assertTrue(rep.networks.none { it.saeAuthFrames > 0 })
        assertTrue(rep.notes.any { it.contains("could not be attributed") })
    }

    @Test
    fun associationRequestAkmListDecidesTheModeWhenNoBeaconWasCaptured() {
        val pcap = PcapBuilder()
        pcap.frame(assocRequest(rsnElement("000fac08"), addr1 = apMac, addr2 = staMac))
        val rep = run(pcap.bytes())
        val net = rep.networks.first { it.bssid == "fc:69:0c:15:82:64" }
        assertEquals(SecurityMode.SAE_ONLY, net.mode)
        assertEquals(listOf("SAE"), net.akmLabels)
        assertEquals("(no beacon in capture)", net.essid)
    }

    @Test
    fun enterpriseAkmIsSeparatedFromPersonalNetworks() {
        val pcap = PcapBuilder()
        pcap.frame(beaconAkm(ssid, "000fac01"))
        val rep = run(pcap.bytes())
        assertEquals(SecurityMode.ENTERPRISE, rep.networks.single().mode)
    }

    // --- pinned to real captured bytes ------------------------------------------
    //
    // Everything above is generated. These two cases are transcribed from a capture
    // this lab actually made with the Marauder board, because generated fixtures only
    // ever prove the assumptions they were written from. Both bugs found on the real
    // capture (RSN counts big-endian, ANonce read out of the Key IV field) failed to
    // show up in the generated tests, and both made real 22000 lines uncrackable.

    /**
     * RSN element copied verbatim from a live access point's beacon
     * (a WPA3-SAE transition network: PSK + FT-PSK + SAE + FT-SAE, PMF capable).
     * Only the MACs and the SSID are the test's own, so no real network identifier
     * ends up in the repository.
     */
    private val realRsnElement = hexBytes(
        "30 20 01 00 00 0f ac 04 01 00 00 0f ac 04 04 00 00 0f ac 02 00 0f ac 04 00 0f ac 08 00 0f ac 09 80 00"
    )

    @Test
    fun rsnCountsAreLittleEndianSoARealTransitionApIsNotReportedUnknown() {
        // Version 01 00, one pairwise suite (01 00), four AKMs (04 00), then PMF
        // capability 80 00 — all little-endian, as the AP really writes them.
        val rsnBody = realRsnElement.copyOfRange(2, realRsnElement.size)
        val pcap = PcapBuilder()
        pcap.frame(beaconWithRsn(ssid, rsnBody))
        pcap.frame(dataEapol(pmkidM1(officialPmkid), fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        val rep = run(pcap.bytes())

        val net = rep.networks.single()
        assertEquals(SecurityMode.MIXED_PSK_SAE, net.mode)
        assertEquals(listOf("PSK", "FT-PSK", "SAE", "FT-SAE"), net.akmLabels)
        // Transition mode means the PSK side is still there, so the hash is worth cracking.
        assertEquals(SecurityMode.MIXED_PSK_SAE, rep.hashes[0].security)
        assertEquals(0, rep.saeOnlyHashes)
        assertTrue(rep.notes.none { it.contains("cut short") })
    }

    @Test
    fun theAnonceComesFromTheNonceFieldNeverFromTheKeyIv() {
        // A real M1: Key IV/RSC/ID are filled with random bytes at 17..49, and the
        // ANonce sits at 49..81. An extractor reading 17..49 produces a line whose
        // ANonce is that IV — which hashes to a different PMK every time, so the
        // correct password never works and nothing explains why.
        val m1 = eapolKey(keyInfo = 0x008a, replay = 7, nonce = anonce, body = m1KeyData())
        val snonce = ByteArray(32) { (it + 11).toByte() }
        val m2 = eapolKey(keyInfo = 0x010a, replay = 8, nonce = snonce, body = m2Body(), mic = ByteArray(16))
        System.arraycopy(keyver2Mic(m2, "hashcat!", anonce, snonce), 0, m2, 81, 16)

        val pcap = PcapBuilder()
        pcap.frame(beacon(ssid))
        pcap.frame(dataEapol(m1, fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true))
        pcap.frame(dataEapol(m2, fcLo = 0x88, fcHi = 0x01, addr1 = apMac, addr2 = staMac, withFcs = true))
        val rep = run(pcap.bytes())

        val parts = rep.hashes[0].line.split("*")
        assertEquals(hexOf(anonce), parts[6])
        assertTrue("the ANonce must not be the Key IV region", parts[6] != ivRegionHex.take(64))
        // The stored M2 must keep the IV/RSC/ID region where the standard puts it.
        assertTrue(parts[7].startsWith("010300"))
        assertEquals(ivRegionHex, parts[7].substring(34, 34 + 64))
        assertTrue("and the credential still recovers", CrackCore.parse(rep.hashes[0].line)!!.verify("hashcat!"))
    }

    /**
     * What a live capture of the board's own injected frames looks like: Ack set, MIC
     * clear, a random Key IV, an empty KEY NONCE field and no key data. Such frames
     * outnumber the real handshake in the capture, and calling them M1 is how a
     * 144-EAPOL capture ends up with nothing usable in it.
     */
    @Test
    fun framesWithAnIvButNoNonceAreAcknowledgementsNotM1() {
        val forged = eapolKey(keyInfo = 0x008a, replay = 1, nonce = ByteArray(32), body = ByteArray(0))
        val pcap = PcapBuilder()
        pcap.frame(beacon(ssid))
        repeat(4) { pcap.frame(dataEapol(forged, fcLo = 0x88, fcHi = 0x02, addr1 = staMac, addr2 = apMac, withFcs = true)) }
        val rep = run(pcap.bytes())

        assertEquals(0, rep.m1Frames)
        assertEquals(4, rep.m4Frames)
        assertTrue(rep.notes.any { it.contains("M4") })
    }
}
