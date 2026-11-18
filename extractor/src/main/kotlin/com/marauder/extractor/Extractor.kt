package com.marauder.extractor

import java.io.File
import java.io.InputStream

/**
 * pcap → hashcat-22000 extractor for captures written by ESP32 Marauder.
 *
 * The byte-level facts below were verified against the Marauder v1.20
 * firmware source (see docs/SPEC-M2-extractor.md) and the serialized line
 * format against hashcat v6.2.6 `module_22000.c`:
 *  - payloads are bare 802.11 frames (linktype 105), no radiotap;
 *  - DATA frames carry a trailing FCS, MGMT frames do not (auto-detected);
 *  - PMKID credential: `WPA*01*<pmkid>*<aa>*<spa>*<essid-hex>***`;
 *  - M1+M2 credential:  `WPA*02*<mic>*<aa>*<spa>*<essid-hex>*<anonce>*<m2 hex>*<mp>`.
 *
 * Pure parsing: no crypto here — the cracker verifies. Truncated / gapped
 * streams (the realistic case over USB serial) must not throw: parse what
 * fits, note the rest.
 */
object Extractor {

    private const val MAGIC_US_BE: Int = 0xA1B2C3D4.toInt() // bytes on disk A1 B2 C3 D4 → file is big-endian
    private const val MAGIC_NS_BE: Int = 0xA1B23C4D.toInt()
    private const val MAX_RECORD: Int = 262_144

    fun extract(pcap: File): ExtractReport = pcap.inputStream().use { extract(it) }

    fun extract(input: InputStream): ExtractReport {
        val notes = mutableListOf<String>()
        val records = readAllRecords(input, notes)

        val essids = HashMap<String, ByteArray>()     // bssid → raw SSID bytes
        val keyverHint = HashMap<String, Int>()       // bssid → keyver guessed from RSN IE
        val m1 = HashMap<String, M1Record>()          // "aa|spa" → first M1
        val pmkids = LinkedHashMap<String, PmkidHit>()// pmkid hex → hit (dedup)
        val handshakes = LinkedHashMap<String, HandshakeHit>() // "aa|spa" → first complete pair

        var parsed = 0
        var eapolFrames = 0
        var beaconFrames = 0

        for (frame in records) {
            parsed++
            val b = frame.bytes
            if (b.size < 10) continue
            // 802.11 frame control (LE 16-bit): version@0-1, type@2-3, subtype@4-7,
            // ToDS@8, FromDS@9.
            val fcLo = b[0].toInt() and 0xFF
            val fcHi = if (b.size > 1) b[1].toInt() and 0xFF else 0
            val type = (fcLo ushr 2) and 0x03
            val subtype = (fcLo ushr 4) and 0x0F
            val toDs = (fcHi and 0x01) != 0
            val fromDs = (fcHi and 0x02) != 0

            when (type) {
                0x00 -> { // management
                    if (subtype == 0x08 || subtype == 0x05) { // Beacon / Probe Response
                        if (b.size >= 36) {
                            beaconFrames++
                            val bssid = mac(b, 10)
                            val ieStart = 36
                            val ssid = ieSsid(b, ieStart)
                            if (ssid != null) essids.putIfAbsent(bssid, ssid)
                            val kv = rsnKeyver(b, ieStart)
                            if (kv != 0) keyverHint.putIfAbsent(bssid, kv)
                        }
                    }
                }

                0x02 -> { // data (QoS data subtypes 0x8/0xC share the base layout)
                    val eapol = eapolFromBody(b) ?: continue
                    eapolFrames++

                    if (toDs && fromDs) continue // 4-address / WDS: out of scope for personal WPA2
                    // 802.11 addresses: addr1 @4, addr2 @10, addr3 @16.
                    // M1 (AP→client, FromDS): addr1=spa, addr2=aa(=BSSID).
                    // M2 (client→AP, ToDS):   addr1=aa(=BSSID), addr2=spa.
                    val aa: String
                    val spa: String
                    if (fromDs) { aa = mac(b, 10); spa = mac(b, 4) }
                    else { aa = mac(b, 4); spa = mac(b, 10) }
                    if (aa == spa) continue

                    val keyInfo = be16(eapol, 5)
                    val ack = (keyInfo and 0x0080) != 0
                    val mic = (keyInfo and 0x0100) != 0
                    val keyver = keyInfo and 0x0007

                    // PMKID may ride in M1 (or, on some firmwares, M2) key data.
                    if (ack || mic) {
                        val pmkid = findPmkid(eapol)
                        if (pmkid != null) {
                            val hex = hex(pmkid)
                            pmkids.putIfAbsent(hex, PmkidHit(aa, spa, hex, keyverHint[aa] ?: defaultKeyver(keyver)))
                        }
                    }

                    if (ack && !mic) {
                        if (eapol.size >= 49) m1.putIfAbsent("$aa|$spa", M1Record(eapol.copyOfRange(17, 49), be64(eapol, 9), keyver))
                    } else if (!ack && mic) {
                        val first = m1["$aa|$spa"]
                        if (first == null) {
                            notes += "EAPOL M2 from $spa to $aa seen without its M1 — no AP nonce, pair not usable"
                        } else if (eapol.size >= 97) {
                            handshakes.putIfAbsent("$aa|$spa", HandshakeHit(aa, spa, first.nonce, eapol, eapol.copyOfRange(81, 97), first.keyver))
                        }
                    }
                }
            }
        }

        // Assemble the hashcat lines. A PBKDF2 salt (the raw SSID) is mandatory:
        // without a beacon we cannot build a line that any cracker could verify.
        val out = mutableListOf<ExtractedHash>()
        for ((pmkidHex, hit) in pmkids) {
            val ssid = essids[hit.aa]
            if (ssid == null) {
                notes += "PMKID for ${hit.aa}: no beacon seen — SSID unknown, cannot build a crackable hash"
                continue
            }
            val hashLine = "WPA*01*${pmkidHex}*${hit.aa.replace(":", "")}*${hit.spa.replace(":", "")}*${hex(ssid)}***"
            out += ExtractedHash(
                kind = HashKind.PMKID,
                essid = essidLabel(ssid),
                bssid = hit.aa,
                sta = hit.spa,
                messagePair = 255,
                keyver = hit.keyver,
                micLenBytes = 16,
            ).apply { line = hashLine }
        }
        for ((_, hit) in handshakes) {
            val ssid = essids[hit.aa]
            if (ssid == null) {
                notes += "handshake ${hit.aa} ↔ ${hit.spa}: no beacon seen — SSID unknown, cannot build a crackable hash"
                continue
            }
            val mp = 2 // M1+M2, AP side (the pairing we actually did)
            val hashLine = "WPA*02*${hex(hit.mic)}*${hit.aa.replace(":", "")}*${hit.spa.replace(":", "")}*" +
                "${hex(ssid)}*${hex(hit.anonce)}*${hex(hit.m2)}*%02x".format(mp)
            val keyver = keyVerFromEapol(hit.m2)
            out += ExtractedHash(
                kind = HashKind.HANDSHAKE,
                essid = essidLabel(ssid),
                bssid = hit.aa,
                sta = hit.spa,
                messagePair = mp,
                keyver = keyver,
                micLenBytes = 16,
            ).apply { line = hashLine }
        }

        return ExtractReport(
            hashes = out,
            recordsParsed = parsed,
            eapolFrames = eapolFrames,
            beacons = beaconFrames,
            notes = notes,
        )
    }

    // --- 802.11 / EAPOL helpers ------------------------------------------------

    /** EAPOL frame for a 802.11 DATA frame, LLC/SNAP stripped, FCS auto-trimmed. */
    private fun eapolFromBody(b: ByteArray): ByteArray? {
        if (b.size < 30) return null
        val fcLo = b[0].toInt() and 0xFF
        val fcHi = if (b.size > 1) b[1].toInt() and 0xFF else 0
        val subtype = (fcLo ushr 4) and 0x0F
        var off = 24 // fc2 + dur2 + 3×mac6 + seqctl2
        if (subtype and 0x08 != 0) off += 2                       // QoS control field
        val toDs = (fcHi and 0x01) != 0
        val fromDs = (fcHi and 0x02) != 0
        if (toDs && fromDs) off += 6                             // 4th address
        if (off + 8 > b.size) return null
        // RFC1042 LLC/SNAP: AA AA 03 00 00 00 <ethertype 88 8E>
        if (!(b[off] == 0xAA.toByte() && b[off + 1] == 0xAA.toByte() && b[off + 2] == 0x03.toByte() &&
                b[off + 6] == 0x88.toByte() && b[off + 7] == 0x8E.toByte())
        ) return null
        val eapolStart = off + 8
        if (eapolStart + 4 > b.size) return null
        val eapolTotal = 4 + be16(b, eapolStart + 2)
        if (eapolTotal < 4 || eapolStart + eapolTotal > b.size) return null
        val rest = b.size - (eapolStart + eapolTotal)
        if (rest != 0 && rest != 4) return null                  // neither "no FCS" nor "FCS present"
        return b.copyOfRange(eapolStart, eapolStart + eapolTotal)
    }

    private fun be16(b: ByteArray, at: Int): Int =
        ((b[at].toInt() and 0xFF) shl 8) or (b[at + 1].toInt() and 0xFF)

    private fun be64(b: ByteArray, at: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (b[at + i].toLong() and 0xFF)
        return v
    }

    private fun mac(b: ByteArray, at: Int): String =
        (0 until 6).joinToString(":") { "%02x".format(b[at + it].toInt() and 0xFF) }

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private fun ieSsid(b: ByteArray, ieStart: Int): ByteArray? {
        var i = ieStart
        while (i + 1 < b.size) {
            val id = b[i].toInt() and 0xFF
            val len = b[i + 1].toInt() and 0xFF
            if (i + 2 + len > b.size) return null
            if (id == 0) return b.copyOfRange(i + 2, i + 2 + len)
            i += 2 + len
        }
        return null
    }

    /** 1 = WPA-TKIP style MIC, 2 = WPA2-AES/CMAC; 0 when no RSN/WPA IE matches. */
    private fun rsnKeyver(b: ByteArray, ieStart: Int): Int {
        var i = ieStart
        while (i + 1 < b.size) {
            val id = b[i].toInt() and 0xFF
            val len = b[i + 1].toInt() and 0xFF
            if (i + 2 + len > b.size) break
            val body = hex(b, i + 2, len)
            if (id == 48) {
                return when {
                    body.contains("000fac02") -> if (body.contains("000fac04")) 2 else 1
                    body.contains("000fac") -> 2
                    else -> 0
                }
            }
            if (id == 221 && len >= 4 && body.startsWith("0050f202")) return 1 // legacy WPA IE
            i += 2 + len
        }
        return 0
    }

    private fun hex(b: ByteArray, at: Int, len: Int): String {
        val sb = StringBuilder(len * 2)
        for (i in at until at + len) sb.append("%02x".format(b[i].toInt() and 0xFF))
        return sb.toString()
    }

    /**
     * PMKID inside the EAPOL-Key frame. Two real-world encodings are accepted:
     *  - modern (802.11-2016): key-data vendor element `dd <len> 00-0f-ac 06 <pmkid:16>`;
     *  - legacy (Broadcom/older chipsets, seen in hcxtools and the SPEC-M2
     *    firmware notes): `dd <len> 00-0e-90 04 <keyidx:4> 00-10 <pmkid:16>`.
     */
    private fun findPmkid(eapol: ByteArray): ByteArray? {
        if (eapol.size < 99) return null
        val dataLen = be16(eapol, 97)
        val dataStart = 99
        val dataEnd = minOf(eapol.size, dataStart + dataLen)
        if (dataEnd <= dataStart) return null
        val d = eapol
        var i = dataStart
        while (i + 6 <= dataEnd) {
            if (d[i] == 0x00.toByte() && d[i + 1] == 0x0F.toByte() &&
                d[i + 2] == 0xAC.toByte() && d[i + 3] == 0x06.toByte() &&
                i + 20 <= dataEnd
            ) {
                return d.copyOfRange(i + 4, i + 20)
            }
            if (d[i] == 0x00.toByte() && d[i + 1] == 0x0E.toByte() &&
                d[i + 2] == 0x90.toByte() && d[i + 3] == 0x04.toByte() &&
                i + 26 <= dataEnd &&
                d[i + 8] == 0x00.toByte() && d[i + 9] == 0x10.toByte()
            ) {
                return d.copyOfRange(i + 10, i + 26)
            }
            i++
        }
        return null
    }

    private fun keyVerFromEapol(m2: ByteArray): Int {
        if (m2.size < 6) return 0
        return when (val v = be16(m2, 5) and 0x0007) { 1, 2, 3 -> v; else -> 2 }
    }

    private fun defaultKeyver(eapolVer: Int): Int =
        if (eapolVer in 1..3) eapolVer else 2

    private fun essidLabel(ssid: ByteArray): String {
        val printable = String(ssid, Charsets.UTF_8)
        return if (printable.all { it.code in 32..126 || it.code in 0xC0..0x2AF }) printable
        else hex(ssid)
    }

    // --- pcap reader -------------------------------------------------------------

    private data class Frame(val bytes: ByteArray)

    private fun readAllRecords(input: InputStream, notes: MutableList<String>): List<Frame> {
        val gh = readExact(input, 24)
            ?: run { notes += "empty or unreadable pcap header"; return emptyList() }
        val m32 = be32(gh, 0)
        val bigEndian = when (m32) {
            MAGIC_US_BE, MAGIC_NS_BE -> true
            0xD4C3B2A1.toInt(), 0x4D3CB2A1.toInt() -> false // the common (native-LE) case
            else -> {
                notes += "not a libpcap file (magic %08x)".format(m32)
                return emptyList()
            }
        }
        val linktype = if (bigEndian) be32(gh, 20) else le32(gh, 20)
        if (linktype != 105) notes += "linktype $linktype (expected 105 — 802.11 without radiotap); parsing anyway"

        val frames = mutableListOf<Frame>()
        while (true) {
            val rh = readExact(input, 16) ?: break
            val incl = if (bigEndian) be32(rh, 8) else le32(rh, 8)
            if (incl <= 0 || incl > MAX_RECORD) {
                notes += "bad record length $incl — stream stopped here"
                break
            }
            val payload = readExact(input, incl)
            if (payload == null) {
                notes += "capture truncated mid-record (kept ${frames.size} complete frames)"
                break
            }
            frames += Frame(payload)
        }
        return frames
    }

    private fun readExact(input: InputStream, n: Int): ByteArray? {
        val buf = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = try { input.read(buf, off, n - off) } catch (e: Exception) { return null }
            if (r < 0) return null
            off += r
        }
        return buf
    }

    private fun be32(b: ByteArray, at: Int): Int =
        ((b[at].toInt() and 0xFF) shl 24) or ((b[at + 1].toInt() and 0xFF) shl 16) or
            ((b[at + 2].toInt() and 0xFF) shl 8) or (b[at + 3].toInt() and 0xFF)

    private fun le32(b: ByteArray, at: Int): Int =
        (b[at].toInt() and 0xFF) or ((b[at + 1].toInt() and 0xFF) shl 8) or
            ((b[at + 2].toInt() and 0xFF) shl 16) or ((b[at + 3].toInt() and 0xFF) shl 24)

    // --- internal match types -----------------------------------------------------

    private class M1Record(val nonce: ByteArray, val replay: Long, val keyver: Int)
    private class PmkidHit(val aa: String, val spa: String, val pmkidHex: String, val keyver: Int)
    private class HandshakeHit(
        val aa: String,
        val spa: String,
        val anonce: ByteArray,
        val m2: ByteArray,
        val mic: ByteArray,
        val keyver: Int,
    )
}
