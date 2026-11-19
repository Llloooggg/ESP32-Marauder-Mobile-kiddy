package com.marauder.extractor

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream

/**
 * pcap → hashcat-22000 extractor for captures written by ESP32 Marauder.
 *
 * Byte-level facts, verified against the firmware source and hashcat/hcxtools:
 *  - payloads are bare 802.11 frames (linktype 105), no radiotap;
 *  - the firmware writes each record as `{ts_sec, ts_usec, len, len}` little
 *    endian with `ts_usec < 1_000_000` and `incl_len == orig_len`
 *    (Buffer.cpp `add()`), which is what lets [readAllRecords] find the frame
 *    stream again after USB transport loss;
 *  - DATA frames may or may not carry a trailing FCS, and the ESP32 pads short
 *    frames, so the EAPOL length field decides the slice, not the record size;
 *  - message pairs follow hcxtools (`hashcatops.h`): 0 = M1+M2 (M2 stored),
 *    2 = M3+M2 (M2 stored, ANonce from M3).
 *
 * The 4-way handshake's key-info bits do NOT identify the messages on their
 * own: M1 and M4 both have Ack=1/MIC=0. Storing an M4 as if it were the M1 is
 * the classic way to end up with a capture full of EAPOL and nothing crackable,
 * so the classification here also requires a non-zero nonce and key data
 * (M4 has neither) and pairs on the replay counter (M1/M2 share one, M3/M4 the
 * next).
 *
 * Pure parsing: no crypto here — the cracker verifies. A gapped or truncated
 * stream must never throw: parse what is parseable and report the rest as
 * counters the UI can show.
 */
object Extractor {

    private const val MAGIC_US_BE: Int = 0xA1B2C3D4.toInt() // bytes on disk A1 B2 C3 D4 → file is big-endian
    private const val MAGIC_NS_BE: Int = 0xA1B23C4D.toInt()
    private const val MAX_RECORD: Int = 262_144

    /**
     * AKM suite ids, grouped by what mode-22000 can do with them. Values follow the
     * IEEE registry (the same numbering hcxtools' `AK_*`/`TAK_*` constants derive
     * from): PSK-family suites derive the PMK with PBKDF2(SSID, password), which is
     * exactly what mode 22000 tests; the SAE family derives it from the dragonfly
     * exchange, so a captured SAE handshake is not a password hash at all. Both the
     * old (11/12) and current (22/23) numbering of SAE-SHA384 are covered.
     */
    private val PSK_AKMS = setOf(2, 4, 6, 7, 20, 24)
    private val SAE_AKMS = setOf(8, 9, 11, 12, 22, 23)
    private val ENTERPRISE_AKMS = setOf(1, 3, 5, 10, 13, 14, 15, 25)
    private val OWE_AKMS = setOf(18, 19)

    /** Cap for reading the capture into memory (the resync pass needs random access). */
    private const val MAX_FILE: Int = 64 * 1024 * 1024

    fun extract(pcap: File, knownEssids: Map<String, String> = emptyMap()): ExtractReport =
        pcap.inputStream().use { extract(it, knownEssids) }

    fun extract(input: InputStream, knownEssids: Map<String, String> = emptyMap()): ExtractReport {
        val stats = Stats()
        val data = readAll(input)
        if (data == null) {
            return ExtractReport(
                hashes = emptyList(), recordsParsed = 0, eapolFrames = 0, beacons = 0,
                notes = listOf("capture too large to read (limit ${MAX_FILE / 1024 / 1024} MB)"),
            )
        }
        val records = readAllRecords(data, stats)

        val essids = HashMap<String, ByteArray>()     // bssid → raw SSID bytes (from beacons)
        val keyverHint = HashMap<String, Int>()       // bssid → keyver guessed from RSN IE
        val akms = HashMap<String, MutableSet<Int>>() // bssid → AKM suite ids it advertised
        val saeSeen = HashMap<String, Int>()          // bssid → SAE auth frames attributed to it
        val m1s = HashMap<String, MutableList<KeyFrame>>()   // "aa|spa" → M1 candidates
        val m3s = HashMap<String, MutableList<KeyFrame>>()   // "aa|spa" → M3 candidates (ANonce source)
        val m2s = HashMap<String, MutableList<KeyFrame>>()   // "aa|spa" → M2 candidates (MIC + SNonce)
        val pmkids = LinkedHashMap<String, PmkidHit>()// pmkid hex → hit (dedup)

        for (frame in records) {
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
                            stats.beacons++
                            val bssid = mac(b, 10)
                            val ieStart = 36
                            val ssid = ieSsid(b, ieStart)
                            if (ssid != null) essids.putIfAbsent(bssid, ssid)
                            val kv = rsnKeyver(b, ieStart)
                            if (kv != 0) keyverHint.putIfAbsent(bssid, kv)
                            addAkm(akms, bssid, akmSuites(b, ieStart, stats))
                        }
                    } else if (subtype == 0x00 || subtype == 0x02) { // Association / Reassociation Request
                        // The client's RSN element names the AKM the pair actually
                        // negotiates, which a beacon alone cannot tell us. Body layout:
                        // capability(2) listen(2) current AP(6) [+interval(4) if reassoc],
                        // so the element list begins at 34 / 38.
                        val ieStart = if (subtype == 0x02) 38 else 34
                        if (b.size >= ieStart + 2) {
                            addAkm(akms, mac(b, 4), akmSuites(b, ieStart, stats))
                        }
                    } else if (subtype == 0x0B) { // Authentication
                        saeAuthentication(b, saeSeen, stats)
                    }
                }

                0x02 -> { // data (QoS data subtypes 0x8/0xC share the base layout)
                    stats.dataLikeFrames++
                    val eapol = eapolFromBody(b, stats) ?: continue
                    stats.eapolFrames++

                    if (toDs && fromDs) { stats.wdsFrames++; continue } // 4-address / WDS
                    // 802.11 addresses: addr1 @4, addr2 @10, addr3 @16.
                    // M1/M3 (AP→client, FromDS): addr1=spa, addr2=aa(=BSSID).
                    // M2/M4 (client→AP, ToDS):   addr1=aa(=BSSID), addr2=spa.
                    val aa: String
                    val spa: String
                    if (fromDs) { aa = mac(b, 10); spa = mac(b, 4) }
                    else { aa = mac(b, 4); spa = mac(b, 10) }
                    if (aa == spa) { stats.selfFrames++; continue }

                    if (eapol.size < 97) { stats.shortEapol++; continue }
                    val keyInfo = be16(eapol, 5)
                    val ack = (keyInfo and 0x0080) != 0
                    val mic = (keyInfo and 0x0100) != 0
                    val keyver = keyInfo and 0x0007
                    // EAPOL-Key descriptor layout (IEEE 802.11, WPA descriptor type 2),
                    // offsets from the EAPOL header start:
                    //   0 ver, 1 type, 2-3 body length, 4 descriptor type, 5-6 key info,
                    //   7-8 key length, 9-16 replay, 17-32 key IV, 33-40 key RSC,
                    //   41-48 key ID, 49-80 KEY NONCE, 81-96 key MIC, 97-98 key data len.
                    // The nonce is NOT at 17: that region is the key IV (random, so it
                    // looked plausible) plus RSC/ID. Reading it there produced 22000 lines
                    // carrying an IV instead of the ANonce — such a line can never crack,
                    // no matter the password. Real captures proved this; the synthetic
                    // fixtures had been laying the nonce out where the code read it.
                    val nonce = eapol.copyOfRange(49, 81)
                    val replay = be64(eapol, 9)
                    val keyDataLen = be16(eapol, 97)

                    // A PMKID rides in the M1 key data (rarely in an M2).
                    val pmkid = findPmkid(eapol)
                    if (pmkid != null) {
                        stats.pmkidFrames++
                        val hex = hex(pmkid)
                        pmkids.putIfAbsent(
                            hex,
                            PmkidHit(aa, spa, hex, keyverHint[aa] ?: defaultKeyver(keyver)),
                        )
                    }

                    val key = "$aa|$spa"
                    val kf = KeyFrame(aa, spa, eapol, nonce, replay, keyver, keyDataLen, mic, ack)
                    when {
                        // M2: MIC set, Ack clear → carries the SNonce and the MIC we verify.
                        !ack && mic -> {
                            stats.m2Frames++
                            m2s.getOrPut(key) { ArrayList(4) }.add(kf)
                        }
                        // M3: MIC set, Ack set, from the AP → carries the ANonce.
                        ack && mic -> {
                            stats.m3Frames++
                            if (nonce.any { it != 0.toByte() }) m3s.getOrPut(key) { ArrayList(4) }.add(kf)
                        }
                        // Ack set, MIC clear: M1 (has nonce + key data) or M4 (has neither).
                        else -> {
                            val hasNonce = nonce.any { it != 0.toByte() }
                            if (hasNonce && keyDataLen > 0) {
                                stats.m1Frames++
                                m1s.getOrPut(key) { ArrayList(4) }.add(kf)
                            } else {
                                stats.m4Frames++   // pure ACK: no key material to use
                            }
                        }
                    }
                }
            }
        }

        val pairs = pickPairs(m1s, m2s, m3s, stats)

        // What each network claimed about its key management, decided before the
        // hashes are assembled: a line taken from an SAE-only network cannot be
        // cracked by mode 22000 and saying so now saves a wordlist run that would
        // report "no password found" without ever having had a chance.
        val security = securityOf(essids, akms, saeSeen, stats)

        // Assemble the hashcat lines. The PBKDF2 salt is the raw SSID, so every
        // credential needs one: a beacon is the authoritative source, the host's
        // own scan list is the fallback.
        val out = mutableListOf<ExtractedHash>()
        for ((pmkidHex, hit) in pmkids) {
            val ssid = essidFor(hit.aa, essids, knownEssids, stats)
            if (ssid == null) {
                stats.pairsNoSsid++
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
                security = security[hit.aa]?.mode ?: SecurityMode.UNKNOWN,
            ).apply { line = hashLine }
        }
        for (p in pairs) {
            val ssid = essidFor(p.aa, essids, knownEssids, stats)
            if (ssid == null) {
                stats.pairsNoSsid++
                continue
            }
            // hashcat/hcxtools convention: the Key MIC field (bytes 81..96) inside
            // the stored eapol hex is zeroed; the real MIC lives in token[2].
            val stored = p.m2.eapol.copyOf().also { java.util.Arrays.fill(it, 81, 97, 0) }
            val hashLine = "WPA*02*${hex(p.m2.mic())}*${p.aa.replace(":", "")}*${p.spa.replace(":", "")}*" +
                "${hex(ssid)}*${hex(p.anonce)}*${hex(stored)}*%02x".format(p.mp)
            out += ExtractedHash(
                kind = HashKind.HANDSHAKE,
                essid = essidLabel(ssid),
                bssid = p.aa,
                sta = p.spa,
                messagePair = p.mp,
                keyver = keyVerFromEapol(p.m2.eapol),
                micLenBytes = 16,
                security = security[p.aa]?.mode ?: SecurityMode.UNKNOWN,
            ).apply { line = hashLine }
        }
        val saeOnlyHashes = out.count { it.security == SecurityMode.SAE_ONLY }

        return ExtractReport(
            hashes = out,
            recordsParsed = stats.parsed,
            eapolFrames = stats.eapolFrames,
            beacons = stats.beacons,
            notes = stats.notes(),
            dataFrames = stats.dataLikeFrames,
            m1Frames = stats.m1Frames,
            m2Frames = stats.m2Frames,
            m3Frames = stats.m3Frames,
            m4Frames = stats.m4Frames,
            pmkidFrames = stats.pmkidFrames,
            pairs = pairs.size,
            pairsNoApMessage = stats.pairsNoApNonce,
            badRecords = stats.badRecords,
            resyncs = stats.resyncs,
            lostBytes = stats.lostBytes,
            shortEapol = stats.shortEapol,
            pairsNoSsid = stats.pairsNoSsid,
            ssidFromScan = stats.ssidFromScan,
            networks = security.values.sortedBy { it.bssid },
            saeAuthFrames = stats.saeFrames,
            saeOnlyHashes = saeOnlyHashes,
        )
    }

    /**
     * Pick one credential per (AP,client) pair.
     *
     * M1+M2 is the canonical pair (mp 0). When the AP's M1 never made it into
     * the air time but its M3 did, the ANonce is still available (M3 carries it)
     * and the M2's MIC verifies against it — that is hcxtools' MESSAGE_PAIR_M32E2
     * (mp 2), and it is worth a lot in a lossy capture. M4 is never a nonce
     * source (it carries none), so an M2 with neither M1 nor M3 stays unusable.
     */
    private fun pickPairs(
        m1s: Map<String, MutableList<KeyFrame>>,
        m2s: Map<String, MutableList<KeyFrame>>,
        m3s: Map<String, MutableList<KeyFrame>>,
        stats: Stats,
    ): List<Pair3> {
        val out = ArrayList<Pair3>()
        for ((key, m2list) in m2s) {
            val (aa, spa) = key.split("|", limit = 2)
            val m2 = m2list.filter { it.eapol.size >= 97 }.maxByOrNull { it.replay } ?: continue
            val m1list = m1s[key].orEmpty()
            val m3list = m3s[key].orEmpty()

            // M1 and M2 share a replay counter in the canonical handshake; M3/M4
            // run one ahead. Take the exact match first, then the closest one.
            val m1 = m1list.firstOrNull { it.replay == m2.replay }
                ?: m1list.filter { it.replay <= m2.replay }.maxByOrNull { it.replay }
                ?: m1list.minByOrNull { it.replay }
            if (m1 != null && m1.replay != m2.replay) stats.replayMismatch++

            val m3 = m3list.firstOrNull { it.replay == m2.replay + 1 }
                ?: m3list.maxByOrNull { it.replay }

            when {
                m1 != null -> { out += Pair3(aa, spa, m1.nonce, m2, mp = 0); stats.pairsM1M2++ }
                m3 != null -> { out += Pair3(aa, spa, m3.nonce, m2, mp = 2); stats.pairsM3M2++ }
                else -> stats.pairsNoApNonce++
            }
        }
        return out
    }

    // --- 802.11 / EAPOL helpers ------------------------------------------------

    /**
     * EAPOL-Key frame out of an 802.11 DATA frame, LLC/SNAP stripped. The frame
     * body length decides the slice: a trailing FCS (4 B), chip padding (1..3 B)
     * or nothing at all may follow, and a frame cut by the capture limit is kept
     * when its 97-byte header is intact (hashcat reconstructs the key data).
     */
    private fun eapolFromBody(b: ByteArray, stats: Stats): ByteArray? {
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
        ) {
            stats.notEapolLlc++
            return null
        }
        val eapolStart = off + 8
        if (eapolStart + 4 > b.size) return null
        val declared = 4 + be16(b, eapolStart + 2)
        if (declared < 4) return null
        val available = b.size - eapolStart
        if (available < 97) { stats.shortEapol++; return null }
        val end = if (eapolStart + declared <= b.size) eapolStart + declared else b.size
        if (end == b.size && declared > available) stats.truncatedEapol++
        else if (declared < available) stats.trailingBytes += available - declared
        return b.copyOfRange(eapolStart, end)
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

    // --- key management (WPA2-PSK vs WPA3-SAE) -------------------------------------

    /**
     * AKM suite ids from an RSN (element 48) or legacy WPA (element 221, OUI
     * 00-50-F2) information element, walking the element list from [ieStart].
     * Empty when no RSN/WPA element is present, which the caller reports as
     * UNKNOWN rather than assuming WPA2.
     *
     * Suite ids are the 4th byte of an OUI 00-0F-AC selector (the numbers are the
     * IEEE registry values hcxtools' `AK_*` constants use too): 1 = 802.1X,
     * 2 = PSK, 3 = FT, 4/7 = FT-PSK, 5 = 802.1X-SHA256, 6 = PSK-SHA256,
     * 8 = SAE, 9 = FT-SAE, 18 = OWE, 22 = SAE-SHA384, 23 = FT-SAE-SHA384.
     */
    private fun akmSuites(b: ByteArray, ieStart: Int, stats: Stats): Set<Int> {
        var i = ieStart
        while (i + 1 < b.size) {
            val id = b[i].toInt() and 0xFF
            val len = b[i + 1].toInt() and 0xFF
            if (i + 2 + len > b.size) break
            if (id == 48 && len >= 10) {
                // ver(2) group cipher(4) pairwise count(2) [suites] akm count(2) [suites]
                //
                // The version and both counts are little-endian (802.11 element bodies),
                // while the suite selectors themselves are OUI-then-selector as written.
                // Reading the counts big-endian turns a list of 1 into 256 and every real
                // RSN element then looks truncated — which is exactly how a WPA3
                // transition network silently degraded to "key management unknown".
                var at = i + 2 + 2 + 4
                val pairwise = le16(b, at); at += 2 + pairwise * 4
                if (at + 2 > i + 2 + len) { stats.rsnTruncated++; return emptySet() }
                val akms = le16(b, at); at += 2
                if (at + akms * 4 > i + 2 + len) { stats.rsnTruncated++; return emptySet() }
                val out = LinkedHashSet<Int>(akms)
                for (k in 0 until akms) {
                    val o = at + k * 4
                    if (b[o] == 0x00.toByte() && b[o + 1] == 0x0F.toByte() && b[o + 2] == 0xAC.toByte()) {
                        out += b[o + 3].toInt() and 0xFF
                    }
                }
                return out
            }
            // Legacy WPA IE: its AKM list uses OUI 00-50-F2, where 02 means PSK.
            if (id == 221 && len >= 4 && b[i + 2] == 0x00.toByte() && b[i + 3] == 0x50.toByte() &&
                b[i + 4] == 0xF2.toByte() && b[i + 5] == 0x02.toByte()
            ) {
                return setOf(2) // WPA1 is pre-SAE: whatever it negotiated, it is PSK
            }
            i += 2 + len
        }
        return emptySet()
    }

    private fun addAkm(target: HashMap<String, MutableSet<Int>>, bssid: String, suites: Set<Int>) {
        if (suites.isEmpty()) return
        target.getOrPut(bssid) { LinkedHashSet() }.addAll(suites)
    }

    /**
     * SAE (WPA3) authentication frames. The Authentication frame's fixed body is
     * algorithm(2) seq(2) status(2) at offset 24, and the SAE commit/confirm ride in
     * an element after that, so counting the frames is what identifies the dragonfly
     * exchange — hashcat/hcxtools count them the same way (`auth->algorithm == SAE`).
     *
     * Attribution follows the transaction sequence: the commit is sent *to* the AP
     * (addr1 = BSSID), the confirm / any frame with a status code comes *from* it
     * (addr2 = BSSID). Guessing the other way would blame a client for its own SAE
     * frames, so an implausible frame is counted but not attributed.
     */
    private fun saeAuthentication(b: ByteArray, saeSeen: HashMap<String, Int>, stats: Stats) {
        if (b.size < 30) return
        val algorithm = le16(b, 24)
        if (algorithm != 3) return
        stats.saeFrames++
        val seq = le16(b, 26)
        val status = le16(b, 28)
        val fromAp = seq >= 2 || status != 0
        val bssid = if (fromAp) mac(b, 10) else mac(b, 4)
        if (seq == 0) { stats.saeUnattributed++; return }
        saeSeen.merge(bssid, 1, Int::plus)
    }

    /** Per-BSSID security verdict: what it advertised, plus what was seen on air. */
    private fun securityOf(
        essids: Map<String, ByteArray>,
        akms: Map<String, Set<Int>>,
        saeSeen: Map<String, Int>,
        stats: Stats,
    ): Map<String, NetworkSecurity> {
        val bssids = LinkedHashSet<String>()
        bssids += essids.keys; bssids += akms.keys; bssids += saeSeen.keys
        val out = LinkedHashMap<String, NetworkSecurity>()
        for (bssid in bssids) {
            val suites = akms[bssid].orEmpty()
            val saeFrames = saeSeen[bssid] ?: 0
            val hasPsk = suites.any { it in PSK_AKMS }
            val hasSae = suites.any { it in SAE_AKMS }
            val hasEnterprise = suites.isNotEmpty() && suites.all { it in ENTERPRISE_AKMS }
            val hasOwe = suites.isNotEmpty() && suites.all { it in OWE_AKMS }
            val mode = when {
                hasSae && hasPsk -> SecurityMode.MIXED_PSK_SAE
                hasSae -> SecurityMode.SAE_ONLY
                hasPsk -> SecurityMode.PSK
                hasEnterprise -> SecurityMode.ENTERPRISE
                hasOwe -> SecurityMode.OWE
                // No RSN element, but a WPA3 dragonfly exchange was seen on this BSSID.
                else -> if (saeFrames > 0) SecurityMode.SAE_ONLY else SecurityMode.UNKNOWN
            }
            if (mode == SecurityMode.SAE_ONLY) stats.saeOnlyNetworks++
            out[bssid] = NetworkSecurity(
                bssid = bssid,
                essid = essids[bssid]?.let { essidLabel(it) } ?: "(no beacon in capture)",
                akmLabels = suites.sorted().map { akmLabel(it) },
                mode = mode,
                saeAuthFrames = saeFrames,
            )
        }
        return out
    }

    private fun akmLabel(suite: Int): String = when (suite) {
        1 -> "802.1X"
        2 -> "PSK"
        3 -> "FT-8021X"
        4 -> "FT-PSK"
        5 -> "802.1X-SHA256"
        6 -> "PSK-SHA256"
        7 -> "FT-PSK"
        8 -> "SAE"
        9 -> "FT-SAE"
        10 -> "802.1X-SUITEB"
        11 -> "SAE-SHA384"
        12 -> "FT-SAE-SHA384"
        13 -> "FILS-SHA256"
        14 -> "FILS-SHA384"
        17 -> "PFS"
        18 -> "OWE"
        19 -> "FT-OWE"
        22 -> "SAE-SHA384"
        23 -> "FT-SAE-SHA384"
        else -> "AKM-$suite"
    }

    private fun le16(b: ByteArray, at: Int): Int =
        (b[at].toInt() and 0xFF) or ((b[at + 1].toInt() and 0xFF) shl 8)

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

    /** Beacon SSID first; the host's scan list second (both are the PBKDF2 salt). */
    private fun essidFor(
        bssid: String,
        fromBeacon: Map<String, ByteArray>,
        fromScan: Map<String, String>,
        stats: Stats,
    ): ByteArray? {
        fromBeacon[bssid]?.let { return it }
        fromScan[bssid.lowercase()]?.let {
            stats.ssidFromScan++
            return it.toByteArray(Charsets.UTF_8)
        }
        return null
    }

    // --- pcap reader -------------------------------------------------------------

    private class Frame(val bytes: ByteArray)

    private fun readAll(input: InputStream): ByteArray? {
        val out = ByteArrayOutputStream(64 * 1024)
        val buf = ByteArray(16 * 1024)
        var total = 0
        while (true) {
            val r = try { input.read(buf) } catch (e: Exception) { return null }
            if (r < 0) break
            out.write(buf, 0, r)
            total += r
            if (total > MAX_FILE) return null
        }
        return out.toByteArray()
    }

    /**
     * Walk the pcap records. When a record header is not plausible (the usual
     * symptom of a chunk the USB link dropped, which desyncs the whole record
     * stream), scan forward for the next header the firmware could have written
     * and keep going — the alternative is losing everything after the first gap.
     */
    private fun readAllRecords(data: ByteArray, stats: Stats): List<Frame> {
        if (data.size < 24) { stats.note("empty or unreadable pcap header"); return emptyList() }
        val m32 = be32(data, 0)
        val bigEndian = when (m32) {
            MAGIC_US_BE, MAGIC_NS_BE -> true
            0xD4C3B2A1.toInt(), 0x4D3CB2A1.toInt() -> false // the common (native-LE) case
            else -> {
                stats.note("not a libpcap file (magic %08x)".format(m32))
                return emptyList()
            }
        }
        val linktype = if (bigEndian) be32(data, 20) else le32(data, 20)
        if (linktype != 105) stats.note("linktype $linktype (expected 105 — 802.11 without radiotap); parsing anyway")

        val frames = ArrayList<Frame>(64)
        var at = 24
        while (at + 16 <= data.size) {
            // Sequentially reached headers get the loose check: rejecting a real
            // frame on a quirk would lose good captures.
            val incl = recordLength(data, at, bigEndian)
            if (incl != null && validFrameLayout(data, at, incl, strict = false)) {
                val end = at + 16 + incl
                if (end > data.size) {
                    stats.note("capture truncated mid-record (kept ${frames.size} complete frames)")
                    break
                }
                frames += Frame(data.copyOfRange(at + 16, end))
                stats.parsed++
                at = end
                continue
            }
            val next = findNextRecord(data, at + 1, bigEndian)
            if (next < 0) {
                stats.note("unparseable tail: ${data.size - at} bytes")
                break
            }
            stats.badRecords += 1
            stats.lostBytes += next - at
            stats.resyncs += 1
            at = next
        }
        if (stats.badRecords > 0) {
            stats.note("${stats.badRecords} broken record(s): ${stats.lostBytes} B skipped — capture frames lost in transit")
        }
        return frames
    }

    /**
     * The record length when the 16 bytes at [at] are a header the firmware could
     * have written: incl_len == orig_len (the firmware writes the same value
     * twice, see Buffer.cpp `add()`), a sane size and a sub-second microsecond
     * field. Null otherwise. Does NOT look at the payload.
     */
    private fun recordLength(data: ByteArray, at: Int, bigEndian: Boolean): Int? {
        val incl = if (bigEndian) be32(data, at + 8) else le32(data, at + 8)
        val orig = if (bigEndian) be32(data, at + 12) else le32(data, at + 12)
        val usec = if (bigEndian) be32(data, at + 4) else le32(data, at + 4)
        if (incl <= 0 || incl > MAX_RECORD) return null
        if (orig != incl) return null
        if (usec < 0 || usec >= 1_000_000) return null
        return incl
    }

    /**
     * Does the payload at [at] + 16 look like the 802.11 frame its header
     * claims? [strict] additionally demands a well-formed LLC/SNAP header on
     * data frames — used only while hunting for a broken stream's next record,
     * where a false positive costs more than a rare miss.
     */
    private fun validFrameLayout(data: ByteArray, at: Int, incl: Int, strict: Boolean): Boolean {
        if (at + 16 >= data.size) return false
        val fcLo = data[at + 16].toInt() and 0xFF
        if ((fcLo and 0x03) != 0) return false                  // 802.11 revision must be 0
        val type = (fcLo ushr 2) and 0x03
        val subtype = (fcLo ushr 4) and 0x0F
        when (type) {
            0 -> if (subtype > 0x0D || incl < 24) return false   // management
            1 -> if (incl < 16) return false                     // control
            2 -> if (incl < 24 + 8) return false                 // data / QoS data: hdr + LLC/SNAP
            else -> return false
        }
        if (strict && type == 2) {
            val hdr = macHeaderLength(data, at + 16)
            if (hdr + 3 > incl) return false                    // LLC/SNAP must fit the record
            val llc = at + 16 + hdr
            if (llc + 3 > data.size) return false
            // Every 802.11 data frame is RFC1042 encapsulated, so a candidate
            // whose body does not begin AA AA 03 is random bytes.
            if (!(data[llc] == 0xAA.toByte() && data[llc + 1] == 0xAA.toByte() && data[llc + 2] == 0x03.toByte()))
                return false
        }
        return true
    }

    /** 802.11 header length of the frame whose first byte is at [fcAt]. */
    private fun macHeaderLength(data: ByteArray, fcAt: Int): Int {
        val fcLo = data[fcAt].toInt() and 0xFF
        val fcHi = data[fcAt + 1].toInt() and 0xFF
        var len = 24                                            // fc + dur + 3 MAC + seqctl
        if ((fcLo ushr 4) and 0x08 != 0) len += 2               // QoS control
        if ((fcHi and 0x01) != 0 && (fcHi and 0x02) != 0) len += 6 // fourth address
        return len
    }

    /**
     * Scans forward for the next record header of a desynced stream. Uses the
     * strict payload check, requires the whole payload to be present (a
     * misaligned read of the two identical length fields looks exactly like a
     * header whose payload runs past end-of-file, so the resync scan must not
     * treat end-of-file truncation as a resync target), and confirms the hit by
     * checking that the record after it is also plausible.
     */
    private fun findNextRecord(data: ByteArray, from: Int, bigEndian: Boolean): Int {
        var at = from
        while (at + 16 <= data.size) {
            val incl = recordLength(data, at, bigEndian)
            if (incl != null && at + 16 + incl <= data.size && validFrameLayout(data, at, incl, strict = true)) {
                val after = at + 16 + incl
                if (after >= data.size) return at               // last record in the stream
                val nIncl = recordLength(data, after, bigEndian)
                if (nIncl != null && validFrameLayout(data, after, nIncl, strict = false)) return at
            }
            at++
        }
        return -1
    }

    private fun be32(b: ByteArray, at: Int): Int =
        ((b[at].toInt() and 0xFF) shl 24) or ((b[at + 1].toInt() and 0xFF) shl 16) or
            ((b[at + 2].toInt() and 0xFF) shl 8) or (b[at + 3].toInt() and 0xFF)

    private fun le32(b: ByteArray, at: Int): Int =
        (b[at].toInt() and 0xFF) or ((b[at + 1].toInt() and 0xFF) shl 8) or
            ((b[at + 2].toInt() and 0xFF) shl 16) or ((b[at + 3].toInt() and 0xFF) shl 24)

    // --- internal match types -----------------------------------------------------

    /** One classified EAPOL-Key frame with the fields the pairing needs. */
    private class KeyFrame(
        val aa: String,
        val spa: String,
        val eapol: ByteArray,
        val nonce: ByteArray,
        val replay: Long,
        val keyver: Int,
        val keyDataLen: Int,
        val micSet: Boolean,
        val ackSet: Boolean,
    ) {
        /** The MIC as it appears on air (bytes 81..96). */
        fun mic(): ByteArray = eapol.copyOfRange(81, 97)
    }

    /** A chosen credential: which nonce source supplied the ANonce, and the mp code. */
    private class Pair3(
        val aa: String,
        val spa: String,
        val anonce: ByteArray,
        val m2: KeyFrame,
        val mp: Int,
    )

    private class PmkidHit(val aa: String, val spa: String, val pmkidHex: String, val keyver: Int)

    /** Counters behind the diagnostics the UI shows when nothing was cracked. */
    private class Stats {
        var parsed = 0
        var beacons = 0
        var eapolFrames = 0
        var dataLikeFrames = 0
        var notEapolLlc = 0
        var wdsFrames = 0
        var selfFrames = 0
        var shortEapol = 0
        var truncatedEapol = 0
        var trailingBytes = 0
        var m1Frames = 0
        var m2Frames = 0
        var m3Frames = 0
        var m4Frames = 0
        var pmkidFrames = 0
        var pairsM1M2 = 0
        var pairsM3M2 = 0
        var pairsNoApNonce = 0
        var replayMismatch = 0
        var badRecords = 0
        var resyncs = 0
        var lostBytes = 0
        var pairsNoSsid = 0
        var ssidFromScan = 0
        var saeFrames = 0
        var saeUnattributed = 0
        var saeOnlyNetworks = 0
        var rsnTruncated = 0

        private val freeNotes = ArrayList<String>()
        private val repeated = LinkedHashMap<String, Int>()

        fun note(text: String) { freeNotes += text }

        /** Human-readable diagnostics: counts only where they change the picture. */
        fun notes(): List<String> {
            val out = ArrayList(freeNotes)
            if (pairsNoApNonce > 0) out += "$pairsNoApNonce client message(s) (M2) had no matching AP message — " +
                "the AP's frame never reached the capture, so that handshake cannot be rebuilt"
            if (m4Frames > 0) out += "$m4Frames final ACK frame(s) (M4) seen — they carry no key material, " +
                "they are not the AP message a handshake needs"
            if (replayMismatch > 0) out += "$replayMismatch pair(s) matched with mismatched replay counters"
            if (truncatedEapol > 0) out += "$truncatedEapol EAPOL frame(s) cut short by the capture (kept what arrived)"
            if (shortEapol > 0) out += "$shortEapol EAPOL frame(s) too short to carry a MIC — ignored"
            if (notEapolLlc > 0) out += "$notEapolLlc data frame(s) were not EAPOL — ignored"
            if (pairsNoSsid > 0) out += "$pairsNoSsid credential(s) dropped: this network's SSID is unknown " +
                "(no beacon in the capture and the network is not in the scan list) — the SSID is the PBKDF2 salt, " +
                "so without it no cracker can work"
            if (ssidFromScan > 0) out += "$ssidFromScan credential(s) used the SSID from the app's scan list (no beacon in this capture)"
            if (saeOnlyNetworks > 0) {
                out += "$saeOnlyNetworks network(s) advertise WPA3-SAE only: their PMK comes from the dragonfly " +
                    "exchange, not from PBKDF2(SSID, password), so a mode-22000 wordlist run cannot recover it — " +
                    "no GPU or wordlist changes that. The firmware's `sniffsae` records the exchange as evidence; " +
                    "attacking such a network means the client side, not offline cracking"
            }
            if (saeFrames > 0) {
                out += "$saeFrames SAE authentication frame(s) seen (the WPA3 handshake) — if a handshake was " +
                    "carved from one of these networks it will not crack"
            }
            if (saeUnattributed > 0) {
                out += "$saeUnattributed SAE frame(s) could not be attributed to a network (implausible transaction " +
                    "sequence) — counted, not assigned to a BSSID"
            }
            if (rsnTruncated > 0) out += "$rsnTruncated RSN element(s) cut short — their key-management list is incomplete"
            out += repeated.entries.joinToString("; ") { "${it.value}× ${it.key}" }
            return out.filter { it.isNotBlank() }
        }
    }
}
