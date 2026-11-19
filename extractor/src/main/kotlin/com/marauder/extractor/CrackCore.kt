package com.marauder.extractor

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.util.Arrays

/**
 * A parsed hashcat mode-22000 line, pre-processed for per-password verification:
 * everything that does not depend on the candidate password is computed once
 * (pairwise-key-expansion buffers, MIC message buffers, expected tag).
 *
 * Parity with hashcat v6.2.6 (`module_22000.c` + `OpenCL/m22000-pure.cl`):
 * every EAPOL line is checked by ALL deep-compute aux kernels — their guards
 * are `type != 2 && keyver != N` — so the keyver field only picks the module's
 * byte-swap convention at parse time, not one MIC algorithm. Verification here
 * is the same variant superset (each tag truncated to 16 bytes):
 *
 *  - PMK    = PBKDF2-HMAC-SHA1(password, essid, 4096 iterations, 32 bytes)
 *  - PMKID  = HMAC-SHA1(PMK, "PMK Name" || AA || SPA)                       (aux4)
 *  - KDE100 = HMAC-SHA1(PMK, PKE100),  PKE100 = label+0 || macs || nonces || 0   (aux1/aux2)
 *  - KDE102 = HMAC-SHA256(PMK, PKE102), PKE102 = 01 00 label macs nonces 80 01   (aux3)
 *  - KCKstd = HMAC-SHA1(PMK, PKE100std), PKE100std = 0 || label || 0 || macs || nonces
 *            (802.11 PRF-384 first block; the plain RSN WPA2-AES KCK, kept as an
 *             extra beyond hashcat for real-capture coverage)
 *  candidate MICs over each message variant: HMAC-MD5(KDE100[0..16)),
 *  HMAC-SHA1(KDE100[0..16)), AES-CMAC(KDE102[0..16)), AES-CMAC(KCKstd[0..16)),
 *  HMAC-MD5(KDE100md5[0..16)) with KDE100md5 = HMAC-MD5(PMK, PKE100) (legacy WPA1)
 *  messages: the stored EAPOL as-is (hcxtools convention: its inner Key MIC
 *  field is already zeroed), its 4-byte-word byte-swapped form (hashcat pre-
 *  swaps the eapol for keyver 2), each also with one trailing 0x80 appended
 *  (hashcat appends that for keyver 3 before CMAC).
 *
 * Known answers (see CrackCoreTest): the mode's built-in selftest PMKID
 * (`ST_HASH`/`ST_PASS` in module_22000.c, password "hashcat!") and the hashcat
 * wiki WPA*02 example (essid TP-LINK_HASHCAT_TEST, password "hashcat!") both
 * crack to the exact byte-for-byte tag.
 */
class WpaTarget internal constructor(
    val kind: HashKind,
    val essid: ByteArray,
    val keyver: Int,
    private val pmkSalt: ByteArray,
    private val pmkidData: ByteArray?,         // type 1: "PMK Name"+AA+SPA
    private val pkeSets: Array<PkeSet>?,       // type 2: one per plausible SNonce placement
    private val micMsgs: Array<ByteArray>?,    // type 2: candidate MIC messages
    private val expected: ByteArray,           // 16B PMKID or Key MIC
) {
    val expectedHex: String = expected.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    val essidText: String = String(essid, Charsets.ISO_8859_1)

    /** One password candidate against this target. */
    fun verify(password: String): Boolean =
        verifyWithPmk(WpaCrypto.pbkdf2Sha1(password, pmkSalt, 4096, 32))

    /**
     * Same check with an already-derived PMK. The PBKDF2 cost dominates cracking,
     * so engines group targets by essid (the PMK salt) and reuse this PMK across
     * every target sharing it.
     */
    fun verifyWithPmk(pmk: ByteArray): Boolean {
        if (kind == HashKind.PMKID) {
            return Arrays.equals(WpaCrypto.hmac("HmacSHA1", pmk, pmkidData!!), 0, 16, expected, 0, 16)
        }
        for (pk in pkeSets!!) {
            val kde100 = WpaCrypto.hmac("HmacSHA1", pmk, pk.p100).copyOfRange(0, 16)
            val kde100md5 = WpaCrypto.hmac("HmacMD5", pmk, pk.p100).copyOfRange(0, 16) // legacy WPA1 KCK
            val kde102 = WpaCrypto.hmac("HmacSHA256", pmk, pk.p102).copyOfRange(0, 16)
            val kckStd = WpaCrypto.hmac("HmacSHA1", pmk, pk.pstd).copyOfRange(0, 16) // 802.11 PRF-384 KCK
            for (msg in micMsgs!!) {
                if (Arrays.equals(WpaCrypto.hmac("HmacMD5", kde100, msg), 0, 16, expected, 0, 16)) return true
                if (Arrays.equals(WpaCrypto.hmac("HmacSHA1", kde100, msg), 0, 16, expected, 0, 16)) return true
                if (Arrays.equals(WpaCrypto.aesCmac(kde102, msg), 0, 16, expected, 0, 16)) return true
                if (Arrays.equals(WpaCrypto.aesCmac(kckStd, msg), 0, 16, expected, 0, 16)) return true
                if (Arrays.equals(WpaCrypto.hmac("HmacMD5", kde100md5, msg), 0, 16, expected, 0, 16)) return true
            }
        }
        return false
    }

    /**
     * The target's password-independent material, handed to the native engines
     * verbatim. This exists so the app's parser is the only place a 22000 line is
     * interpreted: the native side gets the same pre-computed buffers Kotlin's
     * [verifyWithPmk] uses, and both must agree for a candidate to be reported.
     *
     * It carries the FIRST [PkeSet] — the nonce layout the blob's own bytes point at.
     * A line whose SNonce lives in the other layout is still cracked here, by the
     * remaining candidate; the native engine would report "not found" for it, and the
     * caller falls back to this implementation rather than reporting a wrong answer.
     * (Feeding every candidate to the native engines is a transport change: the TLV
     * needs one pke set per candidate.)
     */
    fun material(): TargetMaterial {
        val primary = pkeSets?.firstOrNull()
        return TargetMaterial(
            kind = if (kind == HashKind.PMKID) 1 else 2,
            keyver = keyver,
            salt = pmkSalt,
            expected = expected,
            pmkidData = pmkidData ?: ByteArray(0),
            pke100 = primary?.p100 ?: ByteArray(0),
            pke102 = primary?.p102 ?: ByteArray(0),
            pkeStd = primary?.pstd ?: ByteArray(0),
            micMsgs = micMsgs?.toList() ?: emptyList(),
        )
    }
}

/**
 * One set of pairwise-key-expansion buffers, built for one placement of the
 * supplicant nonce (SNonce) inside the stored EAPOL blob.
 */
internal class PkeSet(val p100: ByteArray, val p102: ByteArray, val pstd: ByteArray)

/** One target's pre-computed verification buffers, in transport form. */
data class TargetMaterial(
    val kind: Int,                  // 1 = PMKID (WPA*01), 2 = handshake (WPA*02)
    val keyver: Int,
    val salt: ByteArray,            // PBKDF2 salt == raw SSID
    val expected: ByteArray,        // 16 bytes: PMKID or Key MIC
    val pmkidData: ByteArray,
    val pke100: ByteArray,
    val pke102: ByteArray,
    val pkeStd: ByteArray,
    val micMsgs: List<ByteArray>,
)

/**
 * Serialises a session's targets for the native engines, in the exact layout
 * `app/src/main/cpp/wpa_crypto.cpp:parse_material` reads (magic, version, count,
 * then per target: kind/keyver bytes, big-endian length-prefixed buffers).
 */
object Material {

    const val MAGIC = "MKMT"
    const val VERSION = 1

    fun write(targets: List<TargetMaterial>): ByteArray {
        require(targets.isNotEmpty()) { "no targets to serialise" }
        val out = java.io.ByteArrayOutputStream(4096)
        fun u32(v: Int) {
            out.write((v ushr 24) and 0xFF); out.write((v ushr 16) and 0xFF)
            out.write((v ushr 8) and 0xFF); out.write(v and 0xFF)
        }
        fun vec(b: ByteArray) { u32(b.size); out.write(b) }

        out.write(MAGIC.toByteArray(Charsets.ISO_8859_1))
        u32(VERSION)
        u32(targets.size)
        for (t in targets) {
            require(t.expected.size == 16) { "expected tag must be 16 bytes, got ${t.expected.size}" }
            out.write(t.kind and 0xFF)
            out.write(t.keyver and 0xFF)
            vec(t.salt)
            out.write(t.expected)
            vec(t.pmkidData)
            vec(t.pke100)
            vec(t.pke102)
            vec(t.pkeStd)
            u32(t.micMsgs.size)
            t.micMsgs.forEach { vec(it) }
        }
        return out.toByteArray()
    }
}

/** Parse + verify for hashcat-22000 lines. Pure JVM, thread-safe, no Android deps. */
object CrackCore {

    /** null when the line is not a parseable 22000 record. */
    fun parse(line: String): WpaTarget? {
        val p = line.trim().split("*")
        if (p.size < 6 || p[0] != "WPA") return null
        return try {
            when (p[1]) {
                "01" -> {
                    if (p.size < 7) return null
                    val pmkid = unhex(p[2], 16) ?: return null
                    val aa = unhex(p[3], 6) ?: return null
                    val spa = unhex(p[4], 6) ?: return null
                    val essid = unhexLenient(p[5]) ?: return null
                    if (essid.isEmpty()) return null
                    val pmkidData = "PMK Name".toByteArray(Charsets.ISO_8859_1) + aa + spa
                    WpaTarget(HashKind.PMKID, essid, 0, essid, pmkidData, null, null, pmkid)
                }
                "02" -> {
                    if (p.size < 9) return null
                    val mic = unhex(p[2], 16) ?: return null
                    val aa = unhex(p[3], 6) ?: return null
                    val spa = unhex(p[4], 6) ?: return null
                    val essid = unhexLenient(p[5]) ?: return null
                    if (essid.isEmpty()) return null
                    val anonce = unhex(p[6], 32) ?: return null
                    val eapol = unhexAny(p[7]) ?: return null
                    if (eapol.size < 99) return null // auth_packet minimum
                    val keyver = be16(eapol, 5) and 0x0003
                    if (keyver !in 1..3) return null // module rejects keyver 0 / >3
                    val snonceAt = snonceCandidates(eapol)
                    val raw = eapol
                    val swap = wordSwapped(raw)
                    val padded = raw.copyOf(raw.size + 1).also { it[raw.size] = 0x80.toByte() }
                    val paddedSwap = swap.copyOf(swap.size + 1).also { it[swap.size] = 0x80.toByte() }
                    WpaTarget(
                        HashKind.HANDSHAKE, essid, keyver, essid, null,
                        snonceAt.map { sn ->
                            PkeSet(
                                pke100(aa, spa, anonce, sn),
                                pke102(aa, spa, anonce, sn),
                                pkeStd(aa, spa, anonce, sn),
                            )
                        }.toTypedArray(),
                        arrayOf(raw, swap, padded, paddedSwap),
                        mic,
                    )
                }
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Where the supplicant nonce (SNonce) sits inside the stored EAPOL blob, most
     * likely placement first. Two layouts occur, and they are not compatible:
     *
     *  * the frame as it appears on air — the standard's KEY NONCE field at 49..81,
     *    with Key IV/RSC/ID at 17..49 (that region is zero on CCMP handshakes). This
     *    is what this app's own extractor stores, and these offsets were confirmed
     *    byte by byte against a live access point's EAPOL frames;
     *  * the form hashcat's own example 22000 line carries — SNonce at 17..49 and
     *    zeros at 49..81. Checked independently of this code: recomputing that
     *    line's MIC with the SNonce from 49..81 does not reproduce its MIC, while
     *    17..49 reproduces it exactly.
     *
     * Guessing wrong does not produce a wrong answer, it produces no answer: the MIC
     * never matches, the password really is right, and nothing explains the miss. So
     * every plausible placement is verified, and the blob's own bytes only decide
     * which one is tried first.
     */
    private fun snonceCandidates(eapol: ByteArray): List<ByteArray> {
        val atNonceField = eapol.copyOfRange(49, 81)
        val atIvField = eapol.copyOfRange(17, 49)
        val ivEmpty = atIvField.all { it == 0.toByte() }
        val nonceEmpty = atNonceField.all { it == 0.toByte() }
        return when {
            ivEmpty && !nonceEmpty -> listOf(atNonceField)               // raw capture
            nonceEmpty && !ivEmpty -> listOf(atIvField)                  // hashcat example form
            else -> listOf(atNonceField, atIvField)                      // both possible: standard first
        }
    }

    /** hashcat aux1/aux2 buffer: label+NUL(23) macs(12) nonces(64) + trailing 0 → 100. */
    private fun pke100(aa: ByteArray, spa: ByteArray, anonce: ByteArray, snonce: ByteArray): ByteArray {
        val (macLow, macHigh) = ordered(aa, spa)
        val (nonLow, nonHigh) = ordered(anonce, snonce)
        val b = ByteArray(100)
        System.arraycopy("Pairwise key expansion\u0000".toByteArray(Charsets.ISO_8859_1), 0, b, 0, 23)
        System.arraycopy(macLow, 0, b, 23, 6)
        System.arraycopy(macHigh, 0, b, 29, 6)
        System.arraycopy(nonLow, 0, b, 35, 32)
        System.arraycopy(nonHigh, 0, b, 67, 32)
        return b
    }

    /** hashcat aux3 buffer: 01 00 label(22) macs(12) nonces(64) 80 01 → 102. */
    private fun pke102(aa: ByteArray, spa: ByteArray, anonce: ByteArray, snonce: ByteArray): ByteArray {
        val (macLow, macHigh) = ordered(aa, spa)
        val (nonLow, nonHigh) = ordered(anonce, snonce)
        val b = ByteArray(102)
        b[0] = 1
        System.arraycopy("Pairwise key expansion".toByteArray(Charsets.ISO_8859_1), 0, b, 2, 22)
        System.arraycopy(macLow, 0, b, 24, 6)
        System.arraycopy(macHigh, 0, b, 30, 6)
        System.arraycopy(nonLow, 0, b, 36, 32)
        System.arraycopy(nonHigh, 0, b, 68, 32)
        b[100] = 0x80.toByte()
        b[101] = 1
        return b
    }

    /** 802.11 PRF-384 block-0 message: counter(00) label(22) 00 macs(12) nonces(64) → 100. */
    private fun pkeStd(aa: ByteArray, spa: ByteArray, anonce: ByteArray, snonce: ByteArray): ByteArray {
        val (macLow, macHigh) = ordered(aa, spa)
        val (nonLow, nonHigh) = ordered(anonce, snonce)
        val b = ByteArray(100)
        System.arraycopy("Pairwise key expansion".toByteArray(Charsets.ISO_8859_1), 0, b, 1, 22)
        System.arraycopy(macLow, 0, b, 24, 6)
        System.arraycopy(macHigh, 0, b, 30, 6)
        System.arraycopy(nonLow, 0, b, 36, 32)
        System.arraycopy(nonHigh, 0, b, 68, 32)
        return b
    }

    private fun ordered(a: ByteArray, b: ByteArray): Pair<ByteArray, ByteArray> =
        if (compare(a, b) <= 0) Pair(a, b) else Pair(b, a)

    /** Reverse each aligned 4-byte group — hashcat's keyver-2 eapol pre-swap. */
    private fun wordSwapped(src: ByteArray): ByteArray {
        val out = src.copyOf()
        var i = 0
        while (i + 4 <= out.size) {
            val a = out[i]; out[i] = out[i + 3]; out[i + 3] = a
            val b = out[i + 1]; out[i + 1] = out[i + 2]; out[i + 2] = b
            i += 4
        }
        return out
    }

    private fun compare(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    private fun be16(b: ByteArray, at: Int): Int =
        ((b[at].toInt() and 0xFF) shl 8) or (b[at + 1].toInt() and 0xFF)

    private fun unhex(s: String, exactBytes: Int): ByteArray? {
        if (s.length != exactBytes * 2) return null
        return unhexAny(s)
    }

    private fun unhexAny(s: String): ByteArray? {
        if (s.length % 2 != 0) return null
        return try {
            ByteArray(s.length / 2) {
                val hi = Character.digit(s[it * 2], 16)
                val lo = Character.digit(s[it * 2 + 1], 16)
                if (hi < 0 || lo < 0) throw NumberFormatException()
                ((hi shl 4) or lo).toByte()
            }
        } catch (e: NumberFormatException) {
            null
        }
    }

    private fun unhexLenient(s: String): ByteArray? = if (s.isEmpty()) ByteArray(0) else unhexAny(s)

    /**
     * Human-readable read-out of one 22000 line, for the "why can't this be
     * cracked?" question. Unlike [parse] it reports what it sees even when the
     * record is unusable, and lists the reasons.
     */
    fun inspect(line: String): HashInspection {
        val problems = mutableListOf<String>()
        val notes = mutableListOf<String>()
        val p = line.trim().split("*")
        if (p.size < 7 || p[0] != "WPA") {
            return HashInspection(
                line = line, kind = null, essidText = "", essidHex = "", ap = "", sta = "",
                keyver = 0, messagePair = -1, anonceHex = "", micHex = "", eapolBytes = 0,
                problems = listOf("not a hashcat-22000 line (expected WPA*01*… or WPA*02*…)"),
                notes = emptyList(),
            )
        }
        val ap = formatMac(p[3])
        val sta = formatMac(p[4])
        val essidHex = p[5]
        val essid = unhexLenient(essidHex) ?: ByteArray(0)
        val essidText = printable(essid)
        if (essid.isEmpty()) {
            problems += "SSID field is empty — the SSID is the PBKDF2 salt, so no candidate password can ever match. Re-extract the capture (a beacon or the scan list supplies the SSID)."
        }
        return when (p[1]) {
            "01" -> {
                val pmkid = unhexAny(p[2]) ?: ByteArray(0)
                if (pmkid.size != 16) problems += "PMKID field is ${pmkid.size} bytes, expected 16"
                if (pmkid.isNotEmpty() && pmkid.all { it == 0.toByte() })
                    problems += "PMKID is all zeros — nothing to check a candidate against"
                notes += "PMKID credential: the password is tested against the AP's own PMKID element, no handshake needed"
                HashInspection(
                    line = line, kind = HashKind.PMKID, essidText = essidText, essidHex = essidHex,
                    ap = ap, sta = sta, keyver = 0, messagePair = 255, anonceHex = "",
                    micHex = hex(pmkid), eapolBytes = 0, problems = problems, notes = notes,
                )
            }
            "02" -> {
                val mic = unhexAny(p[2]) ?: ByteArray(0)
                val anonce = unhexAny(p[6]) ?: ByteArray(0)
                val eapol = unhexAny(p[7]) ?: ByteArray(0)
                val mpToken = p.getOrNull(8)
                val mp = if (mpToken != null && mpToken.length == 2) (unhexAny(mpToken)?.firstOrNull()?.toInt() ?: -1) and 0xFF else -1
                if (mic.size != 16) problems += "MIC field is ${mic.size} bytes, expected 16"
                if (mic.isNotEmpty() && mic.all { it == 0.toByte() })
                    problems += "stored MIC is all zeros — there is no checksum to verify a candidate against (the capture held no real M2)"
                if (anonce.size != 32) problems += "ANonce field is ${anonce.size} bytes, expected 32"
                if (anonce.isNotEmpty() && anonce.all { it == 0.toByte() })
                    problems += "ANonce is all zeros — the AP's handshake message never made it into the capture, so this credential can never verify a password. Re-extract with the current build: it rebuilds the ANonce from an M3 when the M1 was lost."
                if (eapol.size < 99) problems += "stored EAPOL frame is ${eapol.size} bytes — below the 99-byte EAPOL-Key header, the MIC cannot be recomputed"
                var keyver = 0
                if (eapol.size >= 7) {
                    val keyInfo = be16(eapol, 5)
                    keyver = keyInfo and 0x0007
                    if (keyver !in 1..3) problems += "EAPOL key version is $keyver — that is not a WPA/WPA2 key frame"
                    if (keyInfo and 0x0100 == 0)
                        problems += "the stored frame has no MIC flag in its key-info bits — the extractor stored the wrong message (an M1/M4 cannot carry a MIC)"
                    if (keyInfo and 0x0080 != 0)
                        notes += "stored frame is an M3 (ACK + MIC): paired as M3+M2 because the M1 was missing"
                    if (keyInfo and 0x0007 == 1) notes += "key version 1 (legacy WPA/TKIP MIC)"
                    if (keyInfo and 0x0007 == 3) notes += "key version 3 (PSK-SHA256 / FT): SHA256-based MIC"
                }
                // hashcat/hcxtools put the pair index in the low 3 bits and keep flags
                // above it (0x10 = captured without an AP, 0x80 = replay counter not
                // checked), so both have to be read separately.
                when (mp and 0x07) {
                    0 -> notes += "message pair 0 (M1+M2)"
                    1 -> notes += "message pair 1 (M1+M4)"
                    2 -> notes += "message pair 2 (M3 supplied the ANonce, the M2 supplies the MIC)"
                    3 -> notes += "message pair 3 (M3+M3)"
                    4 -> notes += "message pair 4 (M3+M4)"
                    5 -> notes += "message pair 5 (M3 stored, SNonce in the nonce field)"
                }
                if (mp and 0x10 != 0) notes += "flag 0x10: captured without the AP's own frame (ap-less capture)"
                if (mp and 0x80 != 0) notes += "flag 0x80: replay counter not verified by the capture"
                if (mp < 0) problems += "message-pair token is missing or not one hex byte"
                HashInspection(
                    line = line, kind = HashKind.HANDSHAKE, essidText = essidText, essidHex = essidHex,
                    ap = ap, sta = sta, keyver = keyver, messagePair = mp, anonceHex = hex(anonce),
                    micHex = hex(mic), eapolBytes = eapol.size, problems = problems, notes = notes,
                )
            }
            else -> HashInspection(
                line = line, kind = null, essidText = essidText, essidHex = essidHex, ap = ap, sta = sta,
                keyver = 0, messagePair = -1, anonceHex = "", micHex = "", eapolBytes = 0,
                problems = listOf("unknown WPA record type '${p[1]}' (this build cracks 01 = PMKID and 02 = handshake)"),
                notes = emptyList(),
            )
        }
    }

    private fun formatMac(hexToken: String): String =
        if (hexToken.length != 12) hexToken
        else (0 until 6).joinToString(":") { hexToken.substring(it * 2, it * 2 + 2) }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private fun printable(b: ByteArray): String {
        val s = String(b, Charsets.UTF_8)
        return if (s.all { it.code in 32..126 }) s else "<non-printable, ${b.size} bytes>"
    }
}

/**
 * What one 22000 line actually contains, plus the reasons it cannot be cracked.
 * A line can parse and still be worthless (a zero ANonce, a zero MIC, an empty
 * SSID) — the UI shows these so "my real password did not work" has an answer.
 */
data class HashInspection(
    val line: String,
    val kind: HashKind?,
    val essidText: String,
    val essidHex: String,
    val ap: String,
    val sta: String,
    val keyver: Int,
    val messagePair: Int,
    val anonceHex: String,
    val micHex: String,
    val eapolBytes: Int,
    val problems: List<String>,
    val notes: List<String>,
) {
    /** True when a cracker can do something with this line. */
    val crackable: Boolean get() = kind != null && problems.isEmpty()

    /** Short label for lists. */
    val label: String get() = when (kind) {
        HashKind.PMKID -> "PMKID · $essidText"
        HashKind.HANDSHAKE -> "handshake · $essidText · keyver $keyver"
        null -> "unparseable line"
    }
}

/** Minimal shared crypto. Uses JDK primitives only; AES-CMAC is hand-rolled (RFC 4493). */
object WpaCrypto {

    fun pbkdf2Sha1(password: String, salt: ByteArray, iters: Int, outBytes: Int): ByteArray =
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            .generateSecret(PBEKeySpec(password.toCharArray(), salt, iters, outBytes * 8)).encoded

    fun hmac(algorithm: String, key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(algorithm).apply { init(SecretKeySpec(key, algorithm)) }
        return mac.doFinal(data)
    }

    fun aesCmac(key: ByteArray, msg: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        val l = cipher.doFinal(ByteArray(16))

        fun shl1(b: ByteArray): ByteArray {
            val out = ByteArray(16)
            for (i in 0 until 15) out[i] = ((b[i].toInt() shl 1) or ((b[i + 1].toInt() and 0x80) shr 7)).toByte()
            out[15] = (b[15].toInt() shl 1).toByte()
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
