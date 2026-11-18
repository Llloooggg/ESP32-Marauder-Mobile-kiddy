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
 * (pairwise-key-expansion input, MIC message buffer, expected tag).
 *
 * Verification follows hashcat v6.2.6 `module_22000.c` / `m22000-pure.cl`
 * (verified against the hashcat wiki WPA*02 example vector and the mode's
 * built-in PMKID self-test — see CrackCoreTest):
 *  - PMK   = PBKDF2-HMAC-SHA1(password, essid, 4096, 32)
 *  - PMKID = HMAC-SHA1(key=PMK, "PMK Name" + AA + SPA)[0..16)
 *  - keyver1: KDE = HMAC-SHA1(PMK, PKE100);  MIC = HMAC-MD5(KDE[0..16), EAPOL)[0..16)
 *  - keyver2: KDE = HMAC-SHA1(PMK, PKE100);  MIC = HMAC-SHA1(KDE[0..16), EAPOL)[0..16)
 *  - keyver3: K   = HMAC-SHA256(PMK, PKE102); MIC = AES-CMAC(K[0..16), EAPOL || 0x80)
 * EAPOL is hashed exactly as stored in the line; by hcxtools convention the
 * Key MIC field inside the frame is already zeroed there.
 */
class WpaTarget internal constructor(
    val kind: HashKind,
    val essid: ByteArray,
    val keyver: Int,
    private val pmkSalt: ByteArray,
    private val pmkidData: ByteArray?,   // type 1: "PMK Name"+AA+SPA
    private val pke: ByteArray?,         // type 2: pairwise key expansion input
    private val micMsg: ByteArray?,      // type 2: EAPOL w/ MIC zeroed (+0x80 pad for kv3)
    private val expected: ByteArray,     // 16B PMKID or Key MIC
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
        return when (kind) {
            HashKind.PMKID -> {
                val calc = WpaCrypto.hmac("HmacSHA1", pmk, pmkidData!!)
                Arrays.equals(calc, 0, 16, expected, 0, 16)
            }
            HashKind.HANDSHAKE -> when (keyver) {
                // Semantics taken from hashcat v6.2.6 OpenCL/m22000-pure.cl
                // aux1/aux2/aux3 kernels (message bytes = stored eapol as-is):
                //  kv1: KDE = HMAC-SHA1(PMK, PKE100);  MIC = HMAC-MD5(KDE[0..16), eapol)[0..16)
                //  kv2: KDE = HMAC-SHA1(PMK, PKE100);  MIC = HMAC-SHA1(KDE[0..16), eapol)[0..16)
                //  kv3: K   = HMAC-SHA256(PMK, PKE102); MIC = AES-CMAC(K[0..16), eapol || 0x80)
                1 -> Arrays.equals(
                    WpaCrypto.hmac("HmacMD5", WpaCrypto.hmac("HmacSHA1", pmk, pke!!).copyOfRange(0, 16), micMsg!!),
                    0, 16, expected, 0, 16,
                )
                2 -> Arrays.equals(
                    WpaCrypto.hmac("HmacSHA1", WpaCrypto.hmac("HmacSHA1", pmk, pke!!).copyOfRange(0, 16), micMsg!!),
                    0, 16, expected, 0, 16,
                )
                3 -> Arrays.equals(
                    WpaCrypto.aesCmac(WpaCrypto.hmac("HmacSHA256", pmk, pke!!).copyOfRange(0, 16), micMsg!!),
                    0, 16, expected, 0, 16,
                )
                else -> false
            }
        }
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
                    if (keyver !in 1..3) return null
                    val snonce = eapol.copyOfRange(17, 49)
                    val pke = buildPke(keyver, aa, spa, anonce, snonce)
                    // hashcat hashes the eapol EXACTLY as stored in the line (hcxtools
                    // convention: the Key MIC field inside the frame is zeroed there).
                    // For keyver 3 the module appends one 0x80 byte (OpenCL aux3 path).
                    val micMsg = if (keyver == 3) {
                        eapol.copyOf(eapol.size + 1).also { it[it.size - 1] = 0x80.toByte() }
                    } else eapol
                    WpaTarget(HashKind.HANDSHAKE, essid, keyver, essid, null, pke, micMsg, mic)
                }
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun buildPke(keyver: Int, aa: ByteArray, spa: ByteArray, anonce: ByteArray, snonce: ByteArray): ByteArray {
        val (macLow, macHigh) = if (compare(aa, spa) <= 0) Pair(aa, spa) else Pair(spa, aa)
        val (nonLow, nonHigh) = if (compare(anonce, snonce) <= 0) Pair(anonce, snonce) else Pair(snonce, anonce)
        return if (keyver == 3) {
            val pke = ByteArray(102)
            pke[0] = 1
            System.arraycopy("Pairwise key expansion".toByteArray(Charsets.ISO_8859_1), 0, pke, 2, 22)
            System.arraycopy(macLow, 0, pke, 24, 6)
            System.arraycopy(macHigh, 0, pke, 30, 6)
            System.arraycopy(nonLow, 0, pke, 36, 32)
            System.arraycopy(nonHigh, 0, pke, 68, 32)
            pke[100] = 0x80.toByte()
            pke[101] = 1
            pke
        } else {
            // 802.11i PKE: label\0 + macs + nonces = 99 bytes; hashcat HMACs 100
            // (the pke buffer's one trailing zero byte is part of the message)
            val pke = ByteArray(100)
            System.arraycopy("Pairwise key expansion\u0000".toByteArray(Charsets.ISO_8859_1), 0, pke, 0, 23)
            System.arraycopy(macLow, 0, pke, 23, 6)
            System.arraycopy(macHigh, 0, pke, 29, 6)
            System.arraycopy(nonLow, 0, pke, 35, 32)
            System.arraycopy(nonHigh, 0, pke, 67, 32)
            pke
        }
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
