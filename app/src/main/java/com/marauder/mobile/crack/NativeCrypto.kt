package com.marauder.mobile.crack

import com.marauder.extractor.Material

/**
 * Loader and gate for the native cracking core (`libmarauder_crypto.so`).
 *
 * Loading the library is not enough to use it. Three things must hold, and each one is
 * reported separately because "the native engine is off" is useless to a user if it
 * does not say why:
 *
 *  1. the `.so` exists for this ABI and loaded;
 *  2. it reads the same material-protocol version this app writes — a v1 blob carries
 *     one supplicant-nonce placement where v2 carries every plausible one, so mixing
 *     them would let the native engine report "not found" for a hash the JVM verifier
 *     cracks;
 *  3. its own known-answer self-test passes on this device. A crypto core that is
 *     wrong on one CPU would report "not cracked" for a password that really is
 *     correct, and that is the one outcome this app must never present as a result.
 *
 * Anything that fails here is kept in [unavailableReason] and the caller falls back to
 * [JvmCrackEngine] rather than running a half-verified engine.
 */
object NativeCrypto {

    private external fun nativeSelfTest(): String?
    private external fun nativeMaterialVersion(): Int
    private external fun nativeCrackBatch(material: ByteArray, packedWords: ByteArray, threads: Int): IntArray
    private external fun nativeGpuDeviceName(): String
    private external fun nativeGpuUnavailableReason(): String
    private external fun nativeGpuSelfTest(): String
    private external fun nativeGpuCrackBatch(material: ByteArray, packedWords: ByteArray): IntArray

    /** Null when the native engine is safe to use; otherwise the reason it is not. */
    val unavailableReason: String? by lazy { evaluate() }

    private fun evaluate(): String? {
        try {
            System.loadLibrary("marauder_crypto")
        } catch (t: Throwable) {
            // UnsatisfiedLinkError on an ABI with no compiled library, SecurityException
            // on a restricted load. Both mean the same thing to the user: JVM engine only.
            return "native library could not be loaded: ${t.javaClass.simpleName}: ${t.message}"
        }
        val nativeVersion = try {
            nativeMaterialVersion()
        } catch (t: Throwable) {
            return "native library loaded but its material version could not be read: " +
                "${t.javaClass.simpleName}: ${t.message}"
        }
        if (nativeVersion != Material.VERSION) {
            return "native library reads material v$nativeVersion, this app writes " +
                "v${Material.VERSION} (rebuild needed; refusing to mix layouts)"
        }
        val failure = try {
            nativeSelfTest()
        } catch (t: Throwable) {
            return "native self-test could not run: ${t.javaClass.simpleName}: ${t.message}"
        }
        return failure?.let { "native self-test failed: $it" }
    }

    val available: Boolean get() = unavailableReason == null

    /** Verifies [words] against [targets]; returns (wordIndex, targetIndex) pairs. */
    fun crackBatch(targets: List<TargetIndex>, words: List<String>, threads: Int): IntArray {
        val material = Material.write(targets.map { it.material })
        return nativeCrackBatch(material, packWords(words), threads)
    }

    // --- the Vulkan back end ---------------------------------------------------------
    //
    // The GPU does PBKDF2 and the CPU does the verification, with the same material blob and
    // the same pair contract as [crackBatch], so there is one definition of "this candidate
    // matches this hash" in the whole app. Two of those is how a GPU run and a CPU run would
    // end up reporting different things about one hash line.

    /** "" when this device has a usable Vulkan compute device; otherwise the reason. Cheap, and cached in the native side too. */
    val gpuUnavailableReason: String by lazy {
        try {
            nativeGpuUnavailableReason()
        } catch (t: Throwable) {
            "GPU probe failed: ${t.javaClass.simpleName}: ${t.message}"
        }
    }

    /** The compute device that would be used, e.g. "Adreno (TM) 740"; "" when there is none. */
    val gpuDeviceName: String by lazy {
        try {
            nativeGpuDeviceName()
        } catch (t: Throwable) {
            ""
        }
    }

    val gpuPresent: Boolean get() = available && gpuUnavailableReason.isEmpty()

    @Volatile private var gpuSelfTestVerdict: String? = null
    @Volatile private var gpuSelfTestDone = false

    /**
     * Runs the GPU known-answer gate (published PMKID vector + agreement with this repo's own
     * CPU PBKDF2 over every salt alignment) and returns null when it passed.
     *
     * Not a `lazy` val: this is real GPU work — 25 PBKDF2 derivations — so it must not happen
     * while the crack screen is being drawn. The GPU engine calls it at the start of a run,
     * on its worker thread, and the verdict is cached here for the life of the process.
     */
    fun gpuSelfTest(): String? {
        if (!available) return "native library unavailable: $unavailableReason"
        if (gpuSelfTestDone) return gpuSelfTestVerdict
        val verdict = try {
            nativeGpuSelfTest().takeIf { it.isNotEmpty() }?.let { "GPU self-test failed: $it" }
        } catch (t: Throwable) {
            "GPU self-test could not run: ${t.javaClass.simpleName}: ${t.message}"
        }
        gpuSelfTestVerdict = verdict
        gpuSelfTestDone = true
        return verdict
    }

    /** [gpuSelfTest] already ran and passed? Used only for reporting, never to skip the gate. */
    val gpuSelfTestPassed: Boolean get() = gpuSelfTestDone && gpuSelfTestVerdict == null

    /** Same buffers, same pair contract as [crackBatch]; the PBKDF2 runs on the GPU. */
    fun gpuCrackBatch(targets: List<TargetIndex>, words: List<String>): IntArray {
        val material = Material.write(targets.map { it.material })
        return nativeGpuCrackBatch(material, packWords(words))
    }

    /** A target plus the session's hash-line index it came from, in transport order. */
    class TargetIndex(val hashIndex: Int, val material: com.marauder.extractor.TargetMaterial)

    /**
     * u32 big-endian length + bytes per word, i.e. the same length-prefixed encoding
     * the material TLV uses for its buffers.
     *
     * UTF-8, because that is what the JVM engine's `PBEKeySpec(password.toCharArray())`
     * turns a candidate into. Non-ASCII candidates are then expanded identically by both
     * engines — the disagreement that would otherwise appear as "the CPU run found it,
     * the JVM run did not".
     */
    private fun packWords(words: List<String>): ByteArray {
        val out = java.io.ByteArrayOutputStream(words.sumOf { it.length + 6 }.coerceAtLeast(64))
        for (w in words) {
            val b = w.toByteArray(Charsets.UTF_8)
            out.write(b.size ushr 24); out.write(b.size ushr 16 and 0xFF)
            out.write(b.size ushr 8 and 0xFF); out.write(b.size and 0xFF)
            out.write(b)
        }
        return out.toByteArray()
    }
}
