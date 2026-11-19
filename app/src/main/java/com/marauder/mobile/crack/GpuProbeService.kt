package com.marauder.mobile.crack

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.Process

/**
 * The app's one contact with the device's graphics driver, running in its own process
 * (`android:process=":gpucore"` in the manifest).
 *
 * This service is deliberately thin: it owns no policy, no state and no decisions. Every answer here
 * is what `NativeCrypto` says about this device right now. The policy - which backend a run uses,
 * what the screen says about it - stays in the app process, where it can be tested without a device.
 *
 * What running here buys is one thing only: when a vendor driver crashes while being asked a question
 * (measured on one phone: a SIGSEGV inside `vkUpdateDescriptorSets` during the known-answer probe),
 * the process that dies is this one. The app notices a dead binder, says so in words, and runs the
 * guesses on the phone's cores instead.
 */
class GpuProbeService : Service() {

    /**
     * Why the last batch call failed. Kept beside the call rather than thrown across the binder:
     * an AIDL call carries a return value, and the difference between "no match" (an empty array) and
     * "the GPU could not run" has to survive the trip. The client reads it immediately after a null
     * return, and it only ever serves one caller at a time.
     */
    private var lastError = ""

    override fun onBind(intent: Intent): IBinder = object : IGpuCore.Stub() {

        override fun pid(): Int = Process.myPid()

        override fun probe(): String? {
            // The CPU half of the library gates everything below it: the GPU path verifies its PMKs
            // with `verify_with_pmk` from that same library, so without it there is nothing to
            // compare the graphics cores against, and "we cannot check" is not the same as "correct".
            NativeCrypto.unavailableReason?.let { return "native library unusable here: $it" }
            return NativeCrypto.gpuSelfTest()
        }

        override fun deviceName(): String =
            if (NativeCrypto.available) NativeCrypto.gpuDeviceName else ""

        override fun unavailableReason(): String =
            if (!NativeCrypto.available) NativeCrypto.unavailableReason.orEmpty()
            else NativeCrypto.gpuUnavailableReason

        override fun crackBatch(material: ByteArray, packedWords: ByteArray): IntArray? {
            lastError = ""
            return try {
                NativeCrypto.gpuCrackRaw(material, packedWords)
            } catch (t: Throwable) {
                // Kept as a message the caller can show: the native side already separates "no match"
                // (an empty array) from a failure (an exception), and that separation is the
                // difference between an answer and a shrug.
                lastError = t.message ?: t.javaClass.simpleName
                null
            }
        }

        override fun lastError(): String = lastError
    }
}
