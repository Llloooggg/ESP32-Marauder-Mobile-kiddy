// The only door this app has to the device's graphics driver, and it is in another process.
//
// Why a second process: the driver is somebody else's code. It can refuse (no Vulkan device), it
// can be wrong (its hashes disagree with the CPU core), and it can die while being asked - all
// three are normal outcomes on the range of phones this app is sideloaded onto, and only the first
// two arrive as return values. A driver that segfaults takes the process down with it, and an
// Android crash dialog is not an answer about a device: the user cannot act on it, and the capture
// they were about to make is gone. Asked in a helper process, a dying driver is just another fact
// the app can state in words and fall back from.
//
// Nothing else in the app talks Vulkan. `com.marauder.mobile.crack.GpuProbeService` implements this
// in the helper; `com.marauder.mobile.crack.GpuCoreClient` is the caller in the app process.
package com.marauder.mobile.crack;

interface IGpuCore {

    /** Pid of the helper, so a hung call can be ended from the outside. */
    int pid();

    /**
     * Runs the known-answer gate (hashcat's published PMKID vector, plus agreement with this repo's
     * own CPU PBKDF2 over every salt alignment). Null when this device's driver produced correct
     * PMKs; otherwise why it did not, in the driver's own words.
     */
    String probe();

    /** The compute device this helper would use; "" when there is none. */
    String deviceName();

    /** "" when there is a usable Vulkan device; otherwise the reason there is not. */
    String unavailableReason();

    /**
     * Same buffers, same (wordIndex, targetIndex) result shape as the CPU engine's batch call.
     * Returns null when the call failed - and then [lastError] holds why, because "no match" (an
     * empty array) and "the GPU could not run" must not arrive at the caller as the same thing.
     */
    int[] crackBatch(in byte[] material, in byte[] packedWords);

    /** Why the last [crackBatch] returned null; "" when it did not fail. */
    String lastError();
}
