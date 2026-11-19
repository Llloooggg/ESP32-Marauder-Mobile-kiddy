package com.marauder.mobile.crack

/**
 * The wording of the engine report, kept apart from the Android objects that read it.
 *
 * Two reasons it is separate rather than inline in the application class. First, what may be said
 * about a device is a rule, and rules belong where they can be tested: which engine runs, and on
 * whose authority, is exactly the kind of claim this app is not allowed to get wrong. Second, these
 * lines are read on a phone at arm's length - a sentence that wraps into a paragraph reads as a
 * manual page, and the person is trying to start a crack, not read a document. So the length of the
 * sentences this app writes itself is a checked property, not a matter of taste.
 *
 * The parts that come from the device (a driver's own refusal, its name) are only ever appended
 * after a short prefix: they are the device speaking, and they must not be pushed off the screen by
 * our preamble.
 */
object EngineReport {

    /**
     * The longest a line may be and still be one line on the narrowest screen we run on. Measured on
     * this project's test phone: at the label size the report is drawn at, one line fits about 64
     * characters, so the budget is set below that with room for a different font.
     */
    const val LINE_LIMIT: Int = 62

    /** Two CPU sentences this app writes, both within the budget, for the test to compare against. */
    private const val CPU_FOR_AUTO = "used when the graphics can't be proven right here"
    private const val CPU_NATIVE_OK = "native engine, known-answer passed on this device"
    private const val CPU_FOR_GPU_RUN = "not used: this run asks the graphics cores"
    private const val GPU_NOT_ASKED = "not asked yet — nothing is said about an unasked driver"
    private const val GPU_READY = "ready:"
    private const val GPU_UNUSABLE = "unusable:"

    /**
     * The two lines the UI shows, in order: CPU first, then GPU.
     *
     * [verdict] is what this device's driver answered when it was asked, or `null` when it never was;
     * [nativeUnavailableReason] is why the native CPU engine is not in use, or `null` when it is.
     */
    fun lines(backend: Backend, verdict: ProbeVerdict?, nativeUnavailableReason: String?): List<String> {
        val cpu = when (backend) {
            Backend.GPU -> CPU_FOR_GPU_RUN
            Backend.AUTO -> CPU_FOR_AUTO
            else -> if (nativeUnavailableReason == null) CPU_NATIVE_OK
            else "JVM engine: $nativeUnavailableReason"
        }
        val gpu = when (val asked = verdict) {
            null -> GPU_NOT_ASKED
            // The device's name is the point of this line - it is what the claim is about - so the
            // preamble stays short enough that a real driver name still leaves one line. That the
            // asking happened in the helper process is stated where the design is explained (About),
            // not on every report line.
            is ProbeVerdict.Passed -> "$GPU_READY ${asked.deviceName} (known-answer passed)"
            is ProbeVerdict.Refused ->
                "$GPU_UNUSABLE ${asked.reason}" + (asked.deviceName?.let { " [$it]" } ?: "")
            is ProbeVerdict.Died -> "$GPU_UNUSABLE ${asked.words}"
        }
        return listOf("CPU: $cpu", "GPU: $gpu")
    }
}
