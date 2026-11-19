package com.marauder.mobile.crack

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.DeadObjectException
import android.os.IBinder
import android.os.Process
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** A GPU run that cannot go on, with the sentence that says why. Never an empty result. */
class GpuUnavailable(reason: String) : IllegalStateException(reason)

/**
 * What asking this device's graphics driver produced. Three outcomes, and the third is the reason the
 * asking happens in another process at all.
 */
sealed interface ProbeVerdict {
    /** This device's driver produced correct PMKs here, and named itself. */
    data class Passed(val deviceName: String) : ProbeVerdict

    /**
     * The driver is not usable: there is no Vulkan device ([deviceName] is null and [reason] is what
     * the loader said), or a device that did name itself produced wrong PMKs ([deviceName] is that
     * name). Kept apart because the sentence the user needs is different: one phone has no such
     * hardware, another has hardware that cannot be trusted.
     */
    data class Refused(val reason: String, val deviceName: String? = null) : ProbeVerdict

    /**
     * The process that asked the driver went away. A vendor driver crashing while being asked is
     * normal across the range of phones this app is sideloaded onto, and it is the one outcome the
     * app cannot catch - only survive by not being in the process where it happens. The words here
     * are what the user reads; the app keeps running on the phone's cores.
     */
    data class Died(val words: String) : ProbeVerdict
}

/**
 * Asking this device about its graphics side. Implemented by [GpuCoreClient] over a binder; an
 * interface so that the rules built on top of it - which backend a run may use, what the screen may
 * claim - can be tested with no phone attached and no driver that might not exist.
 */
interface GpuCore {
    /** What the last probe said, or null when nothing has been asked. Asks nothing itself. */
    fun lastVerdict(): ProbeVerdict?

    /**
     * This device, asked once. A later call repeats the remembered answer unless the helper has since
     * gone away, which changes what can be claimed. Blocks: call it from a worker thread.
     */
    fun probe(timeoutMs: Long = 30_000L): ProbeVerdict

    /** One batch of candidates. Throws [GpuUnavailable] rather than returning nothing. */
    fun crackBatch(material: ByteArray, packedWords: ByteArray): IntArray

    /** Pid of the helper process, 0 when there is none. A diagnostic: it is what a timeout ends. */
    fun helperPid(): Int

    /** Lets go of the helper. A later call rebinds; the remembered verdict stays. */
    fun shutdown()
}

/**
 * The caller's half of [IGpuCore]: binds to [GpuProbeService] in the `:gpucore` process, asks it
 * things, and turns whatever comes back - an answer, a refusal, a dead binder, a driver that never
 * answers - into a [ProbeVerdict].
 *
 * Two rules it exists to keep:
 *
 *  * **this process never touches the graphics driver**, not for the probe and not for a batch. That
 *    is what makes a vendor driver's crash survivable instead of fatal;
 *  * **no claim without a question.** [lastVerdict] only reports; it never asks, so the crack screen
 *    can state what is known without spending GPU work while drawing a frame. Before anything has
 *    been asked it returns null, and the screen says "not asked yet" rather than guessing.
 *
 * A verdict is remembered for the life of this process: it is a fact about this device and driver,
 * not something that changes between runs. It is also the only copy, because the process that
 * produced it can be gone by the next call - and when that happens, a remembered "it works" is no
 * longer something this app can act on, so the verdict becomes [ProbeVerdict.Died]. The app may have
 * proven the hardware once and still be unable to use it; claiming otherwise would be a claim about a
 * process that does not exist.
 *
 * Every method here blocks. The crack engine already runs on a worker thread, and nothing in the UI
 * path calls these: reporting reads the remembered answer.
 */
class GpuCoreClient(private val context: Context) : GpuCore {

    @Volatile private var api: IGpuCore? = null
    @Volatile private var connection: ServiceConnection? = null
    @Volatile private var helperPid = 0

    /** Set when the helper answered at least once and then went away, or was ended for hanging. */
    @Volatile private var deadWords: String? = null

    /** Set when it never came up at all: no process, no death - a refusal with a reason. */
    @Volatile private var startFailure: String? = null

    @Volatile private var verdict: ProbeVerdict? = null

    override fun lastVerdict(): ProbeVerdict? = verdict

    @Synchronized
    override fun probe(timeoutMs: Long): ProbeVerdict {
        deadWords?.let { return remember(ProbeVerdict.Died(it)) }
        startFailure?.let { return remember(ProbeVerdict.Refused(it)) }
        verdict?.let { cached ->
            // A remembered "this driver is correct" is only a claim while the process that learned it
            // can still be reached. Once it cannot, the honest answer is that the graphics side is not
            // usable here for the rest of this session - not a promise about a process that is gone.
            if (cached is ProbeVerdict.Passed) {
                val binder = api?.asBinder()
                if (binder != null && !binder.pingBinder()) {
                    return remember(ProbeVerdict.Died(markDead("is gone")))
                }
            }
            return cached
        }

        val core = bind()
            ?: return remember(
                ProbeVerdict.Refused(startFailure ?: "the process that asks the graphics driver could not be started"),
            )

        val answer = AtomicReference<ProbeVerdict?>(null)
        val worker = Thread({
            answer.set(
                try {
                    val why = core.probe()
                    val device = readName(core).ifEmpty { null }
                    when {
                        why == null && device != null -> ProbeVerdict.Passed(readName(core))
                        why == null -> ProbeVerdict.Refused(
                            readAbsent(core).ifBlank { "the driver answered, but named no compute device" },
                        )
                        else -> ProbeVerdict.Refused(why, device)
                    }
                } catch (d: DeadObjectException) {
                    ProbeVerdict.Died(markDead("stopped answering"))
                } catch (t: Throwable) {
                    ProbeVerdict.Refused("asking this driver failed: ${t.message ?: t.javaClass.simpleName}")
                }
            )
        }, "gpu-probe")
        worker.start()
        worker.join(timeoutMs)
        if (answer.get() == null) {
            // A driver that never answers would otherwise hold a run open forever. Ending the helper
            // ends the blocked call - the binder returns DeadObjectException - and this process keeps
            // itself to report the outcome from.
            if (helperPid != 0) Process.killProcess(helperPid)
            return remember(ProbeVerdict.Died(markDead("did not answer within ${timeoutMs / 1000} s; the process asking it was ended")))
        }
        return remember(answer.get()!!)
    }

    @Synchronized
    override fun crackBatch(material: ByteArray, packedWords: ByteArray): IntArray {
        val core = api ?: bind()
            ?: throw GpuUnavailable(
                deadWords ?: startFailure
                    ?: "the process that asks the graphics driver could not be started",
            )
        return try {
            val hits = core.crackBatch(material, packedWords)
            if (hits == null) {
                throw GpuUnavailable(
                    runCatching { core.lastError() }.getOrNull()?.takeIf { it.isNotBlank() }
                        ?: "the graphics process returned nothing and did not say why",
                )
            }
            hits
        } catch (d: DeadObjectException) {
            throw GpuUnavailable(markDead("stopped in the middle of a run"))
        }
    }

    override fun helperPid(): Int = helperPid

    @Synchronized
    override fun shutdown() {
        connection?.let { runCatching { context.unbindService(it) } }
        connection = null
        api = null
    }

    // --- internals ------------------------------------------------------------

    private fun bind(): IGpuCore? {
        api?.let { return it }
        if (deadWords != null || startFailure != null) return null
        val ready = CountDownLatch(1)
        var connected: IGpuCore? = null
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                val proxy = IGpuCore.Stub.asInterface(service)
                runCatching {
                    service.linkToDeath({ markDead("the process that asks your graphics driver died") }, 0)
                }
                helperPid = runCatching { proxy.pid() }.getOrDefault(0)
                connected = proxy
                ready.countDown()
            }

            override fun onServiceDisconnected(name: ComponentName) {
                markDead("the process that asks your graphics driver died")
                ready.countDown()
            }

            override fun onBindingDied(name: ComponentName) {
                markDead("the system ended the process that asks your graphics driver")
                ready.countDown()
            }

            override fun onNullBinding(name: ComponentName) {
                startFailure = "the process that asks your graphics driver refused to answer"
                ready.countDown()
            }
        }
        if (!context.bindService(Intent(context, GpuProbeService::class.java), conn, Context.BIND_AUTO_CREATE)) {
            startFailure = "this system would not start the process that asks your graphics driver"
            return null
        }
        connection = conn
        if (!ready.await(BIND_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            runCatching { context.unbindService(conn) }
            connection = null
            startFailure = "the process that asks your graphics driver did not come up within ${BIND_TIMEOUT_MS / 1000} s"
            return null
        }
        return connected.also { api = it }
    }

    private fun readName(core: IGpuCore): String =
        runCatching { core.deviceName() }.getOrDefault("").orEmpty()

    private fun readAbsent(core: IGpuCore): String =
        runCatching { core.unavailableReason() }.getOrDefault("").orEmpty()

    /** Records that the helper is gone and returns the whole sentence for the caller to show. */
    private fun markDead(what: String): String {
        api = null
        val words = if (what.contains("graphics")) what else "the process that asks your graphics driver $what"
        deadWords = words
        return words
    }

    private fun remember(v: ProbeVerdict): ProbeVerdict = v.also { verdict = it }

    private companion object {
        /** Binding starts a process; past this the device is not coming back on this call. */
        const val BIND_TIMEOUT_MS = 10_000L
    }
}
