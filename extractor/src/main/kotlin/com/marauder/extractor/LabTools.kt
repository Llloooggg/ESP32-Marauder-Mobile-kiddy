package com.marauder.extractor

import java.io.File

/**
 * Command-line entry points for running this module's real pipeline by hand, on a
 * real capture, without going through the Android app.
 *
 * Why these live in the module (and not in a scratch script): the whole point of
 * the extractor and the cracker is that they must work on captures that come off
 * hardware — gapped, padded, half-lost over USB. Unit tests can only describe the
 * frames the tests invented. These tools close that gap: point them at a pcap the
 * board actually wrote and the same code paths the app runs report what they found.
 *
 * Nothing here is part of the app's runtime; both are `main` functions wired to the
 * `extractPcap` / `crackHash` Gradle tasks.
 *
 * Usage:
 *   ./gradlew :extractor:extractPcap -PtoolArgs="C:/path/capture.pcap -o out.22000.txt"
 *   ./gradlew :extractor:crackHash   -PtoolArgs="out.22000.txt wordlist.txt"
 */
object ExtractTool {

    @JvmStatic
    fun main(args: Array<String>) {
        val path = args.firstOrNull { !it.startsWith("-") }
        if (path == null) {
            println("usage: ExtractTool <capture.pcap> [-o <hash-file>] [BSSID=ESSID ...]")
            println("  BSSID=ESSID hints supply SSIDs the capture never carried (the PBKDF2 salt).")
            return
        }
        val outFile = argValue(args, "-o")
        val hints = LinkedHashMap<String, String>()
        args.filter { it.contains('=') && !it.startsWith("-") }.forEach {
            val at = it.indexOf('=')
            hints[it.substring(0, at).trim().uppercase()] = it.substring(at + 1)
        }

        val file = File(path)
        if (!file.isFile) {
            println("NOT A FILE: $path")
            return
        }
        println("capture : ${file.absolutePath} (${file.length()} bytes)")

        val report = file.inputStream().use { Extractor.extract(it, hints) }

        println("--- frames/records ------------------------------------------------")
        println("records parsed   : ${report.recordsParsed}")
        println("beacons          : ${report.beacons}")
        println("EAPOL key frames : ${report.eapolFrames}  (M1 ${report.m1Frames} / M2 ${report.m2Frames} / " +
            "M3 ${report.m3Frames} / M4 ${report.m4Frames} / PMKID ${report.pmkidFrames})")
        println("usable pairs     : ${report.pairs}  (no AP message: ${report.pairsNoApMessage})")
        println("bad records      : ${report.badRecords}  resyncs: ${report.resyncs}  lost bytes: ${report.lostBytes}")
        println("short EAPOL      : ${report.shortEapol}   dropped for missing SSID: ${report.pairsNoSsid}" +
            "   SSID from hints: ${report.ssidFromScan}")
        println("SAE auth frames  : ${report.saeAuthFrames}   SAE-only hashes: ${report.saeOnlyHashes}")

        println("--- networks (key management as the capture shows it) -------------")
        if (report.networks.isEmpty()) println("  (no network identified in this capture)")
        report.networks.forEach { n ->
            val akm = if (n.akmLabels.isEmpty()) "no RSN element" else n.akmLabels.joinToString("+")
            println("  " + n.bssid.padEnd(20) + n.essid.padEnd(24) + n.mode.toString().padEnd(15) +
                akm.padEnd(30) + "sae_frames=" + n.saeAuthFrames)
        }

        println("--- hashes (hashcat mode 22000) ----------------------------------")
        report.hashes.forEachIndexed { i, h ->
            println("  [$i] ${h.kind} essid=\"${h.essid}\" ap=${h.bssid} sta=${h.sta} keyver=${h.keyver} " +
                "mp=${h.messagePair} security=${h.security}")
            println("      ${h.line}")
        }
        if (report.hashes.isEmpty()) println("  (none)")

        println("--- why ---------------------------------------------------------")
        if (report.notes.isEmpty()) println("  (no notes)")
        report.notes.forEach { println("  - $it") }

        if (outFile != null) {
            val out = File(outFile)
            out.writeText(report.hashes.joinToString("\n") + if (report.hashes.isEmpty()) "" else "\n")
            println("wrote ${report.hashes.size} hash line(s) -> ${out.absolutePath}")
        }
    }

    private fun argValue(args: Array<String>, key: String): String? {
        val at = args.indexOf(key)
        return if (at >= 0 && at + 1 < args.size) args[at + 1] else null
    }
}

/**
 * Runs the module's own cracker over a 22000 file and a wordlist — the second half
 * of the pipeline. This is what makes a known-answer check on a hardware capture
 * possible: extract, crack, and see the recovered password come back out of the same
 * code the phone uses.
 *
 * A miss here is reported with the per-hash inspection, because "the password is not
 * in the list" and "this line cannot be cracked at all" are different answers and the
 * app must never blur them.
 */
object CrackTool {

    @JvmStatic
    fun main(args: Array<String>) {
        if (args.size < 2) {
            println("usage: CrackTool <hashes.22000> <wordlist.txt> [...]")
            return
        }
        val hashFile = File(args[0])
        if (!hashFile.isFile) {
            println("NOT A FILE: ${args[0]}")
            return
        }
        val lists = args.drop(1).map { File(it) }
        lists.filter { !it.isFile }.forEach { println("NOT A FILE: $it") }
        val usable = lists.filter { it.isFile }
        if (usable.isEmpty()) return

        val lines = hashFile.readLines().map { it.trim() }.filter { it.isNotEmpty() }
        if (lines.isEmpty()) {
            println("no hash lines in ${hashFile.name} — extraction found nothing to crack")
            return
        }

        val targets = lines.map { CrackCore.parse(it) }
        println("targets: ${lines.size} line(s), parsed ${targets.count { it != null }}")
        targets.forEachIndexed { i, t ->
            val insp = CrackCore.inspect(lines[i])
            println("  [$i] ${insp.label} · ap=${insp.ap} sta=${insp.sta} keyver=${insp.keyver} mp=${insp.messagePair} " +
                "eapol=${insp.eapolBytes}B mic=${insp.micHex} anonce=${insp.anonceHex.take(16)}…")
            if (t == null) println("      UNPARSEABLE LINE")
            else if (!insp.crackable) println("      why not crackable: ${insp.problems.joinToString("; ")}")
            insp.notes.forEach { println("      note: $it") }
        }

        val words = ArrayList<String>(1 shl 16)
        usable.forEach { f -> f.forEachLine { w -> if (w.isNotEmpty()) words.add(w) } }
        val total = words.size.toLong() * lines.size
        println("wordlist words: ${words.size} · candidate checks: $total")

        val started = System.nanoTime()
        val found = HashMap<Int, String>()
        var done = 0L
        val allTargets = targets.count { it != null }
        var stoppedEarly = false
        for (w in words) {
            for (i in targets.indices) {
                done++
                val t = targets[i] ?: continue
                if (found.containsKey(i)) continue
                if (!t.verify(w)) continue
                found[i] = w
                println("FOUND [$i] essid=\"${t.essidText}\" -> password \"$w\"")
            }
            if (found.size == allTargets) { stoppedEarly = true; break }
        }
        val secs = (System.nanoTime() - started) / 1_000_000_000.0
        println("--- result --------------------------------------------------------")
        println("checked   : $done candidates in ${"%.2f".format(secs)}s  (${"%.0f".format(done / secs)} c/s)" +
            if (stoppedEarly) "  (stopped once every target was recovered)" else "")
        if (found.isEmpty()) {
            println("no password recovered. If the password really is correct, the per-hash" +
                " problems above are the answer — mode 22000 needs the exact SSID as salt and a" +
                " PSK-family AKM; an SAE-only network is not a password hash at all.")
        }
        found.forEach { (i, w) -> println("recovered [$i] -> \"$w\"") }
    }
}
