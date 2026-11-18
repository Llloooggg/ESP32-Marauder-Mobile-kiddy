package com.marauder.mobile.data

import android.content.Context
import android.net.Uri
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/** Wordlist sources that are part of the APK (copied out on first run). */
private const val ASSET_DIR = "wordlists"

/** Errors worth showing to the user verbatim. */
class WordlistException(message: String) : Exception(message)

/**
 * The Android-facing half of the wordlist library: seeds the list shipped inside the
 * APK, imports a file the user picks (SAF), and downloads a plain-text list from a
 * direct URL (GitHub raw files, wordlist mirrors) with redirect handling.
 */
class WordlistsRepository(private val context: Context) {

    val store: WordlistStore = WordlistStore(File(context.filesDir, "wordlists"))

    /** Copies the built-in list (and its licence note) out of assets exactly once. */
    fun seedBuiltInIfNeeded() {
        if (store.isSeeded()) return
        runCatching {
            val assets = context.assets.list(ASSET_DIR)?.toList().orEmpty()
            for (name in assets) {
                val target = if (name.startsWith("LICENSE")) name else WordlistStore.BUILTIN_PREFIX + name
                if (store.exists(target)) continue
                context.assets.open("$ASSET_DIR/$name").use { input ->
                    if (name.startsWith("LICENSE")) {
                        store.file(target).outputStream().use { out -> input.copyTo(out) }
                    } else {
                        store.install(target, input)
                    }
                }
            }
        }
        store.markSeeded()
    }

    /** Put the built-in list back after the user deleted it. */
    fun restoreBuiltIn() {
        store.clearSeeded()
        seedBuiltInIfNeeded()
    }

    /** Import a user-picked document (SAF). Returns null when nothing was written. */
    fun importFrom(uri: Uri, displayName: String? = null): Wordlist? {
        val name = displayName ?: queryDisplayName(uri) ?: "wordlist.txt"
        return context.contentResolver.openInputStream(uri)?.use { input ->
            store.install(name, input)
        }
    }

    /**
     * Download a plain-text wordlist straight into the library. Follows redirects
     * (raw.githubusercontent and mirrors bounce off CDNs), streams to disk so a
     * 100 MB list never has to fit in memory, and refuses anything that is not
     * http(s).
     */
    fun download(startUrl: String, onProgress: (done: Long, total: Long) -> Unit): Wordlist {
        val start = startUrl.trim()
        if (!start.startsWith("http://", ignoreCase = true) && !start.startsWith("https://", ignoreCase = true)) {
            throw WordlistException("Only direct http(s) links to a plain-text wordlist are supported")
        }
        val head = store.usableSpace()
        if (head in 1 until 20_000_000L) {
            throw WordlistException("Less than 20 MB free on this phone — the download would not fit")
        }

        var url = URL(start)
        var redirects = 0
        while (true) {
            val conn = (url.openConnection() as HttpURLConnection).apply {
                instanceFollowRedirects = false
                connectTimeout = 15_000
                readTimeout = 30_000
                setRequestProperty("User-Agent", "MarauderMobile-Wordlists")
                setRequestProperty("Accept", "text/plain, application/octet-stream")
            }
            try {
                when (val code = conn.responseCode) {
                    HttpURLConnection.HTTP_OK -> {
                        val total = conn.contentLengthLong
                        val name = url.path.substringAfterLast('/').ifBlank { "wordlist.txt" }
                        conn.inputStream.use { input ->
                            val counted = ProgressStream(input, total) { done, len -> onProgress(done, len) }
                            return store.install(name, counted)
                                ?: throw WordlistException("The downloaded file was empty")
                        }
                    }

                    in REDIRECT_CODES -> {
                        val location = conn.getHeaderField("Location")
                            ?: throw WordlistException("Redirect without a Location header")
                        if (++redirects > MAX_REDIRECTS) throw WordlistException("Too many redirects")
                        url = URL(url, location)
                    }

                    else -> throw WordlistException("Download failed (HTTP $code)")
                }
            } finally {
                conn.disconnect()
            }
        }
    }

    /** Guessable default: the built-in list, otherwise the biggest one available. */
    fun preferredWordlist(): Wordlist? = store.list().firstOrNull()

    private fun queryDisplayName(uri: Uri): String? = try {
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (index >= 0 && cursor.moveToFirst()) cursor.getString(index) else null
        }
    } catch (e: Exception) {
        null
    }

    private companion object {
        val REDIRECT_CODES = setOf(
            HttpURLConnection.HTTP_MOVED_PERM,
            HttpURLConnection.HTTP_MOVED_TEMP,
            HttpURLConnection.HTTP_SEE_OTHER,
            307,
            308,
        )
        const val MAX_REDIRECTS = 5
    }
}

/** Reports bytes streamed so far (and the expected total, when the server sends one). */
private class ProgressStream(
    private val source: java.io.InputStream,
    private val total: Long,
    private val onRead: (done: Long, total: Long) -> Unit,
) : java.io.FilterInputStream(source) {

    private var done = 0L

    override fun read(): Int {
        val b = source.read()
        if (b >= 0) report(1)
        return b
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        val n = source.read(b, off, len)
        if (n > 0) report(n)
        return n
    }

    private fun report(delta: Int) {
        done += delta
        onRead(done, total)
    }
}
