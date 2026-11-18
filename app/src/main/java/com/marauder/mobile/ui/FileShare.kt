package com.marauder.mobile.ui

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File

/**
 * Hands a private app file to another app through the manifest FileProvider.
 * Returns false (rather than throwing) when the file is not shareable, so the UI
 * can say so instead of crashing.
 */
fun shareFile(context: Context, file: File): Boolean = try {
    val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "application/octet-stream"
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(send, file.name).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    true
} catch (e: Exception) {
    false
}

/** Streams a capture into a user-picked document (SAF) so it can leave the app entirely. */
fun copyToDocument(context: Context, file: File, uri: android.net.Uri): Boolean = try {
    context.contentResolver.openOutputStream(uri)?.use { out ->
        file.inputStream().use { input -> input.copyTo(out) }
    } != null
} catch (e: Exception) {
    false
}
