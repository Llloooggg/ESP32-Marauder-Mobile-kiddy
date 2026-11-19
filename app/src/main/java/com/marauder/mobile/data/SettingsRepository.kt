package com.marauder.mobile.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "settings")

/**
 * App-level preferences, persisted with Jetpack DataStore so they survive
 * process death and reboot: theme, the authorised-use notice, the Lab gate and
 * the serial line rate the app asks the board for.
 */
class SettingsRepository(context: Context) {

    private val store = context.applicationContext.dataStore

    /** `true` = dark theme (the default). */
    val darkTheme: Flow<Boolean> = store.data.map { it[DARK_THEME] ?: true }

    suspend fun setDarkTheme(dark: Boolean) {
        store.edit { it[DARK_THEME] = dark }
    }

    /** Whether the user has accepted the authorised-use notice (asked once per install). */
    val termsAccepted: Flow<Boolean> = store.data.map { it[TERMS_ACCEPTED] ?: false }

    suspend fun setTermsAccepted(accepted: Boolean) {
        store.edit { it[TERMS_ACCEPTED] = accepted }
    }

    /**
     * Extract hashcat-22000 hashes as soon as a capture closes. On by default —
     * it is what lets the library tell you straight away whether a capture is
     * worth cracking (and why not, when it is not).
     */
    val autoAnalyze: Flow<Boolean> = store.data.map { it[AUTO_ANALYZE] ?: true }

    suspend fun setAutoAnalyze(enabled: Boolean) {
        store.edit { it[AUTO_ANALYZE] = enabled }
    }

    /**
     * USB-serial line rate to ask the board for, as `jsonbaud <rate>`.
     * `0` (the default) = leave the board at its own 115200.
     *
     * Deliberately opt-in: the common CH340 bridge cannot always sustain high
     * rates — the ESP32 switches, the bridge corrupts the link, and the board
     * then speaks a rate the phone is not listening at until it is reset. The
     * app therefore verifies the board's `{"t":"baud"}` confirmation before it
     * believes the change, and a replug always brings the board back to 115200.
     */
    val lineRate: Flow<Int> = store.data.map { it[LINE_RATE] ?: 0 }

    suspend fun setLineRate(rate: Int) {
        store.edit { it[LINE_RATE] = rate }
    }

    private companion object {
        val DARK_THEME = booleanPreferencesKey("dark_theme")
        val TERMS_ACCEPTED = booleanPreferencesKey("terms_accepted")
        val AUTO_ANALYZE = booleanPreferencesKey("auto_analyze")
        val LINE_RATE = intPreferencesKey("line_rate")
    }
}

/** Line rates worth offering for `jsonbaud`, with what they buy and risk. */
data class LineRateOption(val rate: Int, val label: String, val hint: String) {

    companion object {
        /** `0` means "leave the board alone". */
        val OPTIONS = listOf(
            LineRateOption(0, "115200 (board default)", "Rock solid on every bridge, including CH340. Enough for handshakes and PMKID captures."),
            LineRateOption(460800, "460800", "Roughly 4× the bytes through. Usually fine on CP210x / native USB-CDC boards."),
            LineRateOption(921600, "921600", "Roughly 8×. Good on CP210x and ESP32-S2/S3 native USB; CH340 often cannot hold it."),
            LineRateOption(1500000, "1500000", "Maximum sane rate for heavy pcap streaming. Needs a good bridge and cable."),
            LineRateOption(2000000, "2000000", "Maximum the firmware accepts. Only try this on native USB-CDC boards."),
        )

        fun label(rate: Int): String = OPTIONS.firstOrNull { it.rate == rate }?.label ?: "$rate"
    }
}

