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

/**
 * Line rates worth offering for `jsonbaud`, with what they buy and risk.
 *
 * The distinction that matters is the board's USB implementation, and the firmware's own
 * interface document is explicit about it (`JSON_SERIAL_INTERFACE.md` §5): the rate means
 * something on a real UART bridge (CH340, CP210x), while on the ESP32-S2/S3's built-in USB
 * (`usb_serial_jtag` / native CDC) `updateBaudRate()` is a no-op — the link runs at USB speed
 * whatever was asked, and the `{"t":"baud"}` answer arrives anyway. So a confirmed change on
 * such a board proves the command worked, not that bytes move faster.
 */
data class LineRateOption(val rate: Int, val label: String, val hint: String) {

    companion object {
        /**
         * `0` means "leave the board alone".
         *
         * Each description is one short line: these sit in a settings list where a person is choosing a
         * number, not reading a manual. What stays in them is what decides the choice - what a given
         * bridge can actually hold, and that a board on its own USB ignores the value entirely.
         */
        val OPTIONS = listOf(
            LineRateOption(0, "115200 (board default)", "what every bridge boots at; enough for handshakes and PMKID"),
            LineRateOption(460800, "460800", "~4x more bytes on a CP210x/CH340 bridge; native-USB boards run at USB speed anyway"),
            LineRateOption(921600, "921600", "~8x on a good CP210x; CH340 often cannot hold it; native-USB boards ignore it"),
            LineRateOption(1500000, "1500000", "heavy pcap over a good UART bridge and cable; no effect on native USB"),
            LineRateOption(2000000, "2000000", "the firmware's maximum, for fast UART bridges only; never a fix on native USB"),
        )

        fun label(rate: Int): String = OPTIONS.firstOrNull { it.rate == rate }?.label ?: "$rate"
    }
}

