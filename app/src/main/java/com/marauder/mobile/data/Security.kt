package com.marauder.mobile.data

/**
 * Firmware `WIFI_SECURITY_*` codes (WiFiScan.h) mapped to labels the UI shows.
 * Keep the numbers in sync with the firmware defines.
 */
object Security {

    fun label(code: Int): String = when (code) {
        0 -> "Open"
        1 -> "WEP"
        2 -> "WPA"
        3 -> "WPA2"
        4 -> "WPA3"
        5 -> "WPA/WPA2"
        6 -> "WPA2 Enterprise"
        7 -> "WPA3 Enterprise"
        8 -> "WAPI"
        else -> "Unknown"
    }

    /** Handshake/PMKID capture is meaningful for the WPA family, not open/enterprise nets. */
    fun handshakable(code: Int): Boolean = code in 1..5

    /** Enterprise networks need credentials, not a PSK crack. */
    fun enterprise(code: Int): Boolean = code == 6 || code == 7
}
