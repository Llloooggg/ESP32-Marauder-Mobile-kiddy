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

    /**
     * SAE (WPA3) appeared in this network's AKM list. Read the firmware's own
     * detection tree (WiFiScan.cpp): code 4/7 is set as soon as an AKM suite of type
     * 8 shows up, *before* the RSN checks — so it also covers WPA2/WPA3 transition
     * mode, where a PSK fallback exists and a captured handshake is still crackable.
     *
     * That is why this is only "SAE advertised". Whether a hash from this network can
     * be recovered is decided per network by the extractor, which sees the whole AKM
     * list and any dragonfly frames on air (`KeyManagement` on the artifact).
     */
    fun offersSae(code: Int): Boolean = code == 4 || code == 7
}
