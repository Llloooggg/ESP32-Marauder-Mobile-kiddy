package com.marauder.mobile.data

import com.marauder.mobile.protocol.DeviceMessage
import org.junit.Assert.assertEquals
import org.junit.Test

/** CSV shape for the list exports that become library artifacts. */
class ListCsvTest {

    @Test
    fun apsCsvQuotesSeparatorsAndMapsSecurity() {
        val rows = listOf(
            DeviceMessage.Ap(1, 6, -40, false, 120, 3, false, 4, "aa:bb:cc:dd:ee:ff", "Cafe, Wi-Fi"),
            DeviceMessage.Ap(2, 1, -70, false, 10, 0, false, 0, "00:11:22:33:44:55", "open"),
        )
        val csv = ListCsv.aps(rows).trim().lines()
        assertEquals("index,essid,bssid,channel,rssi,security,wps,stations,packets,selected", csv[0])
        assertEquals("1,\"Cafe, Wi-Fi\",aa:bb:cc:dd:ee:ff,6,-40,WPA2,false,4,120,false", csv[1])
        assertEquals(3, csv.size)
        assertEquals("2,open,00:11:22:33:44:55,1,-70,Open,false,0,10,false", csv[2])
    }

    @Test
    fun dronesCsvWritesDecimalCoordinatesOnlyWhenValid() {
        val rows = listOf(
            DeviceMessage.Rid(1, "aa:bb:cc:dd:ee:ff", "UAS-1", "OP-1", 512345678L, -123456789L,
                12.5, 8.0, 90, -60, 2, 30, true),
            DeviceMessage.Rid(2, "11:22:33:44:55:66", "UAS-2", "OP-2", 0, 0,
                0.0, 0.0, 0, -80, 2, 5, false),
        )
        val lines = ListCsv.drones(rows).trim().lines()
        assertEquals(
            "index,mac,uas_id,operator,ua_type,lat,lon,alt_m,speed_mps,direction_deg,rssi,packets",
            lines[0],
        )
        assertEquals("1,aa:bb:cc:dd:ee:ff,UAS-1,OP-1,2,51.2345678,-12.3456789,12.5,8.0,90,-60,30", lines[1])
        assertEquals("2,11:22:33:44:55:66,UAS-2,OP-2,2,,,0.0,0.0,0,-80,5", lines[2])
    }

    @Test
    fun credsCsvKeepsBothFields() {
        val csv = ListCsv.creds(listOf(DeviceMessage.Cred("admin", "p,1"), DeviceMessage.Cred("u", "")))
        assertEquals("user,password", csv.lines()[0])
        assertEquals("admin,\"p,1\"", csv.lines()[1])
        assertEquals("u,", csv.lines()[2])
    }
}
