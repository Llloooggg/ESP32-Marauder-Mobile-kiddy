package com.marauder.mobile.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The SAE/WPA3 verdict has to survive the round trip through the artifact's metadata,
 * because that is the only place the cracker can learn that a hash is not a password
 * hash at all.
 */
class KeyManagementTest {

    private val meta = mapOf(
        KeyManagement.META to
            "AA:BB:CC:DD:EE:FF=WPA3-SAE only · offline cracking does not apply [SAE] · 3 SAE frame(s) on air; " +
            "11:22:33:44:55:66=WPA2-Personal · crackable [PSK]",
        KeyManagement.SAE_ONLY to "AA:BB:CC:DD:EE:FF",
        KeyManagement.SAE_FRAMES to "3",
    )

    @Test
    fun verdictsAreReadBackPerNetwork() {
        val v = KeyManagement.verdicts(meta)
        assertEquals(2, v.size)
        assertEquals("11:22:33:44:55:66", v.sortedBy { it.bssid }[0].bssid)
        val sae = v.first { it.bssid == "AA:BB:CC:DD:EE:FF" }
        assertTrue(sae.saeOnly)
        assertFalse(v.first { it.bssid == "11:22:33:44:55:66" }.saeOnly)
        assertTrue(sae.label.contains("3 SAE frame(s) on air"))
    }

    @Test
    fun malformedOrMissingMetaYieldsNoVerdictsInsteadOfGuesses() {
        assertTrue(KeyManagement.verdicts(emptyMap()).isEmpty())
        assertTrue(KeyManagement.verdicts(mapOf(KeyManagement.META to "garbage")).isEmpty())
        assertTrue(KeyManagement.verdicts(mapOf(KeyManagement.META to "=no bssid")).isEmpty())
        assertTrue(KeyManagement.verdicts(mapOf(KeyManagement.META to "AA:BB=")).isEmpty())
        assertTrue(KeyManagement.saeOnly(emptyMap()).isEmpty())
    }

    @Test
    fun warningNamesTheAimedNetworkWhenThatIsTheSaeOne() {
        val text = KeyManagement.explainSae(listOf("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff")
        assertNotNull(text)
        assertTrue(text!!.contains("aimed at (AA:BB:CC:DD:EE:FF)", ignoreCase = true))
        assertTrue(text.contains("dragonfly"))
        assertTrue(text.contains("sniffsae"))
    }

    @Test
    fun warningStillAppearsWhenAnotherCapturedNetworkIsTheSaeOne() {
        val text = KeyManagement.explainSae(listOf("AA:BB:CC:DD:EE:FF"), "11:22:33:44:55:66")
        assertNotNull(text)
        assertTrue(text!!.startsWith("A network in this capture"))
        assertNull(KeyManagement.explainSae(emptyList(), "11:22:33:44:55:66"))
        assertNull(KeyManagement.explainSae(emptyList(), null))
    }
}
