package com.marauder.mobile.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which screens are reachable with no board, and which honestly need one.
 *
 * This is a product rule, not an implementation detail, and it used to be invisible: the gate sent
 * anyone without a link to the connect screen from anywhere, so a week-old capture sitting on the phone
 * could not be opened, cracked or measured against a wordlist until a cable appeared. The rule is now
 * written down as data, and this test is what stops it from drifting: a screen added tomorrow is either
 * declared offline-capable or counted as board-only, and the second option is the safe one.
 */
class RoutesTest {

    private val offlinePath = listOf(
        Routes.HOME,                       // the screen the app opens on
        Routes.CONNECT,                    // where the link is made, by definition
        Routes.ARTIFACTS,                  // the library of what this phone already saved
        "${Routes.ARTIFACT}/{name}",
        Routes.WORDLISTS,
        "${Routes.CRACK}/{name}",
        Routes.SETTINGS,
        Routes.ABOUT,
    )

    private val boardOnly = listOf(
        Routes.SCAN,
        "${Routes.AP}/{bssid}",
        "${Routes.MISSION}/{id}",
        "${Routes.MENU}/{id}",
        "${Routes.LIST}/{type}",
        Routes.CONSOLE,
        "${Routes.ANALYZER}/{kind}/{cmd}",
        "${Routes.LIVE}/{title}/{cmd}",
        Routes.BOARD_SETTINGS,
        Routes.POSTURE,
        Routes.SCENARIOS,
        Routes.EVIL_PORTAL,
        Routes.FLASH,                      // holds the port itself, so it is about the link too
    )

    @Test
    fun `a capture, its hashes and the wordlists need no board`() {
        for (pattern in offlinePath) {
            assertTrue("$pattern must work without a link", Routes.worksWithoutBoard(pattern))
            assertFalse("$pattern must not be treated as board-only", Routes.needsBoard(pattern))
        }
    }

    @Test
    fun `every screen that asks the board is named as such`() {
        for (pattern in boardOnly) {
            assertTrue("$pattern needs the link", Routes.needsBoard(pattern))
            assertFalse("$pattern must not claim to work offline", Routes.worksWithoutBoard(pattern))
        }
    }

    @Test
    fun `no route is both`() {
        val both = offlinePath.filter { Routes.needsBoard(it) }
        val neither = boardOnly.filter { !Routes.needsBoard(it) }
        assertTrue("classified as offline but counted as board-only: $both", both.isEmpty())
        assertTrue("classified as board-only but not counted as needing it: $neither", neither.isEmpty())
    }

    @Test
    fun `a route nobody classified is treated as needing the board`() {
        // The safe direction of the unknown: the user is told to connect, rather than shown a screen
        // that quietly does nothing.
        assertTrue(Routes.needsBoard("brand/new/{path}"))
        assertFalse(Routes.worksWithoutBoard("brand/new/{path}"))
    }

    @Test
    fun `no route at all is not treated as needing the board`() {
        // Before the first screen resolves there is nothing to judge.
        assertFalse(Routes.needsBoard(null))
        assertFalse(Routes.worksWithoutBoard(null))
    }

    @Test
    fun `every screen that needs the board can say which screen it is`() {
        // The notice that replaces a board-only screen has to name it, or the person is left with a
        // message about an unnamed something. A route added tomorrow without a name fails here.
        for (pattern in boardOnly) {
            val heading = Routes.headingFor(pattern)
            assertNotEquals("no heading for $pattern", "This screen", heading)
            assertTrue("heading for $pattern is too long: $heading", heading.length <= 20)
        }
    }

    @Test
    fun `a heading is found for the filled-in route too, not only the pattern`() {
        // Navigation asks with what the back stack holds, which for parameterised screens is the
        // pattern; the lookup matches the first segment so both forms name the same screen. Written
        // out rather than built with Routes.ap(), because that one encodes through android.net.Uri.
        assertNotEquals("This screen", Routes.headingFor(Routes.menu("wifi_attacks")))
        assertNotEquals("This screen", Routes.headingFor("ap/aa%3Abb%3Acc%3Add%3Aee%3Aff"))
        assertNotEquals("This screen", Routes.headingFor("live/scan%20all/scanall"))
    }

    @Test
    fun `the offline path covers the whole capture-to-crack job`() {
        // Not decoration: this is the job the app is for, and none of it involves the board.
        val job = listOf(Routes.HOME, Routes.ARTIFACTS, "${Routes.ARTIFACT}/{name}", "${Routes.CRACK}/{name}")
        for (pattern in job) assertTrue("$pattern must be reachable with no cable", Routes.worksWithoutBoard(pattern))
    }
}
