package com.marauder.mobile.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Whether a command is a run or an answer.
 *
 * This decides two things the user can feel: whether the live screen offers Stop, and whether the app
 * stops the board when the screen is left. Get it wrong in one direction and a scan keeps running
 * after the phone has stopped looking at it; get it wrong in the other and a one-shot question is
 * presented as a run that never ends. Several of these verbs are multi-verb commands, so the rule has
 * to read the sub-command, not the head.
 */
class LiveClassifierTest {

    @Test
    fun theBoardGpsTrackerRunsWhileThePositionQueriesAnswer() {
        // `gps -t` starts a scan mode on the board (that is why the firmware's GPS modes say
        // "Stop with stopscan"); `gps -g`/`gps -n` print one line and are done.
        assertTrue(LiveClassifier.of(FirmwareCommands.gpsTracker()).continuous)
        assertFalse(LiveClassifier.of(FirmwareCommands.gpsGet("fix")).continuous)
        assertFalse(LiveClassifier.of(FirmwareCommands.gpsSetSystems("all")).continuous)
        assertFalse("a point of interest is written, not streamed", LiveClassifier.of(FirmwareCommands.gpsPoi("m")).continuous)
    }

    @Test
    fun multiVerbCommandsAreJudgedByTheirSubCommand() {
        assertTrue(LiveClassifier.of(FirmwareCommands.csimotionStart(2)).continuous)
        assertFalse(LiveClassifier.of(FirmwareCommands.csimotionStatus()).continuous)
        assertTrue(LiveClassifier.of(FirmwareCommands.remoteId("scan")).continuous)
        assertFalse(LiveClassifier.of(FirmwareCommands.remoteId("clear")).continuous)
        assertFalse(LiveClassifier.of(FirmwareCommands.recon("status")).continuous)
        assertFalse(LiveClassifier.of(FirmwareCommands.recon("stop")).continuous)
    }

    @Test
    fun theListsAFilledRunCanStreamAreNamedByTheCommandThatFillsThem() {
        assertEquals(ListType.DRONES, LiveClassifier.of(FirmwareCommands.remoteId("scan")).list)
        assertEquals(ListType.ACCESS_POINTS, LiveClassifier.of(FirmwareCommands.SNIFF_BEACON).list)
        assertEquals(ListType.PROBES, LiveClassifier.of(FirmwareCommands.SNIFF_PROBE).list)
        // A count or a follow run has no list to poll: showing an empty one would be a claim.
        assertEquals(null, LiveClassifier.of(FirmwareCommands.PACKET_COUNT).list)
        assertEquals(null, LiveClassifier.of(FirmwareCommands.MAC_TRACK).list)
    }

    @Test
    fun everyRunThePlaybooksStartCanBeStoppedOnTheScreen() {
        // The playbooks are the promised path; each command they start has to be a run the app knows
        // it is holding, or "Stop" and leaving the screen would leave the board scanning.
        val runs = Scenarios.all
            .filter { it.run != ScenarioRun.NAVIGATE }
            .map { it.command to it.id }
        val unrunnable = runs.filter { (command, _) -> !LiveClassifier.of(command).continuous }
            .map { (command, id) -> "$id: $command" }
        assertEquals("playbook runs the live screen would not stop: $unrunnable", emptyList<String>(), unrunnable)
    }
}
