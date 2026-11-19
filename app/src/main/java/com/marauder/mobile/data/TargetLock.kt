package com.marauder.mobile.data

import com.marauder.mobile.data.ScanLedger.ApPin

/**
 * Pinning a targeted operation to one access point, given a firmware that only
 * understands list slots.
 *
 * Two facts from the firmware drive this design:
 *
 *  * `select -a <slot>` **toggles** that slot, and the targeted attacks
 *    (`sniffpmkid -d -l`, `attack -t deauth -c`) act on *every* AP that is
 *    currently selected. So a stale index does not just hit the wrong network —
 *    whatever the user selected earlier is still selected and gets attacked too.
 *  * `select -a <ignored> -f <filter>` routes through `filterAccessPoints`, which
 *    **sets** `selected = matchesFilter` for the whole list: one command that
 *    selects the match and clears everything else. Addressed by ESSID, so it does
 *    not care which slot the network happens to sit in.
 *
 * The plan below therefore prefers the ESSID filter, pins out any same-named
 * duplicates by their live slots, and always ends with a `jsonlist a` the caller
 * can check. Nothing is sent to the air until that check agrees.
 */
object TargetLock {

    /** Commands to send, how the target is addressed, and what must be verified. */
    data class Plan(
        /** Selection commands, in order. */
        val commands: List<String>,
        /** True when the target is addressed by ESSID filter (slot-independent). */
        val byEssid: Boolean,
        /** Other BSSIDs that share this exact ESSID (pinned out by slot). */
        val duplicates: List<String>,
        /** Why the ESSID path could not be used, when it was not. */
        val fallbackReason: String? = null,
    )

    /**
     * The firmware filter expression that selects exactly this ESSID, or `null` when
     * the name cannot be expressed through the firmware's parser:
     *
     *  * blank / hidden network — nothing to match;
     *  * contains ` or ` — the firmware splits filters on that literal, so the name
     *    would become two predicates;
     *  * contains both quote kinds — the parser has no escapes, so the argument
     *    cannot be wrapped safely;
     *  * contains a control character — it would break the serial line.
     */
    fun selectionFilter(essid: String): String? {
        // The firmware compares the whole ESSID, so a name that only matches after
        // trimming can never be selected by filter — and an empty one has nothing
        // to match at all.
        if (essid != essid.trim() || essid.isEmpty()) return null
        if (essid.indexOf(" or ", ignoreCase = true) >= 0) return null
        if (essid.any { it.code < 0x20 || it.code == 0x7f }) return null

        val hasDouble = essid.contains('"')
        val hasSingle = essid.contains('\'')
        return when {
            // Wrap the whole filter in apostrophes and quote the name with quotes.
            !hasSingle -> "'equals \"$essid\"'"
            // Mirror it when the name itself contains an apostrophe.
            !hasDouble -> "\"equals '$essid'\""
            else -> null
        }
    }

    /**
     * Build the command sequence that leaves exactly [target] selected.
     *
     * [list] must be the same snapshot [target] came from — the slots it contains
     * are what the commands address, so a stale list makes the plan stale (that is
     * what the caller's verification step catches).
     */
    fun plan(target: ApPin, list: List<ApPin>): Plan {
        val targetBssid = ScanLedger.normalizeMac(target.bssid)
        val pinsByName = list.filter {
            it.essid.trim().equals(target.essid.trim(), ignoreCase = true) && it.bssid != targetBssid
        }
        val duplicates = pinsByName.map { it.bssid }
        val filter = selectionFilter(target.essid)
        val othersSelected = list.filter { it.selected && it.bssid != targetBssid }

        if (filter != null) {
            val commands = ArrayList<String>(1 + pinsByName.size)
            // Needs `-a` to be present for the firmware to reach the filter branch;
            // its value is ignored there, so 0 is never used as an index.
            commands += FirmwareCommands.selectByFilter(filter)
            // The filter selects every AP with this name; toggle the others off by the
            // slot they occupy in the snapshot this plan was built from.
            pinsByName.forEach { commands += FirmwareCommands.toggleAp(it.index) }
            return Plan(commands, byEssid = true, duplicates = duplicates)
        }

        // No usable name: fall back to slots, and make the state exclusive by
        // toggling off everything else that is currently selected.
        val reason = when {
            target.essid.isBlank() -> "this network has no SSID to match on"
            target.essid.contains(" or ", ignoreCase = true) -> "its SSID contains the firmware's \"or\" separator"
            else -> "its SSID cannot be quoted safely for the firmware"
        }
        val commands = ArrayList<String>(1 + othersSelected.size)
        if (!target.selected) commands += FirmwareCommands.toggleAp(target.index)
        othersSelected.forEach { commands += FirmwareCommands.toggleAp(it.index) }
        // An empty command list means the board already has exactly this AP selected;
        // the caller still verifies that before anything is transmitted.
        return Plan(commands, byEssid = false, duplicates = duplicates, fallbackReason = reason)
    }

    /**
     * Commands that leave the board with nothing selected.
     *
     * `select -a <slot>` toggles (CommandLine.cpp:1871-1885), so the deselect plan is
     * exactly the slots that are selected in [list]. `select -a all` cannot be used:
     * it toggles the whole list (CommandLine.cpp:1840-1859), so it *selects* every
     * network when nothing was selected before — the opposite of clearing.
     *
     * The firmware splits that one argument on `,` (CommandLine.cpp:1837), so a single
     * command can address every slot; slots shift between snapshots, which is why the
     * caller reads the list back afterwards instead of trusting the write.
     */
    fun clearPlan(list: List<ApPin>): List<String> {
        val slots = list.filter { it.selected }.map { it.index }
        if (slots.isEmpty()) return emptyList()
        return listOf(FirmwareCommands.selectApSlots(slots))
    }

    /** BSSIDs still selected in [list]; empty means the board really is unselected. */
    fun stillSelected(list: List<ApPin>): Set<String> =
        list.filter { it.selected }.map { it.bssid }.toSet()

    /** What the post-selection `jsonlist a` proved (or failed to prove). */
    sealed class Outcome {
        /** Only the target is selected (or only the target plus its own duplicates). */
        data class Locked(val selected: Set<String>, val duplicates: Set<String>) : Outcome()

        /** The board no longer lists this network — nothing was addressed. */
        data class TargetGone(val bssid: String) : Outcome()

        /** The target ended up unselected: the select commands did not land. */
        data class TargetNotSelected(val selected: Set<String>) : Outcome()

        /** A different network is still selected and cannot be explained. */
        data class ExtraTargets(val selected: Set<String>, val extras: Set<String>) : Outcome()
    }

    /** Judge a fresh AP snapshot against the plan that was just sent. */
    fun verify(targetBssid: String, targetEssid: String, list: List<ApPin>): Outcome {
        val want = ScanLedger.normalizeMac(targetBssid)
        val pin = list.firstOrNull { it.bssid == want } ?: return Outcome.TargetGone(want)
        val selected = list.filter { it.selected }.map { it.bssid }.toSet()
        if (want !in selected) return Outcome.TargetNotSelected(selected)
        val extras = selected - want
        val unexplained = extras.filter { extra ->
            val essid = list.firstOrNull { it.bssid == extra }?.essid.orEmpty()
            !essid.trim().equals(targetEssid.trim(), ignoreCase = true)
        }
        if (unexplained.isNotEmpty()) return Outcome.ExtraTargets(selected, unexplained.toSet())
        return Outcome.Locked(selected, extras)
    }
}
