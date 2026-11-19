package com.marauder.mobile.data

import java.util.Locale

/**
 * The two kinds of thing this library actually holds, and where each belongs on screen.
 *
 * It matters because the two are not the same object. A pcap, a GPX track or wardrive CSV is material
 * a cracker or a mapping tool can work on - a person searches the library for those. A session journal
 * is something the app wrote about its own run: worth keeping, worth being able to find, but not a
 * thing to crack, and mixing the two in one undated pile is how a person ends up scrolling past six
 * logs to reach one capture.
 *
 * Nothing is hidden here. Grouping is the only honest way to separate them, because the alternative
 * that makes the list short - dropping the app's own files - would be the app deciding silently that
 * part of its record does not count.
 */
enum class ArtifactGroup { CAPTURES, NOTES, OTHER }

object ArtifactGroups {

    /** Which group a file belongs to. An unknown kind is not promised to either group. */
    fun of(kind: String): ArtifactGroup = when (kind.lowercase(Locale.US)) {
        "pcap", "gpx", "csv" -> ArtifactGroup.CAPTURES
        "jsonl", "json", "log", "txt" -> ArtifactGroup.NOTES
        else -> ArtifactGroup.OTHER
    }

    /** The heading shown above a group. Short, and it says how many are under it. */
    fun label(group: ArtifactGroup, count: Int): String = when (group) {
        ArtifactGroup.CAPTURES -> "Captures · $count"
        ArtifactGroup.NOTES -> "What the app wrote · $count"
        ArtifactGroup.OTHER -> "Other files · $count"
    }

    /**
     * The library in the order the screen shows it: captures first, because that is what the screen is
     * opened for, then the app's own notes. Inside a group the incoming order is kept untouched - it
     * is newest-first, decided where the files are listed, and re-sorting here would be a second
     * answer to a question already answered.
     */
    fun ordered(items: List<Artifact>): List<Pair<ArtifactGroup, List<Artifact>>> =
        ArtifactGroup.entries.mapNotNull { group ->
            items.filter { of(it.record.kind) == group }.takeIf { it.isNotEmpty() }?.let { group to it }
        }
}
