// Pure-JVM module: ESP32 Marauder pcap → hashcat 22000 extraction.
// No Android dependencies: unit-testable with plain JUnit on any machine.
plugins {
    alias(libs.plugins.kotlin.jvm)
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}

// Lab entry points: run the real pipeline on a real capture from the command line,
// through the same code the app ships. A unit test can only describe the frames it
// invented; hardware captures (gapped, padded, half-lost over USB) have to be run,
// not described. Pass arguments with -PtoolArgs="…", e.g.
//   ./gradlew :extractor:extractPcap -PtoolArgs="C:/tmp/cap.pcap -o C:/tmp/hashes.22000.txt"
//   ./gradlew :extractor:crackHash   -PtoolArgs="C:/tmp/hashes.22000.txt C:/tmp/wordlist.txt"
// Captures of real networks stay out of git — see the repository .gitignore.
mapOf(
    "extractPcap" to "com.marauder.extractor.ExtractTool",
    "crackHash" to "com.marauder.extractor.CrackTool",
).forEach { (taskName, entryPoint) ->
    tasks.register<JavaExec>(taskName) {
        group = "lab"
        description = "Run the $taskName pipeline on a capture/hash file (-PtoolArgs=\"…\")"
        classpath = sourceSets.getByName("main").runtimeClasspath
        mainClass.set(entryPoint)
        argumentProviders.add(CommandLineArgumentProvider {
            (project.findProperty("toolArgs")?.toString() ?: "").split(' ').filter { it.isNotBlank() }
        })
    }
}
