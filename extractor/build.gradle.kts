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
