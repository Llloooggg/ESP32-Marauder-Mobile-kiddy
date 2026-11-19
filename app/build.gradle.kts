import java.io.FileInputStream
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

// Optional release signing. Drop a `keystore.properties` next to this module's
// project root (see README → "Release build") to sign release APKs. When it is
// absent — e.g. a fresh clone or CI — the release build simply stays unsigned,
// so nothing breaks.
val keystorePropsFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) FileInputStream(keystorePropsFile).use { load(it) }
}

android {
    namespace = "com.marauder.mobile"
    compileSdk = 35
    // Pinned so a fresh clone builds the same native code, and so the known-answer
    // test that gates the native engine was compiled by a compiler this repo names.
    ndkVersion = "27.0.12077973"

    defaultConfig {
        // Identity of this build. A different applicationId lets it install SIDE BY
        // SIDE with the upstream ESP32-Marauder-Mobile app; the name follows the
        // repository (…-Mobile-kiddy). The code namespace stays com.marauder.mobile,
        // so no source file had to be renamed. Each install keeps its own data
        // directory, so captures made by one app are not visible to the other
        // (share them out of the Library to move them).
        applicationId = "com.marauder.mobile.kiddy"
        minSdk = 26
        targetSdk = 35
        // The version pair is how a build identifies itself in the wild: the report archive header
        // and the About line both print `versionName (versionCode)`, and a capture made last week
        // can only be re-read against the build that made it if that pair changed when behaviour did.
        // So: any build that changes behaviour gets a new versionCode.
        versionCode = 19
        versionName = "1.4.11-kiddy"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (keystorePropsFile.exists()) {
            create("release") {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        debug {
            // A debug build installs BESIDE the release one instead of fighting it for the same
            // package name. They are signed with different keys, so without this an on-device test
            // would have to uninstall the release app — and with it the captures, wordlists and
            // settings on a phone that is a field instrument, not a test bench.
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (keystorePropsFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    // The native WPA2 core (see src/main/cpp). It is gated at runtime by its own
    // known-answer self-test: if the library is missing for an ABI, or the test fails
    // on a device, the app falls back to the JVM engine and says so on the crack screen
    // rather than running something half-verified.
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    buildFeatures {
        compose = true
        // The GPU helper is reached over binder (src/main/aidl/IGpuCore.aidl).
        aidl = true
        // The About screen and the report header print the real version instead of
        // a hardcoded string that goes stale every release.
        buildConfig = true
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
    // Per-ABI debug/release APKs next to a universal one: install the smallest
    // correct build on the target device (arm64-v8a on modern phones).
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
            isUniversalApk = true
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.datastore.preferences)

    implementation(libs.kotlinx.serialization.json)
    implementation(libs.usbSerial)
    implementation(project(":extractor"))

    debugImplementation(libs.androidx.ui.tooling)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
}
