plugins {
    id("com.android.application")
    // AGP 9.0+ bundles Kotlin support directly (the standalone
    // `org.jetbrains.kotlin.android` plugin is no longer required and
    // actively refuses to apply on top of it) — see
    // https://kotl.in/gradle/agp-built-in-kotlin
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.umbra.android"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.umbra.android"
        // Chosen deliberately lower than compileSdk/targetSdk: 26 (Android 8.0)
        // covers the overwhelming majority of real-world devices while still
        // being high enough to avoid legacy-permission-model complexity.
        // The umbra_test AVD itself runs API 34 (system-images;android-34;
        // google_apis;x86_64), which is comfortably above this floor.
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0-walking-skeleton"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation(platform("androidx.compose:compose-bom:2024.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")

    // Required by the UniFFI-generated Kotlin bindings in
    // src/main/java/uniffi/umbra_native/umbra_native.kt, which call into
    // libumbra_native.so via JNA's Native.register().
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}

// --- cargo-ndk build wiring (ANDROID.md §8) -------------------------------
//
// Cross-compiles the umbra-ffi cdylib (libumbra_native.so) for both v1
// target ABIs (arm64-v8a for real devices, x86_64 for the emulator) and
// drops the outputs into app/src/main/jniLibs/<abi>/ so the Android Gradle
// Plugin packages them automatically. Runs before the Kotlin/Java compile
// step so the .so files are always present for a build.

val cargoNdkAbis = listOf("arm64-v8a", "x86_64")
val jniLibsDir = layout.projectDirectory.dir("src/main/jniLibs")
// Pinned NDK version, matching this workspace's existing reproducibility
// conventions (Cargo.lock, ADR-014 profile pinning, etc).
val ndkVersionPin = "27.0.12077973"

val cargoNdkBuild = tasks.register<Exec>("cargoNdkBuild") {
    description = "Cross-compiles crates/umbra-ffi to libumbra_native.so for arm64-v8a and x86_64 via cargo-ndk"
    group = "build"

    workingDir = rootProject.projectDir.parentFile // repo root (one level above android/)

    val outDir = jniLibsDir.asFile
    outputs.dir(outDir)
    inputs.dir(rootProject.projectDir.parentFile.resolve("crates/umbra-ffi/src"))

    commandLine(
        listOf(
            "cargo", "ndk",
            "--platform", "26",
        ) + cargoNdkAbis.flatMap { listOf("--target", it) } + listOf(
            "-o", outDir.absolutePath,
            "build", "-p", "umbra-ffi", "--lib",
        )
    )

    environment("ANDROID_NDK_HOME", "${System.getProperty("user.home")}/Android/Sdk/ndk/$ndkVersionPin")

    doFirst {
        outDir.mkdirs()
    }
}

// Copies Task 1's uniffi-bindgen-generated Kotlin bindings into the app
// module's source tree. This is a straight file-copy for the walking
// skeleton; regenerating bindings on every build via uniffi-bindgen's own
// Gradle plugin (ANDROID.md §8's longer-term intent) is left to a later
// task since the bindings are stable for this smoke test.
val copyUniffiBindings = tasks.register<Copy>("copyUniffiBindings") {
    description = "Copies the pre-generated UniFFI Kotlin bindings for umbra-ffi into the app source tree"
    group = "build"

    val bindingsSrc = providers.gradleProperty("umbraUniffiBindingsDir")
        .orElse(providers.environmentVariable("UMBRA_UNIFFI_BINDINGS_DIR"))
        .orElse("/tmp/umbra-kotlin-bindings")

    from(bindingsSrc.map { file("$it/uniffi/umbra_native/umbra_native.kt") })
    into("src/main/java/uniffi/umbra_native")
}

tasks.named("preBuild") {
    dependsOn(cargoNdkBuild, copyUniffiBindings)
}
