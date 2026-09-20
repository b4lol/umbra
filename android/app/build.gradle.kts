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
        // FLAG_SECURE is mandatory (TODO B.4). It also hides the window from
        // uiautomator on some OSes, so an on-device E2E driver needs an opt-out —
        // but ONLY via the debug build type below, behind an explicit Gradle
        // property. Default and release are always secure.
        buildConfigField("boolean", "ALLOW_INSECURE_WINDOW", "false")
        // Debug-only test hook: shortens (never lengthens) the 12 h background auto-lock so the
        // real code path can be proven on a device. 0 = use the real bound.
        buildConfigField("long", "AUTO_LOCK_OVERRIDE_MS", "0L")
    }

    buildTypes {
        debug {
            if (project.hasProperty("umbraInsecureE2E")) {
                buildConfigField("boolean", "ALLOW_INSECURE_WINDOW", "true")
            }
            (findProperty("umbraAutoLockSeconds") as String?)?.toLongOrNull()?.let {
                buildConfigField("long", "AUTO_LOCK_OVERRIDE_MS", "${it * 1000}L")
            }
        }
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = true
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
    testImplementation("junit:junit:4.13.2")
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

// Property-driven so on-device iteration can build one ABI with the optimized
// `android` Cargo profile and the Tor feature (TODO B.4 Phase 2); the defaults
// keep the plain debug two-ABI build unchanged.
val cargoNdkAbis = (findProperty("umbraAbis") as String? ?: "arm64-v8a,x86_64").split(",")
val rustProfile = findProperty("umbraRustProfile") as String? ?: "dev"
val rustFeatures = findProperty("umbraRustFeatures") as String? ?: ""
val cargoBuildArgs = buildList {
    addAll(listOf("build", "-p", "umbra-ffi", "--lib"))
    if (rustProfile != "dev") addAll(listOf("--profile", rustProfile))
    if (rustFeatures.isNotEmpty()) addAll(listOf("--features", rustFeatures))
}
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
    inputs.property("rustProfile", rustProfile)
    inputs.property("rustFeatures", rustFeatures)
    inputs.property("abis", cargoNdkAbis)

    commandLine(
        listOf(
            "cargo", "ndk",
            "--platform", "26",
        ) + cargoNdkAbis.flatMap { listOf("--target", it) } + listOf(
            "-o", outDir.absolutePath,
        ) + cargoBuildArgs
    )

    environment("ANDROID_NDK_HOME", "${System.getProperty("user.home")}/Android/Sdk/ndk/$ndkVersionPin")

    doFirst {
        outDir.mkdirs()
        // Drop ABI directories not being built now, so a stale library from an
        // earlier (differently-configured) build can never ride along in the APK.
        outDir.listFiles()
            ?.filter { it.isDirectory && it.name !in cargoNdkAbis }
            ?.forEach { it.deleteRecursively() }
    }
}

// Regenerates the UniFFI Kotlin bindings for umbra-ffi from the freshly
// built cdylib, entirely within this project's own build output (no
// dependency on a path left behind by some earlier, unrelated task/session).
// Depends on cargoNdkBuild so a real libumbra_native.so is guaranteed to
// exist first; bindings are ABI-independent so any one of the built .so
// files works as the --library argument.
val uniffiBindingsGenDir = layout.buildDirectory.dir("generated/uniffi")

val generateUniffiBindings = tasks.register<Exec>("generateUniffiBindings") {
    description = "Regenerates the UniFFI Kotlin bindings for umbra-ffi via uniffi-bindgen"
    group = "build"

    dependsOn(cargoNdkBuild)

    workingDir = rootProject.projectDir.parentFile // repo root (one level above android/)

    val libraryPath = jniLibsDir.dir(cargoNdkAbis.first()).file("libumbra_native.so")
    val outDir = uniffiBindingsGenDir.get().asFile

    inputs.file(libraryPath)
    outputs.dir(outDir)

    doFirst {
        outDir.mkdirs()
    }

    commandLine(
        "cargo", "run", "-p", "umbra-ffi", "--bin", "uniffi-bindgen", "--",
        "generate",
        "--library", libraryPath.asFile.absolutePath,
        "--language", "kotlin",
        "--out-dir", outDir.absolutePath,
    )
}

// Copies the freshly regenerated Kotlin bindings into the app module's
// source tree.
val copyUniffiBindings = tasks.register<Copy>("copyUniffiBindings") {
    description = "Copies the freshly-generated UniFFI Kotlin bindings for umbra-ffi into the app source tree"
    group = "build"

    dependsOn(generateUniffiBindings)

    from(uniffiBindingsGenDir.map { it.file("uniffi/umbra_native/umbra_native.kt") })
    into("src/main/java/uniffi/umbra_native")
}

tasks.named("preBuild") {
    dependsOn(cargoNdkBuild, copyUniffiBindings)
}
