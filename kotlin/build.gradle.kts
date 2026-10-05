// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    id("com.android.application") version "8.1.0" apply false
    id("org.jetbrains.kotlin.android") version "1.9.25" apply false
    id("com.android.library") version "8.1.0" apply false
}

subprojects {
    configurations.all {
        // Force kotlin-stdlib to match the Kotlin compiler version (1.9.25).
        resolutionStrategy {
            force("org.jetbrains.kotlin:kotlin-stdlib:1.9.25")
            force("org.jetbrains.kotlin:kotlin-stdlib-jdk8:1.9.25")
            force("org.jetbrains.kotlin:kotlin-stdlib-jdk7:1.9.25")
            force("org.jetbrains.kotlin:kotlin-reflect:1.9.25") 
        }
        // The 'titanium-json-ld' library (required for LDP_VC) transitively pins Bouncy Castle to v1.60.
        // However, the modern security libraries ('Tink', 'Nimbus') required for JWT_VC strictly require v1.70+.
        resolutionStrategy.eachDependency {
            if (requested.group == "org.bouncycastle" && requested.name.contains("bcprov")) {
                useTarget("org.bouncycastle:bcprov-jdk15to18:1.78")
                because("Resolve version conflict between legacy titanium-json-ld and modern Tink/Nimbus libraries.")
            }
        }
    }
}