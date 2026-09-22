plugins {
    id("com.android.library")
    alias(libs.plugins.kotlinAndroid)
    id("maven-publish")
    id("signing")
    alias(libs.plugins.dokka)
    jacoco
    alias(libs.plugins.sonarqube)
}

jacoco {
    toolVersion = libs.versions.jacoco.get()
    reportsDirectory = layout.buildDirectory.dir("reports/jacoco")
}

android {
    namespace = "com.example.vciclient"
    compileSdk = 34

    defaultConfig {
        minSdk = 23

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    testOptions {
        unitTests {
            isReturnDefaultValues = true
        }
    }
}

dependencies {
    implementation(libs.okHttp)
    implementation(libs.nimbusJoseJwt)
    implementation(libs.fusionauthJwt)
    implementation(libs.gson)
    implementation(libs.coroutinesCore)
    implementation(libs.bouncyCastle)
    implementation(libs.tink)
    implementation(libs.okio)
    implementation(libs.injiOpenid4vp)

    testImplementation(libs.mockWebServer)
    testImplementation(libs.mockk)
    testImplementation(libs.junitJupiterApi)
    testImplementation(libs.orgJson)
    testImplementation(libs.coroutinesTest)
    testImplementation(kotlin("test"))
}

tasks {
    register<JacocoReport>("jacocoTestReport") {
        dependsOn(
            listOf(
                "testDebugUnitTest",
                "compileReleaseUnitTestKotlin",
                "testReleaseUnitTest"
            )
        )

        reports {
            html.required = true
            xml.required = true
        }
        sourceDirectories.setFrom(layout.projectDirectory.dir("src/main/java"))
        classDirectories.setFrom(
            files(
                fileTree(layout.buildDirectory.dir("intermediates/javac/debug")),
                fileTree(layout.buildDirectory.dir("tmp/kotlin-classes/debug"))
            )
        )
        executionData.setFrom(
            fileTree(layout.buildDirectory) {
                include("**/testDebug**.exec")
            }
        )
    }

    register<Jar>("javadocJar") {
        dependsOn("dokkaJavadoc")
        archiveClassifier.set("javadoc")
        from(layout.buildDirectory.dir("dokka/javadoc"))
    }

    register<Jar>("sourcesJar") {
        archiveClassifier.set("sources")
        from(android.sourceSets["main"].java.srcDirs)
    }
}
tasks.register("generatePom") {
     group = "publishing"
    description = "Generates the POM file for the AAR publication"
    dependsOn("generatePomFileForAarPublication")
}



tasks.build {
    finalizedBy("jacocoTestReport")
}

sonarqube {
    properties {
        property( "sonar.java.binaries", "build/intermediates/javac/debug")
        property( "sonar.language", "kotlin")
        property( "sonar.exclusions", "**/build/**, **/*.kt.generated, **/R.java, **/BuildConfig.java")
        property( "sonar.scm.disabled", "true")
        property( "sonar.coverage.jacoco.xmlReportPaths", "build/reports/jacoco/jacocoTestReport/jacocoTestReport.xml")
        property("sonar.projectName", "INJI VCI Client")
        property("sonar.projectKey", "inji-vci-client")
    }
}

apply {
    from("publish-artifact.gradle")
}
