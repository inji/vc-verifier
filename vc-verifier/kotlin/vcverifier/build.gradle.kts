plugins {
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.jetbrainsKotlinAndroid)
    `maven-publish`
    alias(libs.plugins.dokka)
    alias(libs.plugins.sonarqube)
    jacoco
    signing
}

configurations.all {
    resolutionStrategy.force( "com.fasterxml.jackson.core:jackson-core:2.14.0")
}

jacoco {
    toolVersion = "0.8.8" // Ensure compatibility
}

android {
    namespace = "io.mosip.vccred.vcverifier"
    compileSdk = 33

    defaultConfig {
        minSdk = 23
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    packaging {
        resources {
            excludes += "META-INF/*"
            excludes += "META-INF/spring/aot.factories"
        }
    }
}

dependencies {
    implementation(libs.orgJson)
    implementation(libs.ldSignaturesJava) {
        exclude(group = "com.apicatalog", module = "titanium-json-ld")
    }
    implementation (libs.titaniumJsonLd)
    implementation(libs.okHttp)
    implementation(libs.bouncyCastle)
    implementation(libs.jsonldCommonJava)
    implementation(libs.jackson.module.kotlin)
    implementation(libs.jackson.databind)
    implementation(libs.jackson.core)
    implementation(libs.jackson.annotations)
    implementation(libs.nimbusJoseJwt)
    implementation(libs.springWeb)
    implementation(libs.cbor)
    implementation (libs.identity)
    implementation(libs.annotation.jvm)
    implementation(libs.authelete.sd.jwt)
    implementation(libs.threetenbp)
    implementation(libs.jackson.dataformat.cbor)
    implementation(libs.cose.java)

    testImplementation(libs.mockk)
    testImplementation(libs.junitJupiter)
    testImplementation(libs.mockWebServer)

}

tasks.withType<Test> {
    useJUnitPlatform()
    jacoco {
        isEnabled = true
    }
    finalizedBy(tasks.named("jacocoTestReport"))
    testLogging {
        events("passed", "skipped", "failed", "standardOut", "standardError")
        showStandardStreams = true
    }
}

tasks.register("jacocoTestReport", JacocoReport::class) {
    description = "Generates Test coverage report"
    group = "TestReport"
    dependsOn("testDebugUnitTest")

    reports {
        xml.required = true
        html.required = true
        csv.required = false
    }

    val kotlinTree = fileTree(
        mapOf(
            "dir" to "${layout.buildDirectory.get()}/tmp/kotlin-classes/debug",
            "includes" to listOf("**/*.class")
        )
    )
    val coverageSourceDirs = arrayOf("src/main/java")

    classDirectories.setFrom(files(kotlinTree))
    sourceDirectories.setFrom(coverageSourceDirs)

    executionData.setFrom(files("${layout.buildDirectory.get()}/jacoco/testDebugUnitTest.exec"))
}

tasks.register("prepareKotlinBuildScriptModel"){
    group = "ide"
    description = "Prepares the Kotlin build script model for IDE support"
}

tasks.register<Jar>("jarRelease") {
    group = "release"
    description = "Assemple Jar Release"

    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    dependsOn("assembleRelease")
    dependsOn("dokkaJavadoc")
    from("build/intermediates/javac/release/classes") {
        include("**/*.class")
    }
    from("build/tmp/kotlin-classes/release") {
        include("**/*.class")
    }
    manifest {
        attributes["Implementation-Title"] = project.name
        attributes["Implementation-Version"] = "1.3.0-SNAPSHOT"
    }
    archiveBaseName.set("${project.name}-release")
    archiveVersion.set("1.4.0-SNAPSHOT")
    destinationDirectory.set(layout.buildDirectory.dir("libs"))
}

tasks.register<Jar>("javadocJar") {
    group = "release"
    description = "Create JavaDoc Jar for Release"

    dependsOn("dokkaJavadoc")
    archiveClassifier.set("javadoc")
    from(tasks.named("dokkaHtml").get().outputs.files)
}
tasks.register<Jar>("sourcesJar") {
    group = "release"
    description = "Create Source Jar for Release"

    archiveClassifier.set("sources")
    from(android.sourceSets["main"].java.srcDirs)
}

apply(from = "publish-artifact.gradle")
tasks.register("generatePom") {
    group = "release"
    description = "Geneate POM file for AAR and JAR Release"

    dependsOn("generatePomFileForAarPublication", "generatePomFileForJarReleasePublication")
}

sonarqube {
    properties {
        property( "sonar.java.binaries", "build/intermediates/javac/debug")
        property( "sonar.language", "kotlin")
        property( "sonar.exclusions", "**/build/**, **/*.kt.generated, **/R.java, **/BuildConfig.java")
        property( "sonar.scm.disabled", "true")
        property( "sonar.coverage.jacoco.xmlReportPaths", "build/reports/jacoco/jacocoTestReport/jacocoTestReport.xml")
    }
}
