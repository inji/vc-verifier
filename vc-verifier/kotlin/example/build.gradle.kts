plugins {
    alias(libs.plugins.androidApplication)
    alias(libs.plugins.jetbrainsKotlinAndroid)


}

android {
    namespace = "io.mosip.vccred.example"
    compileSdk = 34

    defaultConfig {
        applicationId = "io.mosip.vccred.example"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
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
    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.1"
    }
    packaging {
        resources {
            excludes += "META-INF/*"
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
        }
    }
}
// Exclude duplicate classes and force versions
configurations.all {
    resolutionStrategy {
        exclude(group = "org.bouncycastle", module = "bcprov-jdk15to18")
        exclude(group = "org.bouncycastle", module = "bcutil-jdk18on")
        exclude(group = "org.bouncycastle", module = "bcprov-jdk15on")
        exclude(group = "org.bouncycastle", module = "bcutil-jdk15on")
        exclude(group = "com.apicatalog", module = "titanium-json-ld")
    }
}
dependencies {
    implementation(project(":vcverifier"))

    implementation(libs.ldSignaturesJava) {
        exclude(group = "com.apicatalog", module = "titanium-json-ld")
    }
    implementation (libs.titaniumJsonLd)
    implementation(libs.okHttp)
    implementation(libs.bouncyCastle)
    implementation(libs.jsonldCommonJava)
    implementation(libs.nimbusJoseJwt)
    implementation(libs.springWeb)


    implementation(libs.coreKtx)
    implementation(libs.lifecycleRuntimeKtx)
    implementation(libs.activityCompose)
    implementation(platform(libs.composeBom))
    implementation(libs.ui)
    implementation(libs.uiGraphics)
    implementation(libs.uiToolingPreview)
    implementation(libs.material3)
    testImplementation(libs.junitJupiter)
    androidTestImplementation(libs.extJunit)
    androidTestImplementation(libs.espressoCore)
    androidTestImplementation(platform(libs.composeBom))
    androidTestImplementation(libs.uiTestJunit4)
    debugImplementation(libs.uiTooling)
    debugImplementation(libs.uiTestManifest)
}