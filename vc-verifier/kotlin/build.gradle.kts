// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    alias(libs.plugins.androidApplication) apply false
    alias(libs.plugins.androidLibrary) apply false
    alias(libs.plugins.jetbrainsKotlinAndroid) apply false
    alias(libs.plugins.dokka ) apply false
    `maven-publish`
}

configurations.all {  
    resolutionStrategy {  
        exclude(group = "org.bouncycastle", module = "bcprov-jdk15to18")  
        exclude(group = "org.bouncycastle", module = "bcutil-jdk18on")  
        exclude(group = "org.bouncycastle", module = "bcprov-jdk15on")  
        exclude(group = "org.bouncycastle", module = "bcutil-jdk15on")  
        exclude(group = "com.apicatalog", module = "titanium-json-ld")  
    }  
}