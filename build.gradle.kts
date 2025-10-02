@file:Suppress("UnstableApiUsage")

import com.android.build.api.variant.BuildConfigField
import com.android.build.api.variant.FilterConfiguration
import com.android.build.gradle.internal.cxx.configure.gradleLocalProperties
import java.text.SimpleDateFormat
import java.util.Date

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.serialization)
    alias(libs.plugins.rust)
}

cargo {
   module  = "./libs/rust"
   libname = "keymint"
   targets = listOf("arm64", "arm")

   prebuiltToolchains = true
   profile = "release"
}

dependencies {
    implementation(libs.kotlin.stdlib.common)
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.serialization.json)
}

android {
    defaultConfig.applicationId = "top.qwq2333.ohmykeymint"
    namespace = "top.qwq2333.ohmykeymint"

    sourceSets.getByName("main") {
        java.srcDir("src/main/java")
    }

    lint {
        checkReleaseBuilds = true
        disable += listOf(
            "MissingTranslation", "ExtraTranslation", "BlockedPrivateApi"
        )
    }

    packaging {
        resources.excludes += "**"
    }

    kotlin {
        jvmToolchain(Version.java.toString().toInt())
    }

    buildTypes {
        getByName("release") {
            signingConfig = signingConfigs.getByName("debug")
            isMinifyEnabled = false
            isShrinkResources = true
        }

        getByName("debug") {
            isDefault = true
            isDebuggable = true
            isJniDebuggable = true
        }
    }

    buildFeatures {
        buildConfig = true
    }

    defaultConfig {
        buildConfigField("String", "BUILD_TIME", "\"${SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Date())}\"")
    }

    applicationVariants.all {
        outputs.all {
            val abi = this.filters.find { it.filterType == FilterConfiguration.FilterType.ABI.name }?.identifier
            val output = this as? com.android.build.gradle.internal.api.BaseVariantOutputImpl
            val outputFileName = "OhMyKeymint-${defaultConfig.versionName}-${abiName[abi]}.apk"
            output?.outputFileName = outputFileName
        }
    }
}

