plugins {
    id("com.android.application")
}

android {
    namespace = "com.axcel.modifier"
    compileSdk = 35
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "com.axcel.modifier"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
        ndk { abiFilters += setOf("arm64-v8a") }
        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
                arguments += listOf("-DANDROID_STL=c++_shared")
            }
        }
    }

    buildTypes {
        getByName("debug") { isMinifyEnabled = false }
        getByName("release") { isMinifyEnabled = false }
    }

    externalNativeBuild {
        cmake { path = file("src/main/cpp/CMakeLists.txt") }
    }
}
