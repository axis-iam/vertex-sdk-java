pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

rootProject.name = "vertex-sdk-java"

include("vertex-sdk-core")
include("vertex-gradle-plugin")
include("vertex-sdk-test")
