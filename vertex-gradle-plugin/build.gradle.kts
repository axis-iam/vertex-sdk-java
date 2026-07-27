plugins {
    `java-gradle-plugin`
    id("iam-publish")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
    withJavadocJar()
}

tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).addStringOption("Xdoclint:none", "-quiet")
}

dependencies {
    implementation(gradleApi())
    implementation(project(":vertex-sdk-core")) {
        isTransitive = false
    }
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.2")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("org.assertj:assertj-core:3.25.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

gradlePlugin {
    plugins {
        create("iamSdkPlugin") {
            id = "com.chaosguide.iam.vertex"
            implementationClass = "com.chaosguide.iam.vertex.gradle.IamSdkPlugin"
            displayName = "Axis Vertex Gradle Plugin"
            description = "Sync permissions between IAM server and Java app codegen"
        }
    }
}

iamPublish {
    configurePublication.set(false)
    artifactId.set("vertex-gradle-plugin")
    artifactName.set("Axis Vertex Gradle Plugin")
    artifactDescription.set(
        "Gradle plugin that syncs permissions from the IAM server and generates type-safe " +
            "constants for Java applications. Companion to iam-spring-boot-starter."
    )
}

tasks.test {
    useJUnitPlatform()
}
