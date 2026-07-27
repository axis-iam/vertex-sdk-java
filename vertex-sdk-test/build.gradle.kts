plugins {
    `java-library`
    id("iam-publish")
    id("io.spring.dependency-management")
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

buildscript {
    dependencies {
        classpath("org.springframework.boot:spring-boot-gradle-plugin:3.4.4")
    }
}

dependencyManagement {
    imports {
        mavenBom(org.springframework.boot.gradle.plugin.SpringBootPlugin.BOM_COORDINATES)
    }
}

dependencies {
    api(platform("org.springframework.boot:spring-boot-dependencies:3.4.4"))
    api(project(":vertex-sdk-core"))
    api("org.springframework.boot:spring-boot-starter-test")
    api("org.springframework.security:spring-security-test")
    api("com.squareup.okhttp3:mockwebserver:4.12.0")
    api("org.junit.jupiter:junit-jupiter")
    implementation("com.nimbusds:nimbus-jose-jwt:10.0.2")

    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

iamPublish {
    artifactId.set("vertex-sdk-test")
    artifactName.set("Axis Vertex SDK Test Helpers")
    artifactDescription.set(
        "Test helpers for integrating sdk-java in client apps — mock JWT issuer (IamMockWebServer), " +
            "mock permission resolver, security test fixtures."
    )
}
