plugins {
    java
    id("org.springframework.boot") version "3.4.4"
    id("io.spring.dependency-management") version "1.1.7"
    // id("com.chaosguide.iam.vertex") version "0.1.0"  // enable when plugin is published
}

group = "com.example"
version = "0.0.1-SNAPSHOT"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation("com.chaosguide.iam:vertex-sdk-core:0.1.0")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
}

tasks.test {
    useJUnitPlatform()
}

// Demo using the plugin DSL (uncomment when plugin is available from a published repo)
// Use a WEB/M2M confidential ApplicationClient under the same business Application as the browser SPA.
// iam {
//     endpoint.set("http://localhost:30001")
//     clientId.set(providers.environmentVariable("IAM_CLIENT_ID"))
//     clientSecret.set(providers.environmentVariable("IAM_CLIENT_SECRET"))
//     packageName.set("com.example.demo.security")
//     className.set("MyAppPermissions")
// }
