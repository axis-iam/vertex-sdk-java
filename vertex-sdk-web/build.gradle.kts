plugins { `java-library`; id("iam-publish") }
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    withSourcesJar(); withJavadocJar()
}
tasks.withType<JavaCompile>().configureEach { options.release.set(17) }
tasks.withType<Javadoc>().configureEach { (options as StandardJavadocDocletOptions).addStringOption("Xdoclint:none", "-quiet") }
dependencies {
    api(project(":vertex-sdk-core"))
    api(platform("org.springframework.boot:spring-boot-dependencies:3.4.4"))
    api("org.springframework.security:spring-security-oauth2-client")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
iamPublish {
    artifactId.set("vertex-sdk-web")
    artifactName.set("Axis Vertex SDK Web")
    artifactDescription.set("Explicit server-session BFF integration for Java 17 and Spring Boot 3.4")
}
