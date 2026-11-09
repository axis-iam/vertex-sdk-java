import java.security.MessageDigest

plugins { java }

java { toolchain { languageVersion.set(JavaLanguageVersion.of(17)) } }

dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.4.4"))
    implementation("com.chaosguide.iam:vertex-sdk-core:0.1.0")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("com.nimbusds:nimbus-jose-jwt:10.0.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    maxParallelForks = 1
    testLogging { events("passed", "failed", "skipped") }
}

tasks.register("candidateOrigin") {
    doLast {
        val artifacts = configurations.testRuntimeClasspath.get().resolvedConfiguration.resolvedArtifacts
        val sdkArtifacts = artifacts.filter { it.moduleVersion.id.group == "com.chaosguide.iam" }
        check(sdkArtifacts.size == 1) { "Expected only the candidate core artifact" }
        val staged = file("../../../../.worktrees/task-runtime/TASK-20261105-001/maven-stage/" +
            "com/chaosguide/iam/vertex-sdk-core/0.1.0/vertex-sdk-core-0.1.0.jar")
        fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
        sdkArtifacts.forEach { artifact ->
            val digest = sha256(artifact.file.readBytes())
            check(digest == sha256(staged.readBytes())) { "Resolved artifact is not the current stage" }
            println("CANDIDATE ${artifact.moduleVersion.id} SHA256=$digest")
            println("RESOLVED_FILE=${artifact.file.canonicalPath}")
            println("EXCLUSIVE_REPOSITORY=${staged.parentFile.canonicalPath}")
        }
        val springBoot = artifacts.single { it.moduleVersion.id.name == "spring-boot" }.moduleVersion.id
        check(springBoot.version == "3.4.4")
        println("SPRING_BOOT=$springBoot; TEST_JAVA=17")
    }
}
