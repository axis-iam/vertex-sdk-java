plugins {
    id("io.spring.dependency-management") version "1.1.7" apply false
}

allprojects {
    group = "com.chaosguide.iam"
    version = "0.1.0"

    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

tasks.register("verifyCentralPortalConfiguration") {
    group = "publishing"
    description = "Verifies the disabled-by-default Maven Central Publisher Portal release gate."

    doLast {
        val approved = providers.gradleProperty("centralReleaseApproved").orNull == "true"
        if (approved) {
            check(!System.getenv("CENTRAL_PUBLISHER_TOKEN_USERNAME").isNullOrBlank()) {
                "CENTRAL_PUBLISHER_TOKEN_USERNAME is required after release approval"
            }
            check(!System.getenv("CENTRAL_PUBLISHER_TOKEN_PASSWORD").isNullOrBlank()) {
                "CENTRAL_PUBLISHER_TOKEN_PASSWORD is required after release approval"
            }
            check(providers.gradleProperty("signingKey").isPresent) {
                "signingKey is required after release approval"
            }
        }
        logger.lifecycle(
            "Central Publisher Portal contract: https://central.sonatype.com/api/v1/publisher/upload; " +
                "remote upload is not configured in this build"
        )
    }
}

subprojects {
    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        testLogging {
            events("passed", "failed", "skipped")
        }
    }
}
