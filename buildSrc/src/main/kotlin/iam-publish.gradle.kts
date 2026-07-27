plugins {
    `maven-publish`
    signing
}

interface IamPublishExtension {
    val artifactId: org.gradle.api.provider.Property<String>
    val artifactName: org.gradle.api.provider.Property<String>
    val artifactDescription: org.gradle.api.provider.Property<String>
    val configurePublication: org.gradle.api.provider.Property<Boolean>
}

val iamPublish = extensions.create<IamPublishExtension>("iamPublish").apply {
    configurePublication.convention(true)
}

fun MavenPublication.applyIamPom(ext: IamPublishExtension) {
    pom {
        name.set(ext.artifactName)
        description.set(ext.artifactDescription)
        url.set("https://github.com/axis-iam/vertex-sdk-java")
        inceptionYear.set("2026")
        licenses {
            license {
                name.set("Apache License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                distribution.set("repo")
            }
        }
        developers {
            developer {
                id.set("axis-iam")
                name.set("Axis Vertex Team")
                email.set("dev@axis-iam.com")
                organization.set("Axis Vertex")
                organizationUrl.set("https://github.com/axis-iam")
            }
        }
        scm {
            connection.set("scm:git:https://github.com/axis-iam/vertex-sdk-java.git")
            developerConnection.set("scm:git:ssh://git@github.com/axis-iam/vertex-sdk-java.git")
            url.set("https://github.com/axis-iam/vertex-sdk-java")
        }
        issueManagement {
            system.set("GitHub")
            url.set("https://github.com/axis-iam/vertex-sdk-java/issues")
        }
    }
}

val mainPublicationNames = setOf("mavenJava", "pluginMaven")

publishing {
    publications {
        afterEvaluate {
            if (iamPublish.configurePublication.get() && findByName("mavenJava") == null && findByName("pluginMaven") == null && plugins.hasPlugin("java")) {
                create<MavenPublication>("mavenJava") {
                    from(components["java"])
                }
            }
            withType<MavenPublication>().configureEach {
                if (name in mainPublicationNames) {
                    if (iamPublish.artifactId.isPresent) {
                        artifactId = iamPublish.artifactId.get()
                    }
                }
                applyIamPom(iamPublish)
            }
        }
    }

    repositories {
        providers.gradleProperty("publicationStagingRepository").orNull?.let { stagingPath ->
            maven {
                name = "PublicationStaging"
                url = uri(stagingPath)
            }
        }
    }
}

signing {
    val signingKey = providers.gradleProperty("signingKey")
    val signingPassword = providers.gradleProperty("signingPassword")
    if (signingKey.isPresent) {
        useInMemoryPgpKeys(signingKey.get(), signingPassword.orNull)
    }
    setRequired({
        providers.gradleProperty("centralReleaseApproved").orNull == "true"
    })
    afterEvaluate {
        publishing.publications.withType<MavenPublication>().configureEach {
            sign(this)
        }
    }
}

tasks.withType<org.gradle.jvm.tasks.Jar>().configureEach {
    from(rootProject.file("LICENSE")) {
        into("META-INF")
    }
}
