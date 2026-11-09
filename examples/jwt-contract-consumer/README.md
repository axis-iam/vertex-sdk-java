# Staged JWT contract consumer

This standalone Java 17 / Spring Boot 3.4.4 project consumes only the staged
`com.chaosguide.iam:vertex-sdk-core:0.1.0` Maven artifact. It is intentionally not
included in the SDK multi-project build. Stage the candidate at the task-local
repository declared in `settings.gradle.kts`; IAM artifacts resolve exclusively
there, without `mavenLocal`, old registry entries, source/project dependencies,
or composite builds. All other dependencies resolve from Maven Central.

Use the coordination task registered `java-candidate-stage` and
`java-clean-consumer` validation checks. The consumer check selects a fresh
Gradle user home, verifies the resolved JAR digest against the current stage,
and prints its exact origin. Java 17 is required at runtime, not only as a
compilation target.

The test starts local JWKS and real Spring HTTP servers, signs ephemeral RSA
JWTs, and verifies resource audience distinct from client ID, issuer validation,
mandatory `app_id`, custom permission resolver Application context, and missing
authentication. Private keys and tokens exist only in memory and are never logged.
