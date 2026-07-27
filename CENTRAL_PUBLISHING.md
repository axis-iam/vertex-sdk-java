# Maven Central publication

Axis Vertex Java artifacts target the Maven Central Publisher Portal. The retired OSSRH staging repository and
Sonatype JIRA credential flow are not supported by this build.

The build only stages a Maven-layout repository locally when
`-PpublicationStagingRepository=/absolute/path` is supplied. It has no remote upload repository or credentialed
HTTP task. A later coordinator-authorized release must:

1. confirm Publisher Portal ownership of the `com.chaosguide.iam` namespace;
2. select the common SDK license and add the corresponding top-level `LICENSE`;
3. supply an artifact-signing identity and Publisher Portal user token from CI secrets;
4. stage signed POM, JAR, sources and Javadocs for all three `0.1.0` artifacts;
5. create the deployment bundle and upload it to the Publisher Portal API at
   `https://central.sonatype.com/api/v1/publisher/upload`;
6. verify and publish that deployment through the Publisher Portal.

`./gradlew verifyCentralPortalConfiguration` is read-only. With no approval property it reports the configured
contract. With `-PcentralReleaseApproved=true`, it fails unless the token environment variables and in-memory
signing key property are present. The task never uploads an artifact.
