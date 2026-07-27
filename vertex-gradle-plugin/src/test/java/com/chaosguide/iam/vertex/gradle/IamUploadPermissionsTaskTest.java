package com.chaosguide.iam.vertex.gradle;

import com.chaosguide.iam.vertex.manifest.PermissionManifestClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.gradle.api.Project;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IamUploadPermissionsTaskTest {

    @TempDir Path tempDir;

    @Test
    void postsExplicitStructuredManifestThroughCanonicalV1() throws Exception {
        Path manifestFile = tempDir.resolve("manifest.json");
        Files.writeString(manifestFile, """
                {"manifestId":"orders-api","revision":"1","permissions":[
                  {"resource":"posts","action":"read","name":"Read posts","description":null}
                ]}
                """);
        var manifest = new PermissionManifestClient.Manifest("orders-api", "1", List.of(
                new PermissionManifestClient.Declaration("posts", "read", "Read posts", null)));
        var prepared = PermissionManifestClient.prepare(manifest, PermissionManifestClient.Mode.UPSERT);
        try (var server = new MockWebServer()) {
            server.start();
            server.enqueue(new MockResponse().setBody("{\"access_token\":\"safe\",\"token_type\":\"Bearer\",\"expires_in\":60,\"scope\":\"permissions:sync\"}"));
            server.enqueue(new MockResponse().setBody("{\"mode\":\"upsert\",\"manifestId\":\"orders-api\",\"revision\":\"1\",\"fingerprint\":\"" + prepared.fingerprint() + "\",\"applied\":true,\"results\":[{\"key\":\"posts:read\",\"operation\":\"CREATE\",\"reason\":\"DECLARATION_ACCEPTED\"}],\"drift\":[],\"counts\":{\"created\":1,\"updated\":0,\"unchanged\":0,\"resurrected\":0,\"conflict\":0,\"drift\":0}}"));
            IamUploadPermissionsTask task = task();
            task.getIssuerEndpoint().set(server.url("/").toString());
            task.getPortalApiEndpoint().set(server.url("/").toString());
            task.getClientId().set("client");
            task.getClientSecret().set("secret");
            task.getIdempotencyKey().set("deployment-key");
            task.getManifestFile().set(manifestFile.toFile());

            task.upload();

            var token = server.takeRequest();
            var portal = server.takeRequest();
            assertThat(token.getPath()).isEqualTo("/oauth2/token");
            assertThat(token.getBody().readUtf8()).contains("scope=permissions%3Async");
            assertThat(portal.getPath()).isEqualTo("/open/v1/permission-manifests:sync");
            assertThat(portal.getHeader("Authorization")).isEqualTo("Bearer safe");
            assertThat(portal.getHeader("Idempotency-Key")).isEqualTo("deployment-key");
            assertThat(portal.getBody().readUtf8()).contains("\"manifestId\":\"orders-api\"").contains("\"mode\":\"upsert\"");
        }
    }

    @Test
    void consumesEverySharedStructuredFileVector() throws Exception {
        var fixture = sharedManifestVectors();
        for (var vector : fixture.path("manifestFiles").path("accept")) {
            Path file = tempDir.resolve(vector.path("name").textValue() + ".json");
            Files.writeString(file, vector.path("json").textValue());
            IamUploadPermissionsTask task = task();
            task.getManifestFile().set(file.toFile());
            assertThat(task.readManifest().manifestId()).as(vector.path("name").textValue()).isEqualTo("orders-api");
        }
        for (var vector : fixture.path("manifestFiles").path("reject")) {
            Path file = tempDir.resolve(vector.path("name").textValue() + ".json");
            Files.writeString(file, vector.path("json").textValue());
            IamUploadPermissionsTask task = task();
            task.getManifestFile().set(file.toFile());
            assertThatThrownBy(task::readManifest).as(vector.path("name").textValue()).isInstanceOfAny(
                    IllegalArgumentException.class, java.io.IOException.class);
        }
    }

    private static IamUploadPermissionsTask task() {
        Project project = ProjectBuilder.builder().build();
        return project.getTasks().create("uploadUnderTest", IamUploadPermissionsTask.class);
    }

    private static com.fasterxml.jackson.databind.JsonNode sharedManifestVectors() throws Exception {
        try (var input = IamUploadPermissionsTaskTest.class.getResourceAsStream("/permission-manifest-vectors.json")) {
            if (input == null) throw new IllegalStateException("missing permission manifest vectors");
            return new ObjectMapper().readTree(input);
        }
    }
}
