package com.chaosguide.iam.vertex.client;

import com.chaosguide.iam.vertex.client.dto.AccountUpdateProfileRequest;
import com.chaosguide.iam.vertex.client.dto.UserProfileResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.Test;

import java.lang.reflect.RecordComponent;
import java.time.Duration;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CanonicalProfileContractTest {
    private static final String PROFILE = """
            {"userId":"user-1","applicationId":"app-1","globalIdentityId":"identity-1",
             "email":"user@example.com","emailVerified":true,"username":"alice",
             "displayName":"Alice","avatarUrl":"https://example.com/avatar.png","status":"ACTIVE",
             "createdAt":"2026-10-30T00:00:00Z","updatedAt":"2026-10-30T01:00:00Z",
             "currentOrganization":{"organizationId":"org-1","name":"Acme","slug":"acme",
               "role":"MEMBER","joinedAt":"2026-10-30T00:00:00Z","current":true}}
            """;
    private static final String NULLABLE_PROFILE = """
            {"userId":"user-1","applicationId":"app-1","globalIdentityId":null,
             "email":null,"emailVerified":false,"username":null,"displayName":null,
             "avatarUrl":null,"status":"ACTIVE","createdAt":"2026-10-30T00:00:00Z",
             "updatedAt":"2026-10-30T01:00:00Z","currentOrganization":null}
            """;

    @Test
    void canonicalProfileAndNullableProjectionsUseOnlyProfileEndpoint() throws Exception {
        try (var server = new MockWebServer()) {
            server.start();
            var client = client(server);
            server.enqueue(json(PROFILE));
            server.enqueue(json(NULLABLE_PROFILE));
            server.enqueue(json(NULLABLE_PROFILE));

            var profile = client.getMe("access-token");
            assertThat(profile.userId()).isEqualTo("user-1");
            assertThat(profile.applicationId()).isEqualTo("app-1");
            assertThat(profile.globalIdentityId()).isEqualTo("identity-1");
            assertThat(profile.email()).isEqualTo("user@example.com");
            assertThat(profile.emailVerified()).isTrue();
            assertThat(profile.username()).isEqualTo("alice");
            assertThat(profile.displayName()).isEqualTo("Alice");
            assertThat(profile.avatarUrl()).isEqualTo("https://example.com/avatar.png");
            assertThat(profile.status()).isEqualTo("ACTIVE");
            assertThat(profile.createdAt()).isEqualTo("2026-10-30T00:00:00Z");
            assertThat(profile.updatedAt()).isEqualTo("2026-10-30T01:00:00Z");
            assertThat(profile.currentOrganization().organizationId()).isEqualTo("org-1");

            assertNullable(client.getAccountProfile("access-token"));
            assertNullable(client.updateAccountProfile(
                    "access-token", new AccountUpdateProfileRequest("Alice", null)));

            for (String method : new String[]{"GET", "GET", "PATCH"}) {
                var request = server.takeRequest();
                assertThat(request.getMethod()).isEqualTo(method);
                assertThat(request.getPath()).isEqualTo("/api/v1/auth/me/profile");
                assertThat(request.getHeader("Authorization")).isEqualTo("Bearer access-token");
                assertThat(request.getHeader("X-IAM-Client-Id")).isNull();
            }
        }
    }

    @Test
    void profileHasOnlyCurrentProducerFieldsAndNoLegacyAlias() {
        assertThat(Arrays.stream(UserProfileResponse.class.getRecordComponents())
                .map(RecordComponent::getName)).containsExactly(
                "userId", "applicationId", "globalIdentityId", "email", "emailVerified",
                "username", "displayName", "avatarUrl", "status", "createdAt", "updatedAt",
                "currentOrganization");
        assertThat(Arrays.stream(UserProfileResponse.class.getMethods()).map(method -> method.getName()))
                .doesNotContain("id", "roles", "metadata");
        for (String oldField : new String[]{"id", "roles", "metadata"}) {
            String oldValue = switch (oldField) {
                case "roles" -> "[]";
                case "metadata" -> "{}";
                default -> "\"legacy-user\"";
            };
            assertThatThrownBy(() -> new ObjectMapper().readValue(
                    "{\"" + oldField + "\":" + oldValue + "}", UserProfileResponse.class))
                    .isInstanceOf(UnrecognizedPropertyException.class);
        }
    }

    @Test
    void independentPermissionResponseRetainsRoles() throws Exception {
        try (var server = new MockWebServer()) {
            server.start();
            server.enqueue(json("""
                    {"applicationId":"app-1","organizationId":null,
                     "roles":["reader"],"permissions":["orders:read","orders:*"]}
                    """));
            var permissions = client(server).getAccountPermissionSummary("access-token", null);
            assertThat(permissions.organizationId()).isNull();
            assertThat(permissions.roles()).containsExactly("reader");
            assertThat(permissions.permissions()).containsExactly("orders:read", "orders:*");
            assertThat(server.takeRequest().getPath()).isEqualTo("/api/v1/auth/me/permissions");
        }
    }

    private static void assertNullable(UserProfileResponse profile) {
        assertThat(profile.userId()).isEqualTo("user-1");
        assertThat(profile.globalIdentityId()).isNull();
        assertThat(profile.email()).isNull();
        assertThat(profile.emailVerified()).isFalse();
        assertThat(profile.username()).isNull();
        assertThat(profile.displayName()).isNull();
        assertThat(profile.avatarUrl()).isNull();
        assertThat(profile.currentOrganization()).isNull();
    }

    private static IamClient client(MockWebServer server) {
        return new IamClient(server.url("/").toString().replaceAll("/+$", ""),
                "client-1", "fixture-secret", Duration.ofSeconds(5), new ObjectMapper());
    }

    private static MockResponse json(String body) {
        return new MockResponse().setHeader("Content-Type", "application/json").setBody(body);
    }
}
