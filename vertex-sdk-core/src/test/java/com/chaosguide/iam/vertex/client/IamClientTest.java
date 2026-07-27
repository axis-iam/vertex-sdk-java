package com.chaosguide.iam.vertex.client;

import com.chaosguide.iam.vertex.client.dto.PasswordChangeRequest;
import com.chaosguide.iam.vertex.client.dto.PermissionCheckRequest;
import com.chaosguide.iam.vertex.client.dto.PermissionDto;
import com.chaosguide.iam.vertex.client.dto.PermissionListResponse;
import com.chaosguide.iam.vertex.client.dto.ResolveRequest;
import com.chaosguide.iam.vertex.client.dto.ResolveResponse;
import com.chaosguide.iam.vertex.client.dto.UserProfileResponse;
import com.chaosguide.iam.vertex.exception.IamSdkException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.time.Duration;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IamClientTest {

    private MockWebServer server;
    private IamClient client;

    @BeforeEach
    void start() throws Exception {
        server = new MockWebServer();
        server.start();
        client = new IamClient(
                server.url("/").toString().replaceAll("/+$", ""),
                "demo-app",
                "s3cret",
                Duration.ofSeconds(5),
                new ObjectMapper());
    }

    @AfterEach
    void stop() throws Exception {
        server.shutdown();
    }

    @Test
    void resolveSendsAuthAndReturnsPermissions() throws Exception {
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("{\"permissions\":[\"posts:read\"]}"));

        ResolveResponse resp = client.resolvePermissions(new ResolveRequest("demo-app", Set.of("admin")));

        assertThat(resp.permissions()).containsExactly("posts:read");
        RecordedRequest req = server.takeRequest();
        assertThat(req.getHeader("Authorization")).startsWith("Basic ");
    }

    @Test
    void resolveThrowsOn5xx() {
        server.enqueue(new MockResponse().setResponseCode(502));
        assertThatThrownBy(() -> client.resolvePermissions(new ResolveRequest("demo-app", Set.of("admin"))))
                .isInstanceOf(IamSdkException.class)
                .hasMessageContaining("502");
    }

    @Test
    void resolveRequiresConfidentialClientSecret() {
        IamClient publicClient = new IamClient(
                server.url("/").toString().replaceAll("/+$", ""),
                "demo-app",
                null,
                Duration.ofSeconds(5),
                new ObjectMapper());

        assertThatThrownBy(() -> publicClient.resolvePermissions(new ResolveRequest("demo-app", Set.of("admin"))))
                .isInstanceOf(IamSdkException.class)
                .hasMessageContaining("confidential ApplicationClient");
        assertThat(server.getRequestCount()).isZero();
    }

    @Test
    void resolveEmptyRolesReturnsLocally() {
        assertThat(client.resolvePermissions(new ResolveRequest("demo-app", Set.of())).permissions()).isEmpty();
        assertThat(server.getRequestCount()).isZero();
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "IAM_PERMISSION_COMPATIBILITY_E2E", matches = "1")
    void realBackendSnapshotAndResolveParity() {
        String clientId = System.getenv("IAM_COMPAT_CLIENT_ID");
        IamClient live = new IamClient(
                System.getenv("IAM_COMPAT_ISSUER"), clientId, System.getenv("IAM_COMPAT_CLIENT_SECRET"),
                Duration.ofSeconds(5), new ObjectMapper());
        assertThat(live.resolvePermissions(new ResolveRequest(clientId, Set.of())).permissions()).isEmpty();
        assertThat(live.listPermissions(clientId, null).permissions())
                .containsExactly(
                        new PermissionDto("orders", "write", ""),
                        new PermissionDto("orders", "*", ""),
                        new PermissionDto("*", "*", ""));
        assertThat(live.resolvePermissions(new ResolveRequest(clientId, Set.of("m7d_reader"))).permissions())
                .containsExactlyInAnyOrder("orders:write", "orders:*", "*:*");
    }

    @Test
    void resolveRejectsMalformedResponse() {
        server.enqueue(new MockResponse().setBody("{\"permissions\":[\"posts:read\",\"posts:read\"]}"));
        assertThatThrownBy(() -> client.resolvePermissions(new ResolveRequest("demo-app", Set.of("admin"))))
                .isInstanceOf(IamSdkException.class);
    }

    @Test
    void listSendsIfNoneMatchHeader() throws Exception {
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setHeader("ETag", "\"abc123\"")
                .setBody("{\"applicationId\":\"123e4567-e89b-42d3-a456-426614174000\",\"clientId\":\"demo-app\",\"roles\":[{\"key\":\"admin\",\"name\":\"Admin\",\"permissions\":[\"posts:read\",\"posts:*\",\"*:*\"]}]}"));

        PermissionListResponse resp = client.listPermissions("demo-app", "\"prev-etag\"");

        assertThat(resp.permissions()).hasSize(3);
        assertThat(resp.etag()).isEqualTo("\"abc123\"");
        RecordedRequest req = server.takeRequest();
        assertThat(req.getHeader("If-None-Match")).isEqualTo("\"prev-etag\"");
    }

    @Test
    void listFlattensServerRolePermissionMapping() throws Exception {
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("""
                        {
                          "applicationId":"123e4567-e89b-42d3-a456-426614174000",
                          "clientId":"demo-app",
                          "roles":[
                            {"key":"admin","name":"Admin","permissions":["posts:read","posts:*","*:*"]},
                            {"key":"viewer","name":"Viewer","permissions":["posts:read"]}
                          ]
                        }
                        """));

        PermissionListResponse resp = client.listPermissions("demo-app", null);

        assertThat(resp.permissions())
                .containsExactly(
                        new PermissionDto("posts", "read", ""),
                        new PermissionDto("posts", "*", ""),
                        new PermissionDto("*", "*", ""));
    }

    @Test
    void listRejectsLegacyFlatAndMalformedSnapshots() {
        server.enqueue(new MockResponse().setBody("{\"applicationId\":\"app\",\"clientId\":\"demo-app\",\"permissions\":[]}"));
        server.enqueue(new MockResponse().setBody("{\"applicationId\":\"app\",\"clientId\":\"demo-app\",\"roles\":[{\"key\":\"admin\",\"name\":\"Admin\",\"permissions\":[\"posts\"]}]}"));

        assertThatThrownBy(() -> client.listPermissions("demo-app", null)).isInstanceOf(IamSdkException.class);
        assertThatThrownBy(() -> client.listPermissions("demo-app", null)).isInstanceOf(IamSdkException.class);
    }

    @Test
    void exhaustsSharedPermissionCompatibilityRejectVectors() throws Exception {
        JsonNode fixture = new ObjectMapper().readTree(Files.readString(
                Path.of("../../docs/fixtures/permission-compatibility-vectors.json")));
        for (JsonNode vector : fixture.path("snapshot").path("reject")) {
            server.enqueue(new MockResponse().setBody(vector.path("body").toString()));
            assertThatThrownBy(() -> client.listPermissions("orders-service", null))
                    .as(vector.path("name").asText())
                    .isInstanceOf(IamSdkException.class);
        }
        for (JsonNode vector : fixture.path("snapshot").path("rawReject")) {
            server.enqueue(new MockResponse().setBody(vector.path("body").asText()));
            assertThatThrownBy(() -> client.listPermissions("orders-service", null))
                    .as(vector.path("name").asText())
                    .isInstanceOf(IamSdkException.class);
        }
        for (JsonNode vector : fixture.path("resolve").path("reject")) {
            server.enqueue(new MockResponse().setBody(vector.path("body").toString()));
            assertThatThrownBy(() -> client.resolvePermissions(new ResolveRequest("orders-service", Set.of("admin"))))
                    .as(vector.path("name").asText())
                    .isInstanceOf(IamSdkException.class);
        }
    }

    @Test
    void acceptsSharedCanonicalSnapshotWithWildcardGrants() throws Exception {
        JsonNode fixture = new ObjectMapper().readTree(Files.readString(
                Path.of("../../docs/fixtures/permission-compatibility-vectors.json")));
        server.enqueue(new MockResponse().setBody(fixture.path("snapshot").path("valid").toString()));

        PermissionListResponse response = client.listPermissions("orders-service", null);

        assertThat(response.permissions()).containsExactly(
                new PermissionDto("orders", "read", ""),
                new PermissionDto("orders", "*", ""),
                new PermissionDto("*", "*", ""));
    }

    @Test
    void acceptsSharedResolveResponseWithWildcardGrants() throws Exception {
        JsonNode fixture = new ObjectMapper().readTree(Files.readString(
                Path.of("../../docs/fixtures/permission-compatibility-vectors.json")));
        server.enqueue(new MockResponse().setBody(fixture.path("resolve").path("valid").toString()));

        assertThat(client.resolvePermissions(new ResolveRequest("orders-service", Set.of("admin"))).permissions())
                .containsExactlyInAnyOrder("orders:read", "orders:*", "*:*");
    }

    @Test
    void listReturnsNotModifiedOn304() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(304).setHeader("ETag", "\"abc\""));

        PermissionListResponse resp = client.listPermissions("demo-app", "\"abc\"");

        assertThat(resp.permissions()).isEmpty();
        assertThat(resp.etag()).isEqualTo("\"abc\"");
    }

    @Test
    void listThrowsOnUnsuccessfulStatus() {
        server.enqueue(new MockResponse().setResponseCode(500));
        assertThatThrownBy(() -> client.listPermissions("demo-app", null))
                .isInstanceOf(IamSdkException.class);
    }

    @Test
    void listRequiresConfidentialClientSecret() {
        IamClient publicClient = new IamClient(
                server.url("/").toString().replaceAll("/+$", ""),
                "demo-app",
                "",
                Duration.ofSeconds(5),
                new ObjectMapper());

        assertThatThrownBy(() -> publicClient.listPermissions("demo-app", null))
                .isInstanceOf(IamSdkException.class)
                .hasMessageContaining("confidential ApplicationClient");
        assertThat(server.getRequestCount()).isZero();
    }

    @Test
    void getMeSendsBearerTokenAndReturnsProfile() throws Exception {
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("""
                        {
                          "userId":"user-1",
                          "applicationId":"app-1",
                          "email":"user@example.com",
                          "emailVerified":true,
                          "username":"alice",
                          "displayName":"Alice",
                          "status":"ACTIVE",
                          "currentOrganization":{"organizationId":"org-1","name":"Acme","slug":"acme","role":"ADMIN","joinedAt":"2026-07-06T00:00:00Z","current":true}
                        }
                        """));

        UserProfileResponse resp = client.getMe("Bearer user-token");

        assertThat(resp.id()).isEqualTo("user-1");
        assertThat(resp.userId()).isEqualTo("user-1");
        assertThat(resp.applicationId()).isEqualTo("app-1");
        assertThat(resp.username()).isEqualTo("alice");
        assertThat(resp.displayName()).isEqualTo("Alice");
        assertThat(resp.currentOrganization().organizationId()).isEqualTo("org-1");
        RecordedRequest req = server.takeRequest();
        assertThat(req.getPath()).isEqualTo("/api/v1/auth/me/profile");
        assertThat(req.getHeader("Authorization")).isEqualTo("Bearer user-token");
    }

    @Test
    void accountOrgAndInvitationHelpersUseBearerOrPublicContracts() throws Exception {
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("{\"emailVerified\":true,\"passwordCredentialPresent\":true,\"mfaEnrolled\":false,\"totpEnrolled\":false,\"webAuthnEnrolled\":false,\"activeSessionCount\":2}"));
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("[{\"organizationId\":\"org-1\",\"name\":\"Acme\",\"slug\":\"acme\",\"role\":\"ADMIN\",\"joinedAt\":\"2026-07-06T00:00:00Z\",\"current\":true}]"));
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("{\"organizationId\":\"org-2\",\"continuation\":\"REFRESH_OR_REAUTHENTICATE_WITH_ORGANIZATION\",\"tokenRefreshRequired\":true,\"message\":\"refresh\"}"));
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("{\"applicationId\":\"app-1\",\"applicationName\":\"Demo\",\"organizationId\":\"org-1\",\"organizationName\":\"Acme\",\"inviteeEmail\":\"a***@example.com\",\"role\":\"MEMBER\",\"status\":\"PENDING\",\"expiresAt\":\"2026-07-08T00:00:00Z\"}"));
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("{\"status\":\"LOGIN_REQUIRED\",\"continuation\":\"LOGIN_OR_REGISTER_THEN_RETRY_ACCEPT\",\"applicationId\":\"app-1\",\"organizationId\":\"org-1\",\"organizationName\":\"Acme\",\"role\":\"MEMBER\"}"));

        assertThat(client.getAccountSecuritySummary("Bearer user-token").activeSessionCount()).isEqualTo(2);
        assertThat(client.listAccountOrganizations("user-token")).hasSize(1);
        assertThat(client.switchAccountOrganization("user-token", "org-2").tokenRefreshRequired()).isTrue();
        assertThat(client.previewOrganizationInvitation("public token").organizationName()).isEqualTo("Acme");
        assertThat(client.acceptOrganizationInvitation("public token", null).status()).isEqualTo("LOGIN_REQUIRED");

        RecordedRequest security = server.takeRequest();
        assertThat(security.getPath()).isEqualTo("/api/v1/auth/me/security");
        assertThat(security.getHeader("Authorization")).isEqualTo("Bearer user-token");
        assertThat(security.getHeader("X-IAM-Client-Id")).isNull();

        RecordedRequest organizations = server.takeRequest();
        assertThat(organizations.getPath()).isEqualTo("/api/v1/auth/me/organizations");
        assertThat(organizations.getHeader("Authorization")).isEqualTo("Bearer user-token");

        RecordedRequest switchRequest = server.takeRequest();
        assertThat(switchRequest.getPath()).isEqualTo("/api/v1/auth/me/organizations/current");
        assertThat(switchRequest.getBody().readUtf8()).contains("\"organizationId\":\"org-2\"");

        RecordedRequest preview = server.takeRequest();
        assertThat(preview.getPath()).isEqualTo("/api/v1/auth/organization-invitations/public+token");
        assertThat(preview.getHeader("Authorization")).isNull();

        RecordedRequest accept = server.takeRequest();
        assertThat(accept.getPath()).isEqualTo("/api/v1/auth/organization-invitations/public+token/accept");
        assertThat(accept.getHeader("Authorization")).isNull();
    }

    @Test
    void accountPasswordSessionAndPermissionHelpersUseBearerOrPublicContracts() throws Exception {
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("{\"message\":\"If eligible, a verification email has been sent. Please wait before retrying.\",\"retryAfterSeconds\":60}"));
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("{\"message\":\"Email verified\",\"retryAfterSeconds\":null}"));
        server.enqueue(new MockResponse().setResponseCode(204));
        server.enqueue(new MockResponse().setResponseCode(204));
        server.enqueue(new MockResponse().setResponseCode(204));
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("[{\"sessionId\":\"sid-current\",\"ipAddress\":\"127.0.0.1\",\"userAgent\":\"JUnit\",\"deviceId\":null,\"createdAt\":\"2026-07-07T00:00:00Z\",\"lastSeenAt\":\"2026-07-07T01:00:00Z\",\"current\":true}]"));
        server.enqueue(new MockResponse().setResponseCode(204));
        server.enqueue(new MockResponse().setResponseCode(204));
        server.enqueue(new MockResponse().setResponseCode(204));
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("{\"applicationId\":\"app-1\",\"organizationId\":\"org-1\",\"roles\":[\"admin\"],\"permissions\":[\"orders:read\",\"orders:*\"]}"));
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("{\"applicationId\":\"app-1\",\"organizationId\":\"org-1\",\"permission\":\"orders:write\",\"allowed\":true,\"roles\":[\"admin\"]}"));

        assertThat(client.sendEmailVerification("user@example.com").retryAfterSeconds()).isEqualTo(60);
        assertThat(client.verifyEmail("verify-token").message()).isEqualTo("Email verified");
        client.changePassword("Bearer user-token", new PasswordChangeRequest("old-pass", "new-pass"));
        client.requestPasswordReset("user@example.com", "https://app.example.com/reset");
        client.resetPassword("reset-token", "new-pass");
        assertThat(client.listAccountSessions("user-token").get(0).current()).isTrue();
        client.revokeAccountSession("user-token", "sid-current");
        client.revokeOtherAccountSessions("user-token");
        client.logoutAccount("user-token", "refresh-token");
        assertThat(client.getAccountPermissionSummary("user-token", "org-1").permissions()).contains("orders:read");
        assertThat(client.checkAccountPermission(
                "user-token", new PermissionCheckRequest("orders:write", "org-1")).allowed()).isTrue();

        RecordedRequest send = server.takeRequest();
        assertThat(send.getPath()).isEqualTo("/api/v1/auth/email/verification/send");
        assertThat(send.getBody().readUtf8()).contains("\"client_id\":\"demo-app\"");
        assertThat(send.getHeader("Authorization")).isNull();

        RecordedRequest verify = server.takeRequest();
        assertThat(verify.getPath()).isEqualTo("/api/v1/auth/email/verification/verify");
        assertThat(verify.getBody().readUtf8()).contains("\"token\":\"verify-token\"");

        RecordedRequest change = server.takeRequest();
        assertThat(change.getPath()).isEqualTo("/api/v1/auth/password/change");
        assertThat(change.getHeader("Authorization")).isEqualTo("Bearer user-token");
        assertThat(change.getHeader("X-IAM-Client-Id")).isNull();

        RecordedRequest forgot = server.takeRequest();
        assertThat(forgot.getPath()).isEqualTo("/api/v1/auth/password/forgot");
        assertThat(forgot.getBody().readUtf8()).contains("\"client_id\":\"demo-app\"");

        RecordedRequest reset = server.takeRequest();
        assertThat(reset.getPath()).isEqualTo("/api/v1/auth/password/reset");

        RecordedRequest listSessions = server.takeRequest();
        assertThat(listSessions.getPath()).isEqualTo("/api/v1/auth/sessions");
        assertThat(listSessions.getHeader("Authorization")).isEqualTo("Bearer user-token");

        RecordedRequest revokeOne = server.takeRequest();
        assertThat(revokeOne.getPath()).isEqualTo("/api/v1/auth/sessions/sid-current");
        assertThat(revokeOne.getMethod()).isEqualTo("DELETE");

        RecordedRequest revokeOther = server.takeRequest();
        assertThat(revokeOther.getPath()).isEqualTo("/api/v1/auth/sessions");
        assertThat(revokeOther.getMethod()).isEqualTo("DELETE");

        RecordedRequest logout = server.takeRequest();
        assertThat(logout.getPath()).isEqualTo("/api/v1/auth/logout");
        assertThat(logout.getBody().readUtf8()).contains("\"refresh_token\":\"refresh-token\"");

        RecordedRequest summary = server.takeRequest();
        assertThat(summary.getPath()).isEqualTo("/api/v1/auth/me/permissions?organizationId=org-1");
        assertThat(summary.getHeader("X-IAM-Client-Id")).isNull();

        RecordedRequest check = server.takeRequest();
        assertThat(check.getPath()).isEqualTo("/api/v1/auth/me/permissions:check");
        assertThat(check.getBody().readUtf8()).contains("\"permission\":\"orders:write\"");
    }

    @Test
    void rejectsBlankBaseUrl() {
        assertThatThrownBy(() -> new IamClient("", "x", "y", Duration.ofSeconds(1), new ObjectMapper()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void getClientIdReturnsConfigured() {
        assertThat(client.getClientId()).isEqualTo("demo-app");
    }
}
