package com.chaosguide.iam.vertex.portal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static com.chaosguide.iam.vertex.portal.PortalOpenApiClient.PORTAL_OPENAPI_READ_SCOPE;
import static com.chaosguide.iam.vertex.portal.PortalOpenApiClient.PORTAL_OPENAPI_WRITE_SCOPE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PortalOpenApiClientTest {

    private MockWebServer server;
    private PortalOpenApiClient client;

    @BeforeEach
    void start() throws Exception {
        server = new MockWebServer();
        server.start();
        client = newClient(Duration.ZERO);
    }

    @AfterEach
    void stop() throws Exception {
        server.shutdown();
    }

    @Test
    void requestJsonUsesExplicitReadWriteScopesSeparateCachesAndBearerOnlyResourceHeaders() throws Exception {
        enqueueToken("read-token-1", PORTAL_OPENAPI_READ_SCOPE, 120);
        enqueueJson("{\"ok\":true}");
        enqueueJson("{\"ok\":true}");
        enqueueToken("write-token-1", PORTAL_OPENAPI_WRITE_SCOPE, 120);
        enqueueJson("{\"created\":true}");

        JsonNode firstRead = client.get("/open/v1/apps", JsonNode.class);
        JsonNode secondRead = client.get("/open/v1/apps", JsonNode.class);
        JsonNode write = client.post("/open/v1/apps", Map.of("name", "Demo"), JsonNode.class);

        assertThat(firstRead.path("ok").asBoolean()).isTrue();
        assertThat(secondRead.path("ok").asBoolean()).isTrue();
        assertThat(write.path("created").asBoolean()).isTrue();

        RecordedRequest readToken = server.takeRequest();
        assertThat(readToken.getPath()).isEqualTo("/oauth2/token");
        assertThat(readToken.getHeader("Authorization")).startsWith("Basic ");
        assertThat(readToken.getBody().readUtf8())
                .contains("grant_type=client_credentials")
                .contains("scope=portal%3Aopenapi%3Aread");

        RecordedRequest firstResource = server.takeRequest();
        assertResourceRequest(firstResource, "GET", "/open/v1/apps", "Bearer read-token-1");

        RecordedRequest secondResource = server.takeRequest();
        assertResourceRequest(secondResource, "GET", "/open/v1/apps", "Bearer read-token-1");

        RecordedRequest writeToken = server.takeRequest();
        assertThat(writeToken.getPath()).isEqualTo("/oauth2/token");
        assertThat(writeToken.getHeader("Authorization")).startsWith("Basic ");
        assertThat(writeToken.getBody().readUtf8())
                .contains("grant_type=client_credentials")
                .contains("scope=portal%3Aopenapi%3Awrite");

        RecordedRequest writeResource = server.takeRequest();
        assertResourceRequest(writeResource, "POST", "/open/v1/apps", "Bearer write-token-1");
        assertThat(writeResource.getBody().readUtf8()).contains("\"name\":\"Demo\"");
    }

    @Test
    void staleTokenRefreshesByScope() throws Exception {
        PortalOpenApiClient staleClient = newClient(Duration.ofSeconds(2));
        enqueueToken("read-token-1", PORTAL_OPENAPI_READ_SCOPE, 1);
        enqueueToken("read-token-2", PORTAL_OPENAPI_READ_SCOPE, 1);

        PortalOpenApiMachineToken first = staleClient.getMachineToken(PORTAL_OPENAPI_READ_SCOPE);
        PortalOpenApiMachineToken second = staleClient.getMachineToken(PORTAL_OPENAPI_READ_SCOPE);

        assertThat(first.accessToken()).isEqualTo("read-token-1");
        assertThat(second.accessToken()).isEqualTo("read-token-2");
        assertThat(server.takeRequest().getPath()).isEqualTo("/oauth2/token");
        assertThat(server.takeRequest().getPath()).isEqualTo("/oauth2/token");
    }

    @Test
    void clearTokenCacheCanEvictOneScope() throws Exception {
        enqueueToken("read-token-1", PORTAL_OPENAPI_READ_SCOPE, 120);
        enqueueToken("write-token-1", PORTAL_OPENAPI_WRITE_SCOPE, 120);
        enqueueToken("read-token-2", PORTAL_OPENAPI_READ_SCOPE, 120);

        assertThat(client.getMachineToken(PORTAL_OPENAPI_READ_SCOPE).accessToken()).isEqualTo("read-token-1");
        assertThat(client.getMachineToken(PORTAL_OPENAPI_WRITE_SCOPE).accessToken()).isEqualTo("write-token-1");
        client.clearTokenCache(PORTAL_OPENAPI_READ_SCOPE);

        assertThat(client.getMachineToken(PORTAL_OPENAPI_READ_SCOPE).accessToken()).isEqualTo("read-token-2");
        assertThat(client.getMachineToken(PORTAL_OPENAPI_WRITE_SCOPE).accessToken()).isEqualTo("write-token-1");
        assertThat(server.getRequestCount()).isEqualTo(3);
    }

    @Test
    void rejectsUnsupportedScopeBeforeHttp() {
        assertThatThrownBy(() -> client.getMachineToken("openid"))
                .isInstanceOf(PortalOpenApiTokenException.class)
                .hasMessageContaining("Unsupported Portal Open API scope");
        assertThatThrownBy(() -> client.getMachineToken(""))
                .isInstanceOf(PortalOpenApiTokenException.class)
                .hasMessageContaining("explicit scope");
        assertThat(server.getRequestCount()).isZero();
    }

    @Test
    void rejectsInvalidPathMethodAndManagedHeadersBeforeResourceCall() throws Exception {
        assertThatThrownBy(() -> client.get("/api/v1/apps", JsonNode.class))
                .isInstanceOf(PortalOpenApiException.class)
                .satisfies(error -> assertThat(((PortalOpenApiException) error).getCode())
                        .isEqualTo("invalid_portal_path"));

        assertThatThrownBy(() -> client.requestJson("OPTIONS", "/open/v1/apps", null, JsonNode.class))
                .isInstanceOf(PortalOpenApiException.class)
                .satisfies(error -> assertThat(((PortalOpenApiException) error).getCode())
                        .isEqualTo("invalid_portal_method"));

        assertThatThrownBy(() -> client.requestJson(
                        "GET",
                        "/open/v1/apps",
                        null,
                        JsonNode.class,
                        Map.of("X-Application-Id", "stale-app-id")))
                .isInstanceOf(PortalOpenApiException.class)
                .satisfies(error -> assertThat(((PortalOpenApiException) error).getCode())
                        .isEqualTo("invalid_portal_header"));
        assertThat(server.getRequestCount()).isZero();
    }

    @Test
    void tokenErrorIncludesStatusCodeAndCode() {
        server.enqueue(new MockResponse()
                .setResponseCode(400)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"error\":\"invalid_scope\",\"error_description\":\"scope denied\"}"));

        assertThatThrownBy(() -> client.getMachineToken(PORTAL_OPENAPI_READ_SCOPE))
                .isInstanceOf(PortalOpenApiTokenException.class)
                .satisfies(error -> {
                    PortalOpenApiTokenException tokenError = (PortalOpenApiTokenException) error;
                    assertThat(tokenError.getStatusCode()).isEqualTo(400);
                    assertThat(tokenError.getCode()).isEqualTo("invalid_scope");
                    assertThat(tokenError.getBody()).contains("scope denied");
                });
    }

    @Test
    void tokenResponseMustIncludeRequestedScope() {
        enqueueToken("read-token-1", PORTAL_OPENAPI_READ_SCOPE, 120);

        assertThatThrownBy(() -> client.getMachineToken(PORTAL_OPENAPI_WRITE_SCOPE))
                .isInstanceOf(PortalOpenApiTokenException.class)
                .satisfies(error -> assertThat(((PortalOpenApiTokenException) error).getCode())
                        .isEqualTo("invalid_scope"));
    }

    @Test
    void resourceErrorIncludesStatusCodeAndPortalCode() {
        enqueueToken("read-token-1", PORTAL_OPENAPI_READ_SCOPE, 120);
        server.enqueue(new MockResponse()
                .setResponseCode(403)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"code\":\"OPEN_API_SCOPE_INSUFFICIENT\",\"message\":\"need write\"}"));

        assertThatThrownBy(() -> client.get("/open/v1/apps", JsonNode.class))
                .isInstanceOf(PortalOpenApiException.class)
                .satisfies(error -> {
                    PortalOpenApiException portalError = (PortalOpenApiException) error;
                    assertThat(portalError.getStatusCode()).isEqualTo(403);
                    assertThat(portalError.getCode()).isEqualTo("OPEN_API_SCOPE_INSUFFICIENT");
                    assertThat(portalError.getBody()).contains("need write");
                });
    }

    @Test
    void registrationGrantHelpersUseExactScopesAndRejectDoubleProof() throws Exception {
        enqueueToken("grant-read", PortalOpenApiClient.REGISTRATION_GRANTS_READ_SCOPE, 120);
        enqueueJson("{\"content\":[],\"page\":{\"size\":20,\"number\":0,\"totalElements\":0,\"totalPages\":0}}");
        enqueueToken("grant-write", PortalOpenApiClient.REGISTRATION_GRANTS_WRITE_SCOPE, 120);
        enqueueJson("{\"grant\":{\"type\":\"EMAIL_LINK\"},\"registrationGrantToken\":\"test-token\",\"registrationAccessCode\":\"12345678\"}");
        enqueueToken("redemptions", PortalOpenApiClient.REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE, 120);
        enqueueJson("{\"content\":[],\"page\":{\"size\":20,\"number\":0,\"totalElements\":0,\"totalPages\":0}}");

        client.listRegistrationGrants(null);
        assertThatThrownBy(() -> client.createRegistrationGrant(new CreateRegistrationGrantRequest(
                        CreateRegistrationGrantType.EMAIL_LINK, null, null, null, null, null)))
                .isInstanceOf(PortalOpenApiException.class)
                .satisfies(error -> assertThat(((PortalOpenApiException) error).getCode())
                        .isEqualTo("invalid_registration_grant_response"));
        client.listRegistrationGrantRedemptions("123e4567-e89b-12d3-a456-426614174000", null);

        assertThat(server.takeRequest().getBody().readUtf8()).contains("registration_grants%3Aread");
        server.takeRequest();
        assertThat(server.takeRequest().getBody().readUtf8()).contains("registration_grants%3Awrite");
        server.takeRequest();
        assertThat(server.takeRequest().getBody().readUtf8()).contains("registration_grants%3Aredemptions%3Aread");
    }

    @Test
    void registrationGrantListEncodesFiltersAndParsesOrgInvitation() throws Exception {
        enqueueToken("grant-read", PortalOpenApiClient.REGISTRATION_GRANTS_READ_SCOPE, 120);
        enqueueJson("{\"content\":[" + grantJson("ORG_INVITATION") + "],\"page\":{\"size\":25,\"number\":2,\"totalElements\":1,\"totalPages\":1}}");

        RegistrationGrantPage page = client.listRegistrationGrants(new RegistrationGrantListOptions(
                RegistrationGrantType.ORG_INVITATION, RegistrationGrantStatus.ACTIVE, "a+b & c", 2, 25));

        assertThat(page.content()).singleElement().extracting(RegistrationGrant::type)
                .isEqualTo(RegistrationGrantType.ORG_INVITATION);
        assertThat(server.takeRequest().getBody().readUtf8()).contains("registration_grants%3Aread");
        assertResourceRequest(server.takeRequest(), "GET",
                "/open/v1/registration-grants?type=ORG_INVITATION&status=ACTIVE&search=a%2Bb+%26+c&page=2&size=25",
                "Bearer grant-read");
    }

    @Test
    void registrationGrantCreateEmailLinkAcceptsNullAccessCode() throws Exception {
        enqueueToken("grant-write", PortalOpenApiClient.REGISTRATION_GRANTS_WRITE_SCOPE, 120);
        enqueueJson("{\"grant\":" + grantJson("EMAIL_LINK")
                + ",\"registrationGrantToken\":\"fake-one-time-proof\",\"registrationAccessCode\":null}");

        CreatedRegistrationGrant created = client.createRegistrationGrant(new CreateRegistrationGrantRequest(
                CreateRegistrationGrantType.EMAIL_LINK, null, null, null, null, null));

        assertThat(created.registrationGrantToken()).isEqualTo("fake-one-time-proof");
        assertThat(created.registrationAccessCode()).isNull();
        assertThat(server.takeRequest().getBody().readUtf8()).contains("registration_grants%3Awrite");
        RecordedRequest request = server.takeRequest();
        assertResourceRequest(request, "POST", "/open/v1/registration-grants", "Bearer grant-write");
        assertThat(request.getBody().readUtf8()).isEqualTo("{\"type\":\"EMAIL_LINK\"}");
    }

    @Test
    void registrationGrantCreateAccessCodeAcceptsNullToken() throws Exception {
        enqueueToken("grant-write", PortalOpenApiClient.REGISTRATION_GRANTS_WRITE_SCOPE, 120);
        enqueueJson("{\"grant\":" + grantJson("ACCESS_CODE")
                + ",\"registrationGrantToken\":null,\"registrationAccessCode\":\"fake-one-time-proof\"}");

        CreatedRegistrationGrant created = client.createRegistrationGrant(new CreateRegistrationGrantRequest(
                CreateRegistrationGrantType.ACCESS_CODE, null, null, null, null, null));

        assertThat(created.registrationGrantToken()).isNull();
        assertThat(created.registrationAccessCode()).isEqualTo("fake-one-time-proof");
        server.takeRequest();
        assertResourceRequest(server.takeRequest(), "POST", "/open/v1/registration-grants", "Bearer grant-write");
    }

    @Test
    void registrationGrantCreateRejectsZeroBlankAndTypeMismatchedProofs() {
        assertInvalidCreate("{\"grant\":" + grantJson("EMAIL_LINK") + ",\"registrationGrantToken\":null,\"registrationAccessCode\":null}");
        assertInvalidCreate("{\"grant\":" + grantJson("EMAIL_LINK") + ",\"registrationGrantToken\":\"fake-token\",\"registrationAccessCode\":\"fake-code\"}");
        assertInvalidCreate("{\"grant\":" + grantJson("EMAIL_LINK") + ",\"registrationGrantToken\":\"\",\"registrationAccessCode\":null}");
        assertInvalidCreate("{\"grant\":" + grantJson("EMAIL_LINK") + ",\"registrationGrantToken\":null,\"registrationAccessCode\":\"fake-code\"}");
        assertInvalidCreate("{\"grant\":" + grantJson("ORG_INVITATION") + ",\"registrationGrantToken\":\"fake-token\",\"registrationAccessCode\":null}");
    }

    @Test
    void registrationGrantDetailLifecycleRevokeAndRedemptionUseContractVectors() throws Exception {
        String id = "019f4cca-88f8-7e77-a67d-4a6a2a68b803";
        enqueueToken("grant-read", PortalOpenApiClient.REGISTRATION_GRANTS_READ_SCOPE, 120);
        enqueueJson(grantJson("ORG_INVITATION"));
        enqueueToken("grant-write", PortalOpenApiClient.REGISTRATION_GRANTS_WRITE_SCOPE, 120);
        enqueueJson(grantJson("EMAIL_LINK"));
        enqueueJson(grantJson("EMAIL_LINK"));
        enqueueJson(grantJson("EMAIL_LINK"));
        enqueueJson(grantJson("EMAIL_LINK"));
        enqueueToken("grant-redemptions", PortalOpenApiClient.REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE, 120);
        enqueueJson("{\"content\":[],\"page\":{\"size\":10,\"number\":1,\"totalElements\":0,\"totalPages\":0}}");

        assertThat(client.getRegistrationGrant(id).type()).isEqualTo(RegistrationGrantType.ORG_INVITATION);
        client.pauseRegistrationGrant(id);
        client.resumeRegistrationGrant(id);
        client.revokeRegistrationGrant(id, null);
        client.revokeRegistrationGrant(id, "expired request");
        client.listRegistrationGrantRedemptions(id, new RegistrationGrantPageOptions(1, 10));

        server.takeRequest();
        assertResourceRequest(server.takeRequest(), "GET", "/open/v1/registration-grants/" + id, "Bearer grant-read");
        server.takeRequest();
        assertResourceRequest(server.takeRequest(), "POST", "/open/v1/registration-grants/" + id + "/pause", "Bearer grant-write");
        assertResourceRequest(server.takeRequest(), "POST", "/open/v1/registration-grants/" + id + "/resume", "Bearer grant-write");
        RecordedRequest revokeWithoutReason = server.takeRequest();
        assertResourceRequest(revokeWithoutReason, "POST", "/open/v1/registration-grants/" + id + "/revoke", "Bearer grant-write");
        assertThat(revokeWithoutReason.getBody().readUtf8()).isEmpty();
        RecordedRequest revokeWithReason = server.takeRequest();
        assertResourceRequest(revokeWithReason, "POST", "/open/v1/registration-grants/" + id + "/revoke", "Bearer grant-write");
        assertThat(revokeWithReason.getBody().readUtf8()).isEqualTo("{\"reason\":\"expired request\"}");
        server.takeRequest();
        assertResourceRequest(server.takeRequest(), "GET", "/open/v1/registration-grants/" + id + "/redemptions?page=1&size=10", "Bearer grant-redemptions");
    }

    @Test
    void registrationGrantUuidv7IsAcceptedAndNoncanonicalIdsFailLocally() {
        String uuidV7 = "019f4cca-88f8-7e77-a67d-4a6a2a68b803";
        enqueueToken("grant-read", PortalOpenApiClient.REGISTRATION_GRANTS_READ_SCOPE, 120);
        enqueueJson(grantJson("EMAIL_LINK"));

        client.getRegistrationGrant(uuidV7);
        assertThatThrownBy(() -> client.getRegistrationGrant("019f4cca88f87e77a67d4a6a2a68b803"))
                .isInstanceOf(PortalOpenApiException.class)
                .satisfies(error -> assertThat(((PortalOpenApiException) error).getCode())
                        .isEqualTo("invalid_registration_grant_id"));
        assertThat(server.getRequestCount()).isEqualTo(2);
    }

    @Test
    void registrationGrantBackend403404And409Propagate() {
        enqueueToken("grant-read", PortalOpenApiClient.REGISTRATION_GRANTS_READ_SCOPE, 120);
        for (int status : new int[] {403, 404, 409}) {
            server.enqueue(new MockResponse().setResponseCode(status).setHeader("Content-Type", "application/json")
                    .setBody("{\"error\":\"CONTRACT_ERROR\",\"message\":\"safe error\"}"));
            assertThatThrownBy(() -> client.getRegistrationGrant("019f4cca-88f8-7e77-a67d-4a6a2a68b803"))
                    .isInstanceOf(PortalOpenApiException.class)
                    .satisfies(error -> {
                        PortalOpenApiException portalError = (PortalOpenApiException) error;
                        assertThat(portalError.getStatusCode()).isEqualTo(status);
                        assertThat(portalError.getCode()).isEqualTo("CONTRACT_ERROR");
                    });
        }
    }

    @Test
    void registrationGrantExactScopeTokenCacheEntriesAreIsolated() {
        enqueueToken("grant-read", PortalOpenApiClient.REGISTRATION_GRANTS_READ_SCOPE, 120);
        enqueueToken("grant-write", PortalOpenApiClient.REGISTRATION_GRANTS_WRITE_SCOPE, 120);
        enqueueToken("grant-redemptions", PortalOpenApiClient.REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE, 120);

        client.getMachineToken(PortalOpenApiClient.REGISTRATION_GRANTS_READ_SCOPE);
        client.getMachineToken(PortalOpenApiClient.REGISTRATION_GRANTS_WRITE_SCOPE);
        client.getMachineToken(PortalOpenApiClient.REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE);
        client.getMachineToken(PortalOpenApiClient.REGISTRATION_GRANTS_READ_SCOPE);
        client.getMachineToken(PortalOpenApiClient.REGISTRATION_GRANTS_WRITE_SCOPE);
        client.getMachineToken(PortalOpenApiClient.REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE);

        assertThat(server.getRequestCount()).isEqualTo(3);
    }

    @Test
    void organizationManagementHelpersUseExactScopesHeadersAndPaths() throws Exception {
        String organizationId = "123e4567-e89b-42d3-a456-426614174000";
        String invitationId = "223e4567-e89b-42d3-a456-426614174000";
        String membershipId = "323e4567-e89b-42d3-a456-426614174000";

        enqueueToken("organizations-read", PortalOpenApiClient.ORGANIZATIONS_READ_SCOPE, 120);
        enqueueJson("{\"content\":[" + organizationJson(organizationId) + "],\"page\":{\"size\":10,\"number\":1,\"totalElements\":1,\"totalPages\":1}}");
        enqueueToken("organizations-write", PortalOpenApiClient.ORGANIZATIONS_WRITE_SCOPE, 120);
        server.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setHeader("ETag", "\"7\"")
                .setBody(organizationJson(organizationId)));
        server.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setHeader("ETag", "\"7\"")
                .setBody(organizationJson(organizationId)));
        server.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setHeader("ETag", "\"8\"")
                .setBody(organizationJson(organizationId)));
        server.enqueue(new MockResponse().setResponseCode(204));
        enqueueToken("invitations-read", PortalOpenApiClient.ORGANIZATION_INVITATIONS_READ_SCOPE, 120);
        enqueueJson("{\"content\":[" + invitationJson(invitationId) + "],\"page\":{\"size\":10,\"number\":1,\"totalElements\":1,\"totalPages\":1}}");
        enqueueToken("invitations-write", PortalOpenApiClient.ORGANIZATION_INVITATIONS_WRITE_SCOPE, 120);
        enqueueJson(invitationJson(invitationId));
        enqueueJson(invitationJson(invitationId));
        enqueueJson(invitationJson(invitationId));
        server.enqueue(new MockResponse().setResponseCode(204));
        enqueueToken("members-read", PortalOpenApiClient.ORGANIZATION_MEMBERS_READ_SCOPE, 120);
        enqueueJson("{\"content\":[" + memberJson(membershipId) + "],\"page\":{\"size\":10,\"number\":1,\"totalElements\":1,\"totalPages\":1}}");
        enqueueJson(memberJson(membershipId));
        enqueueToken("members-write", PortalOpenApiClient.ORGANIZATION_MEMBERS_WRITE_SCOPE, 120);
        enqueueJson(memberJson(membershipId));
        server.enqueue(new MockResponse().setResponseCode(204));

        OpenOrganizationPage organizations = client.listOrganizations(new OrganizationListOptions(
                "acme & co", 1, 10, List.of("name", "slug"),
                List.of(OrganizationSortDirection.ASC, OrganizationSortDirection.DESC)));
        assertThat(organizations.content()).singleElement().extracting(OpenOrganization::slug).isEqualTo("acme");
        OpenOrganization created = client.createOrganization(new CreateOrganizationRequest("Acme", "acme"), "org-create-1");
        assertThat(created.etag()).isEqualTo("\"7\"");
        client.getOrganization(organizationId);
        client.updateOrganization(organizationId, new UpdateOrganizationRequest("Acme Inc.", null), "\"7\"");
        client.deleteOrganization(organizationId, "\"8\"");
        client.listOrganizationInvitations(organizationId, new OrganizationInvitationListOptions(
                OrganizationInvitationStatus.PENDING, 1, 10));
        client.createOrganizationInvitation(organizationId,
                new CreateOrganizationInvitationRequest("member@example.test", OrganizationMemberRole.ADMIN, false),
                "invite-create-1");
        client.getOrganizationInvitation(organizationId, invitationId);
        client.resendOrganizationInvitation(organizationId, invitationId);
        client.cancelOrganizationInvitation(organizationId, invitationId);
        client.listOrganizationMembers(organizationId, new OrganizationMemberListOptions("member", 1, 10));
        client.getOrganizationMember(organizationId, membershipId);
        client.updateOrganizationMemberRole(organizationId, membershipId, OrganizationMemberRole.ADMIN, "\"2\"");
        client.removeOrganizationMember(organizationId, membershipId);

        assertThat(server.takeRequest().getBody().readUtf8()).contains("organizations%3Aread");
        assertResourceRequest(server.takeRequest(), "GET", "/open/v1/organizations?search=acme+%26+co&page=1&size=10&sort=name&sort=slug&direction=ASC&direction=DESC", "Bearer organizations-read");
        assertThat(server.takeRequest().getBody().readUtf8()).contains("organizations%3Awrite");
        RecordedRequest create = server.takeRequest();
        assertResourceRequest(create, "POST", "/open/v1/organizations", "Bearer organizations-write");
        assertThat(create.getHeader("Idempotency-Key")).isEqualTo("org-create-1");
        assertResourceRequest(server.takeRequest(), "GET", "/open/v1/organizations/" + organizationId, "Bearer organizations-read");
        RecordedRequest update = server.takeRequest();
        assertResourceRequest(update, "PATCH", "/open/v1/organizations/" + organizationId, "Bearer organizations-write");
        assertThat(update.getHeader("If-Match")).isEqualTo("\"7\"");
        RecordedRequest delete = server.takeRequest();
        assertResourceRequest(delete, "DELETE", "/open/v1/organizations/" + organizationId, "Bearer organizations-write");
        assertThat(delete.getHeader("If-Match")).isEqualTo("\"8\"");
        assertThat(server.takeRequest().getBody().readUtf8()).contains("organization_invitations%3Aread");
        assertResourceRequest(server.takeRequest(), "GET", "/open/v1/organizations/" + organizationId + "/invitations?status=PENDING&page=1&size=10", "Bearer invitations-read");
        assertThat(server.takeRequest().getBody().readUtf8()).contains("organization_invitations%3Awrite");
        RecordedRequest createInvitation = server.takeRequest();
        assertResourceRequest(createInvitation, "POST", "/open/v1/organizations/" + organizationId + "/invitations", "Bearer invitations-write");
        assertThat(createInvitation.getHeader("Idempotency-Key")).isEqualTo("invite-create-1");
        assertResourceRequest(server.takeRequest(), "GET", "/open/v1/organizations/" + organizationId + "/invitations/" + invitationId, "Bearer invitations-read");
        assertResourceRequest(server.takeRequest(), "POST", "/open/v1/organizations/" + organizationId + "/invitations/" + invitationId + "/resend", "Bearer invitations-write");
        assertResourceRequest(server.takeRequest(), "DELETE", "/open/v1/organizations/" + organizationId + "/invitations/" + invitationId, "Bearer invitations-write");
        assertThat(server.takeRequest().getBody().readUtf8()).contains("organization_members%3Aread");
        assertResourceRequest(server.takeRequest(), "GET", "/open/v1/organizations/" + organizationId + "/members?search=member&page=1&size=10", "Bearer members-read");
        assertResourceRequest(server.takeRequest(), "GET", "/open/v1/organizations/" + organizationId + "/members/" + membershipId, "Bearer members-read");
        assertThat(server.takeRequest().getBody().readUtf8()).contains("organization_members%3Awrite");
        RecordedRequest updateMember = server.takeRequest();
        assertResourceRequest(updateMember, "PATCH", "/open/v1/organizations/" + organizationId + "/members/" + membershipId, "Bearer members-write");
        assertThat(updateMember.getHeader("If-Match")).isEqualTo("\"2\"");
        assertResourceRequest(server.takeRequest(), "DELETE", "/open/v1/organizations/" + organizationId + "/members/" + membershipId, "Bearer members-write");
    }

    @Test
    void organizationInvitationRetryAndLastOwnerErrorsRemainTyped() {
        String organizationId = "123e4567-e89b-42d3-a456-426614174000";
        String invitationId = "223e4567-e89b-42d3-a456-426614174000";
        String membershipId = "323e4567-e89b-42d3-a456-426614174000";
        enqueueToken("invitations-write", PortalOpenApiClient.ORGANIZATION_INVITATIONS_WRITE_SCOPE, 120);
        server.enqueue(new MockResponse().setResponseCode(429).setHeader("Content-Type", "application/json")
                .setHeader("Retry-After", "30").setBody("{\"error\":\"CONFLICT\",\"message\":\"terminal invitation\"}"));

        assertThatThrownBy(() -> client.resendOrganizationInvitation(organizationId, invitationId))
                .isInstanceOf(PortalOpenApiException.class)
                .satisfies(error -> {
                    PortalOpenApiException portalError = (PortalOpenApiException) error;
                    assertThat(portalError.getStatusCode()).isEqualTo(429);
                    assertThat(portalError.getRetryAfter()).isEqualTo("30");
                });

        enqueueToken("members-write", PortalOpenApiClient.ORGANIZATION_MEMBERS_WRITE_SCOPE, 120);
        server.enqueue(new MockResponse().setResponseCode(400).setHeader("Content-Type", "application/json")
                .setBody("{\"error\":\"BAD_REQUEST\",\"message\":\"Cannot remove the last OWNER\"}"));
        assertThatThrownBy(() -> client.removeOrganizationMember(organizationId, membershipId))
                .isInstanceOf(PortalOpenApiException.class)
                .satisfies(error -> assertThat(((PortalOpenApiException) error).getCode()).isEqualTo("BAD_REQUEST"));
    }

    @Test
    void validatesConfig() {
        assertThatThrownBy(() -> PortalOpenApiClientConfig.builder().build())
                .isInstanceOf(PortalOpenApiConfigException.class)
                .hasMessageContaining("issuer");

        assertThatThrownBy(() -> PortalOpenApiClientConfig.builder()
                        .issuer("https://issuer.example.com")
                        .portalEndpoint("https://portal.example.com")
                        .clientId("client-id")
                        .clientSecret("secret")
                        .timeout(Duration.ZERO)
                        .build())
                .isInstanceOf(PortalOpenApiConfigException.class)
                .hasMessageContaining("timeout");

        assertThatThrownBy(() -> PortalOpenApiClientConfig.builder()
                        .issuer("https://issuer.example.com")
                        .portalEndpoint("https://portal.example.com")
                        .clientId("client-id")
                        .clientSecret("secret")
                        .tokenSkew(Duration.ofSeconds(-1))
                        .build())
                .isInstanceOf(PortalOpenApiConfigException.class)
                .hasMessageContaining("tokenSkew");
    }

    @Test
    void authorizationManagementUsesEightSeparateExactScopeTokensAndRejectsMalformedInputs() throws Exception {
        List<String> scopes = List.of(
                PortalOpenApiClient.ROLES_READ_SCOPE, PortalOpenApiClient.ROLES_WRITE_SCOPE,
                PortalOpenApiClient.PERMISSIONS_READ_SCOPE, PortalOpenApiClient.PERMISSIONS_WRITE_SCOPE,
                PortalOpenApiClient.ROLE_PERMISSIONS_READ_SCOPE, PortalOpenApiClient.ROLE_PERMISSIONS_WRITE_SCOPE,
                PortalOpenApiClient.USER_ROLES_READ_SCOPE, PortalOpenApiClient.USER_ROLES_WRITE_SCOPE);
        for (String scope : scopes) enqueueToken(scope + "-token", scope, 120);
        for (String scope : scopes) assertThat(client.getMachineToken(scope).scope()).isEqualTo(scope);
        for (String scope : scopes) {
            RecordedRequest request = server.takeRequest();
            assertThat(request.getPath()).isEqualTo("/oauth2/token");
            assertThat(request.getBody().readUtf8()).contains("scope=" + scope.replace(":", "%3A"));
        }
        assertThatThrownBy(() -> client.createPermission(
                new CreateOpenPermissionRequest("*", "read", "invalid", null), null))
                .isInstanceOf(PortalOpenApiException.class)
                .extracting("code").isEqualTo("invalid_authorization_response");
        assertThatThrownBy(() -> client.updateRole(
                "123e4567-e89b-42d3-a456-426614174000", new UpdateOpenRoleRequest(null, "x", null), "W/\"1\""))
                .isInstanceOf(PortalOpenApiException.class)
                .extracting("code").isEqualTo("invalid_authorization_response");
        assertThatThrownBy(() -> client.listRoles(new AuthorizationPageOptions(0, 101)))
                .isInstanceOf(PortalOpenApiException.class);
    }

    @Test
    void authorizationManagementListsFailClosedForMalformedItemsAndPageMetadata() {
        assertMalformedAuthorizationList(PortalOpenApiClient.ROLES_READ_SCOPE,
                "{\"content\":[%s],\"page\":%s}".formatted(roleJson("not-a-uuid", "2026-07-15T00:00:00Z"), pageJson(20, 1)),
                () -> client.listRoles(AuthorizationPageOptions.defaults()));
        assertMalformedAuthorizationList(PortalOpenApiClient.ROLES_READ_SCOPE,
                "{\"content\":[%s],\"page\":%s}".formatted(roleJson("123e4567-e89b-42d3-a456-426614174000", "yesterday"), pageJson(20, 1)),
                () -> client.listRoles(AuthorizationPageOptions.defaults()));
        assertMalformedAuthorizationList(PortalOpenApiClient.ROLES_READ_SCOPE,
                "{\"content\":[%s],\"page\":%s}".formatted(roleJson("123e4567-e89b-42d3-a456-426614174000", "2026-07-15T00:00:00Z"), pageJson(1000, 1)),
                () -> client.listRoles(AuthorizationPageOptions.defaults()));
        assertMalformedAuthorizationList(PortalOpenApiClient.ROLES_READ_SCOPE,
                "{\"content\":[%s],\"page\":{\"size\":1,\"number\":1,\"totalElements\":1,\"totalPages\":1}}".formatted(roleJson("123e4567-e89b-42d3-a456-426614174000", "2026-07-15T00:00:00Z")),
                () -> client.listRoles(AuthorizationPageOptions.defaults()));
        assertMalformedAuthorizationList(PortalOpenApiClient.ROLES_READ_SCOPE,
                "{\"content\":[%s],\"page\":{\"size\":2,\"number\":0,\"totalElements\":2,\"totalPages\":1}}".formatted(roleJson("123e4567-e89b-42d3-a456-426614174000", "2026-07-15T00:00:00Z")),
                () -> client.listRoles(AuthorizationPageOptions.defaults()));
        assertMalformedAuthorizationList(PortalOpenApiClient.PERMISSIONS_READ_SCOPE,
                "{\"content\":[{\"id\":\"223e4567-e89b-42d3-a456-426614174000\",\"resource\":\"orders\",\"action\":\"read\",\"key\":\"orders:read\",\"name\":\"Read\",\"description\":null,\"source\":\"CUSTOM\",\"version\":1,\"createdAt\":\"2026-07-15T00:00:00Z\",\"updatedAt\":\"2026-07-15T00:00:00Z\"}],\"page\":%s}".formatted(pageJson(20, 1)),
                () -> client.listPermissions(AuthorizationPageOptions.defaults()));
        assertMalformedAuthorizationList(PortalOpenApiClient.PERMISSIONS_READ_SCOPE,
                "{\"content\":[{\"id\":\"223e4567-e89b-42d3-a456-426614174000\",\"resource\":\"Orders\",\"action\":\"read\",\"key\":\"Orders:read\",\"name\":\"Read\",\"description\":null,\"source\":\"MANUAL\",\"version\":1,\"createdAt\":\"2026-07-15T00:00:00Z\",\"updatedAt\":\"2026-07-15T00:00:00Z\"}],\"page\":%s}".formatted(pageJson(20, 1)),
                () -> client.listPermissions(AuthorizationPageOptions.defaults()));
        assertMalformedAuthorizationList(PortalOpenApiClient.USER_ROLES_READ_SCOPE,
                "{\"content\":[{\"id\":\"423e4567-e89b-42d3-a456-426614174000\",\"userId\":\"323e4567-e89b-42d3-a456-426614174000\",\"roleId\":\"bad-role\",\"organizationId\":null,\"conditionExpression\":null,\"conditionDescription\":null,\"version\":1,\"createdAt\":\"2026-07-15T00:00:00Z\",\"updatedAt\":\"2026-07-15T00:00:00Z\"}],\"page\":%s}".formatted(pageJson(20, 1)),
                () -> client.listUserRoles("323e4567-e89b-42d3-a456-426614174000", AuthorizationPageOptions.defaults()));
        assertMalformedAuthorizationList(PortalOpenApiClient.USER_ROLES_READ_SCOPE,
                "{\"content\":[{\"id\":\"423e4567-e89b-42d3-a456-426614174000\",\"userId\":\"523e4567-e89b-42d3-a456-426614174000\",\"roleId\":\"123e4567-e89b-42d3-a456-426614174000\",\"organizationId\":null,\"conditionExpression\":null,\"conditionDescription\":null,\"version\":1,\"createdAt\":\"2026-07-15T00:00:00Z\",\"updatedAt\":\"2026-07-15T00:00:00Z\"}],\"page\":%s}".formatted(pageJson(20, 1)),
                () -> client.listUserRoles("323e4567-e89b-42d3-a456-426614174000", AuthorizationPageOptions.defaults()));

        enqueueToken("binding-read", PortalOpenApiClient.ROLE_PERMISSIONS_READ_SCOPE, 120);
        server.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setHeader("ETag", "\"1\"")
                .setBody("{\"content\":[{\"roleId\":\"bad-role\",\"permissionId\":\"223e4567-e89b-42d3-a456-426614174000\",\"createdAt\":\"2026-07-15T00:00:00Z\"}],\"page\":" + pageJson(20, 1) + "}"));
        assertAuthorizationResponseError(() -> client.listRolePermissions(
                "123e4567-e89b-42d3-a456-426614174000", AuthorizationPageOptions.defaults()));
        server.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setHeader("ETag", "\"1\"")
                .setBody("{\"content\":[{\"roleId\":\"523e4567-e89b-42d3-a456-426614174000\",\"permissionId\":\"223e4567-e89b-42d3-a456-426614174000\",\"createdAt\":\"2026-07-15T00:00:00Z\"}],\"page\":" + pageJson(20, 1) + "}"));
        assertAuthorizationResponseError(() -> client.listRolePermissions(
                "123e4567-e89b-42d3-a456-426614174000", AuthorizationPageOptions.defaults()));
    }

    @Test
    void authorizationManagementBindsObjectIdentityAndRequiresPageScalars() {
        String roleId = "123e4567-e89b-42d3-a456-426614174000";
        String permissionId = "223e4567-e89b-42d3-a456-426614174000";
        String userId = "323e4567-e89b-42d3-a456-426614174000";
        String assignmentId = "423e4567-e89b-42d3-a456-426614174000";
        String wrongId = "523e4567-e89b-42d3-a456-426614174000";
        String timestamp = "2026-07-15T00:00:00Z";
        enqueueToken("role-read", PortalOpenApiClient.ROLES_READ_SCOPE, 120);
        server.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setHeader("ETag", "\"1\"")
                .setBody(roleJson(wrongId, timestamp)));
        assertAuthorizationResponseError(() -> client.getRole(roleId));

        enqueueToken("role-write", PortalOpenApiClient.ROLES_WRITE_SCOPE, 120);
        enqueueAuthorizationObject(roleJson(wrongId, timestamp));
        assertAuthorizationResponseError(() -> client.updateRole(roleId, new UpdateOpenRoleRequest(null, "x", null), "\"0\""));

        String permission = "{\"id\":\"%s\",\"resource\":\"orders\",\"action\":\"read\",\"key\":\"orders:read\",\"name\":\"Read\",\"description\":null,\"source\":\"MANUAL\",\"version\":0,\"createdAt\":\"%s\",\"updatedAt\":\"%s\"}".formatted(wrongId, timestamp, timestamp);
        enqueueToken("permission-read", PortalOpenApiClient.PERMISSIONS_READ_SCOPE, 120);
        enqueueAuthorizationObject(permission);
        assertAuthorizationResponseError(() -> client.getPermission(permissionId));
        enqueueToken("permission-write", PortalOpenApiClient.PERMISSIONS_WRITE_SCOPE, 120);
        enqueueAuthorizationObject(permission);
        assertAuthorizationResponseError(() -> client.updatePermission(permissionId, new UpdateOpenPermissionRequest("x", null), "\"0\""));

        enqueueToken("role-permission-write", PortalOpenApiClient.ROLE_PERMISSIONS_WRITE_SCOPE, 120);
        enqueueAuthorizationObject("{\"roleId\":\"%s\",\"permissionIds\":[\"%s\"],\"version\":0}".formatted(wrongId, permissionId));
        assertAuthorizationResponseError(() -> client.replaceRolePermissions(roleId, List.of(permissionId), "\"0\""));

        String assignment = "{\"id\":\"%s\",\"userId\":\"%s\",\"roleId\":\"%s\",\"organizationId\":null,\"conditionExpression\":null,\"conditionDescription\":null,\"version\":0,\"createdAt\":\"%s\",\"updatedAt\":\"%s\"}";
        enqueueToken("user-role-write", PortalOpenApiClient.USER_ROLES_WRITE_SCOPE, 120);
        enqueueAuthorizationObject(assignment.formatted(assignmentId, wrongId, roleId, timestamp, timestamp));
        assertAuthorizationResponseError(() -> client.createUserRole(userId, new CreateOpenUserRoleRequest(roleId, null), null));
        enqueueAuthorizationObject(assignment.formatted(assignmentId, userId, wrongId, timestamp, timestamp));
        assertAuthorizationResponseError(() -> client.createUserRole(userId, new CreateOpenUserRoleRequest(roleId, null), null));
        enqueueAuthorizationObject(assignment.formatted(assignmentId, wrongId, roleId, timestamp, timestamp));
        assertAuthorizationResponseError(() -> client.updateUserRole(userId, assignmentId, new UpdateOpenUserRoleRequest(null), "\"0\""));
        enqueueAuthorizationObject(assignment.formatted(wrongId, userId, roleId, timestamp, timestamp));
        assertAuthorizationResponseError(() -> client.updateUserRole(userId, assignmentId, new UpdateOpenUserRoleRequest(null), "\"0\""));

        server.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setBody("{\"content\":[],\"page\":{\"size\":20}}"));
        assertAuthorizationResponseError(() -> client.listRoles(AuthorizationPageOptions.defaults()));

        for (String body : List.of(
                "{\"content\":[],\"page\":{\"size\":20,\"totalElements\":0,\"totalPages\":0}}",
                "{\"content\":[],\"page\":{\"size\":20,\"number\":0,\"totalPages\":0}}",
                "{\"content\":[],\"page\":{\"size\":20,\"number\":0,\"totalElements\":0}}")) {
            enqueueJson(body);
            assertAuthorizationResponseError(() -> client.listRoles(AuthorizationPageOptions.defaults()));
        }
        enqueueJson("{\"content\":[{\"id\":\"%s\",\"key\":\"admin\",\"name\":\"Admin\",\"description\":null,\"version\":0,\"createdAt\":\"%s\",\"updatedAt\":\"%s\"}],\"page\":%s}".formatted(roleId, timestamp, timestamp, pageJson(20, 1)));
        assertAuthorizationResponseError(() -> client.listRoles(AuthorizationPageOptions.defaults()));
        enqueueJson("{\"content\":[{\"id\":\"%s\",\"key\":\"admin\",\"name\":\"Admin\",\"description\":null,\"system\":false,\"createdAt\":\"%s\",\"updatedAt\":\"%s\"}],\"page\":%s}".formatted(roleId, timestamp, timestamp, pageJson(20, 1)));
        assertAuthorizationResponseError(() -> client.listRoles(AuthorizationPageOptions.defaults()));

        enqueueJson("{\"content\":[{\"id\":\"%s\",\"resource\":\"orders\",\"action\":\"read\",\"key\":\"orders:read\",\"name\":\"Read\",\"description\":null,\"source\":\"MANUAL\",\"createdAt\":\"%s\",\"updatedAt\":\"%s\"}],\"page\":%s}".formatted(permissionId, timestamp, timestamp, pageJson(20, 1)));
        assertAuthorizationResponseError(() -> client.listPermissions(AuthorizationPageOptions.defaults()));

        enqueueAuthorizationObject("{\"roleId\":\"%s\",\"permissionIds\":[\"%s\"]}".formatted(roleId, permissionId));
        assertAuthorizationResponseError(() -> client.replaceRolePermissions(roleId, List.of(permissionId), "\"0\""));
        enqueueAuthorizationObject(assignment.formatted(assignmentId, userId, roleId, timestamp, timestamp).replace("\"version\":0,", ""));
        assertAuthorizationResponseError(() -> client.createUserRole(userId, new CreateOpenUserRoleRequest(roleId, null), null));

        enqueueAuthorizationObject(roleJson(roleId, timestamp).replace("\"version\":1", "\"version\":0"));
        assertThat(client.getRole(roleId)).extracting(OpenRole::system, OpenRole::version).containsExactly(false, 0L);
        enqueueAuthorizationObject(permission.replace(wrongId, permissionId));
        assertThat(client.getPermission(permissionId).version()).isZero();
        enqueueAuthorizationObject("{\"roleId\":\"%s\",\"permissionIds\":[\"%s\"],\"version\":0}".formatted(roleId, permissionId));
        assertThat(client.replaceRolePermissions(roleId, List.of(permissionId), "\"0\"").version()).isZero();
        enqueueAuthorizationObject(assignment.formatted(assignmentId, userId, roleId, timestamp, timestamp));
        assertThat(client.createUserRole(userId, new CreateOpenUserRoleRequest(roleId, null), null).version()).isZero();
        enqueueJson("{\"content\":[],\"page\":{\"size\":20,\"number\":0,\"totalElements\":0,\"totalPages\":0}}");
        assertThat(client.listRoles(AuthorizationPageOptions.defaults()).content()).isEmpty();
    }

    private void enqueueAuthorizationObject(String body) {
        server.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setHeader("ETag", "\"0\"").setBody(body));
    }

    private void assertMalformedAuthorizationList(String scope, String body, Runnable call) {
        enqueueToken(scope + "-token", scope, 120);
        enqueueJson(body);
        assertAuthorizationResponseError(call);
        client.clearTokenCache(scope);
    }

    private static void assertAuthorizationResponseError(Runnable call) {
        assertThatThrownBy(call::run).isInstanceOf(PortalOpenApiException.class)
                .extracting("code").isEqualTo("invalid_authorization_response");
    }

    private static String pageJson(int size, long totalElements) {
        return "{\"size\":" + size + ",\"number\":0,\"totalElements\":" + totalElements + ",\"totalPages\":" + (totalElements == 0 ? 0 : 1) + "}";
    }

    private static String roleJson(String id, String createdAt) {
        return "{\"id\":\"" + id + "\",\"key\":\"admin\",\"name\":\"Admin\",\"description\":null,\"system\":false,\"version\":1,\"createdAt\":\"" + createdAt + "\",\"updatedAt\":\"2026-07-15T00:00:00Z\"}";
    }

    private PortalOpenApiClient newClient(Duration tokenSkew) {
        PortalOpenApiClientConfig config = PortalOpenApiClientConfig.builder()
                .issuer(server.url("/").toString())
                .portalEndpoint(server.url("/").toString())
                .clientId("m2m-client")
                .clientSecret("m2m-secret")
                .timeout(Duration.ofSeconds(5))
                .tokenSkew(tokenSkew)
                .build();
        return new PortalOpenApiClient(config, new ObjectMapper());
    }

    private void enqueueToken(String token, String scope, int expiresIn) {
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("""
                        {
                          "access_token":"%s",
                          "token_type":"Bearer",
                          "expires_in":%d,
                          "scope":"%s"
                        }
                        """.formatted(token, expiresIn, scope)));
    }

    private void enqueueJson(String body) {
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody(body));
    }

    private void assertInvalidCreate(String response) {
        enqueueToken("grant-write", PortalOpenApiClient.REGISTRATION_GRANTS_WRITE_SCOPE, 120);
        enqueueJson(response);
        assertThatThrownBy(() -> client.createRegistrationGrant(new CreateRegistrationGrantRequest(
                        CreateRegistrationGrantType.EMAIL_LINK, null, null, null, null, null)))
                .isInstanceOf(PortalOpenApiException.class)
                .satisfies(error -> {
                    PortalOpenApiException portalError = (PortalOpenApiException) error;
                    assertThat(portalError.getCode()).isEqualTo("invalid_registration_grant_response");
                    assertThat(portalError.getMessage()).doesNotContain("fake-token", "fake-code");
                });
        client.clearTokenCache(PortalOpenApiClient.REGISTRATION_GRANTS_WRITE_SCOPE);
    }

    private String grantJson(String type) {
        return "{\"id\":\"019f4cca-88f8-7e77-a67d-4a6a2a68b803\",\"type\":\"" + type
                + "\",\"status\":\"ACTIVE\",\"displayName\":null,\"allowedEmail\":null,\"allowedDomain\":null,"
                + "\"expiresAt\":null,\"maxUses\":null,\"usedCount\":0,\"sourceType\":\"API\","
                + "\"createdAt\":\"2026-07-11T00:00:00Z\",\"updatedAt\":\"2026-07-11T00:00:00Z\","
                + "\"revokedAt\":null,\"revokeReason\":null}";
    }

    private String organizationJson(String id) {
        return "{\"id\":\"" + id + "\",\"name\":\"Acme\",\"slug\":\"acme\",\"version\":7,"
                + "\"createdAt\":\"2026-07-12T00:00:00Z\",\"updatedAt\":\"2026-07-12T00:00:00Z\"}";
    }

    private String invitationJson(String id) {
        return "{\"id\":\"" + id + "\",\"email\":\"member@example.test\",\"role\":\"ADMIN\","
                + "\"status\":\"PENDING\",\"deliveryStatus\":\"SENT\",\"expiresAt\":\"2026-07-19T00:00:00Z\","
                + "\"createdAt\":\"2026-07-12T00:00:00Z\",\"updatedAt\":\"2026-07-12T00:00:00Z\"}";
    }

    private String memberJson(String membershipId) {
        return "{\"membershipId\":\"" + membershipId + "\",\"userId\":\"423e4567-e89b-42d3-a456-426614174000\","
                + "\"email\":\"member@example.test\",\"displayName\":\"Member\",\"role\":\"ADMIN\","
                + "\"joinedAt\":\"2026-07-12T00:00:00Z\",\"updatedAt\":\"2026-07-12T00:00:00Z\",\"version\":2}";
    }

    private void assertResourceRequest(
            RecordedRequest request,
            String method,
            String path,
            String authorization) {
        assertThat(request.getMethod()).isEqualTo(method);
        assertThat(request.getPath()).isEqualTo(path);
        assertThat(request.getHeader("Authorization")).isEqualTo(authorization);
        assertThat(request.getHeader("Authorization")).doesNotStartWith("Basic ");
        assertThat(request.getHeader("X-IAM-Client-Id")).isNull();
        assertThat(request.getHeader("X-Application-Id")).isNull();
        assertThat(request.getHeader("X-App-Key")).isNull();
    }
}
