package com.chaosguide.iam.vertex.portal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.Credentials;
import okhttp3.FormBody;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Server-side M2M client for iam-portal {@code /open/v1/**}.
 *
 * <p>The client requests {@code client_credentials} machine tokens from
 * {@code {issuer}/oauth2/token} with explicit {@code portal:openapi:read} or
 * {@code portal:openapi:write} scope, caches read/write tokens separately, and
 * sends only bearer auth to Portal resource endpoints.
 */
public class PortalOpenApiClient {

    public static final String PORTAL_OPENAPI_READ_SCOPE = "portal:openapi:read";
    public static final String PORTAL_OPENAPI_WRITE_SCOPE = "portal:openapi:write";
    public static final String REGISTRATION_GRANTS_READ_SCOPE = "registration_grants:read";
    public static final String REGISTRATION_GRANTS_WRITE_SCOPE = "registration_grants:write";
    public static final String REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE = "registration_grants:redemptions:read";
    public static final String ORGANIZATIONS_READ_SCOPE = "organizations:read";
    public static final String ORGANIZATIONS_WRITE_SCOPE = "organizations:write";
    public static final String ORGANIZATION_INVITATIONS_READ_SCOPE = "organization_invitations:read";
    public static final String ORGANIZATION_INVITATIONS_WRITE_SCOPE = "organization_invitations:write";
    public static final String ORGANIZATION_MEMBERS_READ_SCOPE = "organization_members:read";
    public static final String ORGANIZATION_MEMBERS_WRITE_SCOPE = "organization_members:write";
    public static final String ROLES_READ_SCOPE = "roles:read";
    public static final String ROLES_WRITE_SCOPE = "roles:write";
    public static final String PERMISSIONS_READ_SCOPE = "permissions:read";
    public static final String PERMISSIONS_WRITE_SCOPE = "permissions:write";
    public static final String ROLE_PERMISSIONS_READ_SCOPE = "role_permissions:read";
    public static final String ROLE_PERMISSIONS_WRITE_SCOPE = "role_permissions:write";
    public static final String USER_ROLES_READ_SCOPE = "user_roles:read";
    public static final String USER_ROLES_WRITE_SCOPE = "user_roles:write";

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final Set<String> SUPPORTED_SCOPES = Set.of(
            PORTAL_OPENAPI_READ_SCOPE,
            PORTAL_OPENAPI_WRITE_SCOPE,
            REGISTRATION_GRANTS_READ_SCOPE,
            REGISTRATION_GRANTS_WRITE_SCOPE,
            REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE,
            ORGANIZATIONS_READ_SCOPE,
            ORGANIZATIONS_WRITE_SCOPE,
            ORGANIZATION_INVITATIONS_READ_SCOPE,
            ORGANIZATION_INVITATIONS_WRITE_SCOPE,
            ORGANIZATION_MEMBERS_READ_SCOPE,
            ORGANIZATION_MEMBERS_WRITE_SCOPE,
            ROLES_READ_SCOPE, ROLES_WRITE_SCOPE, PERMISSIONS_READ_SCOPE, PERMISSIONS_WRITE_SCOPE,
            ROLE_PERMISSIONS_READ_SCOPE, ROLE_PERMISSIONS_WRITE_SCOPE, USER_ROLES_READ_SCOPE, USER_ROLES_WRITE_SCOPE);
    private static final Set<String> SUPPORTED_METHODS = Set.of("GET", "POST", "PUT", "PATCH", "DELETE");
    private static final Set<String> FORBIDDEN_RESOURCE_HEADERS = Set.of(
            "authorization",
            "x-iam-client-id",
            "x-application-id",
            "x-app-key");

    private final PortalOpenApiClientConfig config;
    private final OkHttpClient http;
    private final ObjectMapper mapper;
    private final Map<String, PortalOpenApiMachineToken> tokenCache = new ConcurrentHashMap<>();

    public PortalOpenApiClient(PortalOpenApiClientConfig config) {
        this(config, new ObjectMapper());
    }

    public PortalOpenApiClient(PortalOpenApiClientConfig config, ObjectMapper mapper) {
        this(defaultHttp(config), mapper, config);
    }

    // Visible for testing
    PortalOpenApiClient(OkHttpClient http, ObjectMapper mapper, PortalOpenApiClientConfig config) {
        this.http = http;
        this.mapper = mapper;
        this.config = config;
    }

    /**
     * Return a cached or freshly requested machine token for one explicit Portal scope.
     */
    public PortalOpenApiMachineToken getMachineToken(String scope) {
        String normalizedScope = normalizeScope(scope);
        synchronized (tokenCache) {
            PortalOpenApiMachineToken cached = tokenCache.get(normalizedScope);
            if (cached != null && cached.expiresAt().isAfter(Instant.now())) {
                return cached;
            }
            PortalOpenApiMachineToken token = requestMachineToken(normalizedScope);
            tokenCache.put(normalizedScope, token);
            return token;
        }
    }

    /** Clear all cached read/write tokens. */
    public void clearTokenCache() {
        tokenCache.clear();
    }

    /** Clear one cached scope token. */
    public void clearTokenCache(String scope) {
        tokenCache.remove(normalizeScope(scope));
    }

    /**
     * Call a Portal {@code /open/v1/**} JSON endpoint with a bearer machine token.
     */
    public <T> T requestJson(String method, String path, Object body, Class<T> responseType) {
        return requestJson(method, path, body, responseType, Map.of());
    }

    /**
     * Call a Portal {@code /open/v1/**} JSON endpoint with extra non-auth headers.
     *
     * <p>{@code Authorization}, {@code X-IAM-Client-Id}, {@code X-Application-Id},
     * and {@code X-App-Key} are managed or forbidden by this SDK and are rejected.
     */
    public <T> T requestJson(
            String method,
            String path,
            Object body,
            Class<T> responseType,
            Map<String, String> headers) {
        String normalizedMethod = normalizeMethod(method);
        String scope = scopeForMethod(normalizedMethod);
        return requestJsonWithScope(normalizedMethod, path, body, responseType, headers, scope);
    }

    /** List registration grants using the exact registration-grants read scope. */
    public RegistrationGrantPage listRegistrationGrants(RegistrationGrantListOptions options) {
        RegistrationGrantListOptions effectiveOptions = options == null ? RegistrationGrantListOptions.empty() : options;
        JsonNode response = requestJsonWithScope("GET", "/open/v1/registration-grants" + effectiveOptions.toQueryString(),
                null, JsonNode.class, Map.of(), REGISTRATION_GRANTS_READ_SCOPE);
        return parseRegistrationGrantResponse(response, RegistrationGrantPage.class);
    }

    /** Create an EMAIL_LINK or ACCESS_CODE registration grant and return its one-time proof. */
    public CreatedRegistrationGrant createRegistrationGrant(CreateRegistrationGrantRequest request) {
        if (request == null) {
            throw invalidRegistrationGrantResponse();
        }
        JsonNode response = requestJsonWithScope("POST", "/open/v1/registration-grants", request,
                JsonNode.class, Map.of(), REGISTRATION_GRANTS_WRITE_SCOPE);
        return parseRegistrationGrantResponse(response, CreatedRegistrationGrant.class);
    }

    /** Return a safe registration-grant detail without any raw proof fields. */
    public RegistrationGrant getRegistrationGrant(String grantId) {
        JsonNode response = requestJsonWithScope("GET", registrationGrantPath(grantId), null,
                JsonNode.class, Map.of(), REGISTRATION_GRANTS_READ_SCOPE);
        return parseRegistrationGrantResponse(response, RegistrationGrant.class);
    }

    /** Pause an active registration grant. */
    public RegistrationGrant pauseRegistrationGrant(String grantId) {
        return registrationGrantLifecycle(grantId, "pause");
    }

    /** Resume a paused registration grant. */
    public RegistrationGrant resumeRegistrationGrant(String grantId) {
        return registrationGrantLifecycle(grantId, "resume");
    }

    /** Revoke a registration grant, optionally retaining the supplied reason. */
    public RegistrationGrant revokeRegistrationGrant(String grantId, String reason) {
        JsonNode response = requestJsonWithScope("POST", registrationGrantPath(grantId) + "/revoke",
                reason == null ? null : new RevokeRegistrationGrantRequest(reason), JsonNode.class,
                Map.of(), REGISTRATION_GRANTS_WRITE_SCOPE);
        return parseRegistrationGrantResponse(response, RegistrationGrant.class);
    }

    /** List safe, masked redemption history using its dedicated exact scope. */
    public RegistrationGrantRedemptionPage listRegistrationGrantRedemptions(
            String grantId, RegistrationGrantPageOptions options) {
        RegistrationGrantPageOptions effectiveOptions = options == null ? RegistrationGrantPageOptions.empty() : options;
        JsonNode response = requestJsonWithScope("GET",
                registrationGrantPath(grantId) + "/redemptions" + effectiveOptions.toQueryString(), null,
                JsonNode.class, Map.of(), REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE);
        return parseRegistrationGrantResponse(response, RegistrationGrantRedemptionPage.class);
    }

    /** List Organizations bound to the Application represented by the M2M token. */
    public OpenOrganizationPage listOrganizations(OrganizationListOptions options) {
        OrganizationListOptions effectiveOptions = options == null ? OrganizationListOptions.empty() : options;
        JsonNode response = requestJsonWithScope("GET", "/open/v1/organizations" + effectiveOptions.toQueryString(),
                null, JsonNode.class, Map.of(), ORGANIZATIONS_READ_SCOPE);
        return parseOrganizationResponse(response, OpenOrganizationPage.class);
    }

    /** Create an Organization without an idempotency key. */
    public OpenOrganization createOrganization(CreateOrganizationRequest request) {
        return createOrganization(request, null);
    }

    /** Create an Organization with an optional Idempotency-Key. */
    public OpenOrganization createOrganization(CreateOrganizationRequest request, String idempotencyKey) {
        PortalOpenApiResponse<JsonNode> response = requestJsonWithScopeResponse("POST", "/open/v1/organizations",
                request, JsonNode.class, idempotencyHeaders(idempotencyKey), ORGANIZATIONS_WRITE_SCOPE);
        return parseOrganizationResponse(response.body(), OpenOrganization.class).withEtag(response.etag());
    }

    /** Get an Organization and expose the returned ETag for a subsequent conditional write. */
    public OpenOrganization getOrganization(String organizationId) {
        PortalOpenApiResponse<JsonNode> response = requestJsonWithScopeResponse("GET", organizationPath(organizationId),
                null, JsonNode.class, Map.of(), ORGANIZATIONS_READ_SCOPE);
        return parseOrganizationResponse(response.body(), OpenOrganization.class).withEtag(response.etag());
    }

    /** Patch an Organization without an If-Match precondition. */
    public OpenOrganization updateOrganization(String organizationId, UpdateOrganizationRequest request) {
        return updateOrganization(organizationId, request, null);
    }

    /** Patch an Organization with an optional If-Match ETag precondition. */
    public OpenOrganization updateOrganization(String organizationId, UpdateOrganizationRequest request, String ifMatch) {
        PortalOpenApiResponse<JsonNode> response = requestJsonWithScopeResponse("PATCH", organizationPath(organizationId),
                request, JsonNode.class, ifMatchHeaders(ifMatch), ORGANIZATIONS_WRITE_SCOPE);
        return parseOrganizationResponse(response.body(), OpenOrganization.class).withEtag(response.etag());
    }

    /** Delete an Organization without an If-Match precondition. */
    public void deleteOrganization(String organizationId) {
        deleteOrganization(organizationId, null);
    }

    /** Delete an Organization with an optional If-Match ETag precondition. */
    public void deleteOrganization(String organizationId, String ifMatch) {
        requestJsonWithScope("DELETE", organizationPath(organizationId), null, Void.class,
                ifMatchHeaders(ifMatch), ORGANIZATIONS_WRITE_SCOPE);
    }

    /** List invitation lifecycle and delivery state for one Organization. */
    public OpenOrganizationInvitationPage listOrganizationInvitations(
            String organizationId, OrganizationInvitationListOptions options) {
        OrganizationInvitationListOptions effectiveOptions =
                options == null ? OrganizationInvitationListOptions.empty() : options;
        JsonNode response = requestJsonWithScope("GET", organizationPath(organizationId) + "/invitations"
                        + effectiveOptions.toQueryString(), null, JsonNode.class, Map.of(),
                ORGANIZATION_INVITATIONS_READ_SCOPE);
        return parseOrganizationResponse(response, OpenOrganizationInvitationPage.class);
    }

    /** Create an invitation without an idempotency key. */
    public OpenOrganizationInvitation createOrganizationInvitation(
            String organizationId, CreateOrganizationInvitationRequest request) {
        return createOrganizationInvitation(organizationId, request, null);
    }

    /** Create an invitation with an optional Idempotency-Key. */
    public OpenOrganizationInvitation createOrganizationInvitation(
            String organizationId, CreateOrganizationInvitationRequest request, String idempotencyKey) {
        JsonNode response = requestJsonWithScope("POST", organizationPath(organizationId) + "/invitations", request,
                JsonNode.class, idempotencyHeaders(idempotencyKey), ORGANIZATION_INVITATIONS_WRITE_SCOPE);
        return parseOrganizationResponse(response, OpenOrganizationInvitation.class);
    }

    /** Return a safe invitation detail; the API never returns a raw redemption proof. */
    public OpenOrganizationInvitation getOrganizationInvitation(String organizationId, String invitationId) {
        JsonNode response = requestJsonWithScope("GET", organizationInvitationPath(organizationId, invitationId), null,
                JsonNode.class, Map.of(), ORGANIZATION_INVITATIONS_READ_SCOPE);
        return parseOrganizationResponse(response, OpenOrganizationInvitation.class);
    }

    /** Resend a pending invitation. A rate limit is reported with PortalOpenApiException#getRetryAfter(). */
    public OpenOrganizationInvitation resendOrganizationInvitation(String organizationId, String invitationId) {
        JsonNode response = requestJsonWithScope("POST", organizationInvitationPath(organizationId, invitationId) + "/resend",
                null, JsonNode.class, Map.of(), ORGANIZATION_INVITATIONS_WRITE_SCOPE);
        return parseOrganizationResponse(response, OpenOrganizationInvitation.class);
    }

    /** Cancel an invitation. Portal remains authoritative for terminal-state semantics. */
    public void cancelOrganizationInvitation(String organizationId, String invitationId) {
        requestJsonWithScope("DELETE", organizationInvitationPath(organizationId, invitationId), null, Void.class,
                Map.of(), ORGANIZATION_INVITATIONS_WRITE_SCOPE);
    }

    /** List Organization members with optional search and paging. */
    public OpenOrganizationMemberPage listOrganizationMembers(
            String organizationId, OrganizationMemberListOptions options) {
        OrganizationMemberListOptions effectiveOptions =
                options == null ? OrganizationMemberListOptions.empty() : options;
        JsonNode response = requestJsonWithScope("GET", organizationPath(organizationId) + "/members"
                        + effectiveOptions.toQueryString(), null, JsonNode.class, Map.of(),
                ORGANIZATION_MEMBERS_READ_SCOPE);
        return parseOrganizationResponse(response, OpenOrganizationMemberPage.class);
    }

    public OpenOrganizationMember getOrganizationMember(String organizationId, String membershipId) {
        JsonNode response = requestJsonWithScope("GET", organizationMemberPath(organizationId, membershipId), null,
                JsonNode.class, Map.of(), ORGANIZATION_MEMBERS_READ_SCOPE);
        return parseOrganizationResponse(response, OpenOrganizationMember.class);
    }

    /** Update a member role without an If-Match precondition. */
    public OpenOrganizationMember updateOrganizationMemberRole(
            String organizationId, String membershipId, OrganizationMemberRole role) {
        return updateOrganizationMemberRole(organizationId, membershipId, role, null);
    }

    /** Update a member role with an optional If-Match version precondition. */
    public OpenOrganizationMember updateOrganizationMemberRole(
            String organizationId, String membershipId, OrganizationMemberRole role, String ifMatch) {
        JsonNode response = requestJsonWithScope("PATCH", organizationMemberPath(organizationId, membershipId),
                new UpdateOrganizationMemberRoleRequest(role), JsonNode.class, ifMatchHeaders(ifMatch),
                ORGANIZATION_MEMBERS_WRITE_SCOPE);
        return parseOrganizationResponse(response, OpenOrganizationMember.class);
    }

    /** Remove a member. A last-owner rejection remains a typed 400 Portal error. */
    public void removeOrganizationMember(String organizationId, String membershipId) {
        requestJsonWithScope("DELETE", organizationMemberPath(organizationId, membershipId), null, Void.class,
                Map.of(), ORGANIZATION_MEMBERS_WRITE_SCOPE);
    }

    public OpenRolePage listRoles(AuthorizationPageOptions options) {
        JsonNode raw = requestJsonWithScope("GET", "/open/v1/roles" + authorizationPageQuery(options), null,
                JsonNode.class, Map.of(), ROLES_READ_SCOPE);
        OpenRolePage result = parseAuthorizationPage(raw, OpenRolePage.class, "system", "version");
        validatePage(result.content(), result.page());
        result.content().forEach(this::validateRole);
        return result;
    }

    public OpenRole getRole(String roleId) {
        var response = requestJsonWithScopeResponse("GET", authorizationPath("roles", roleId, "role"), null,
                JsonNode.class, Map.of(), ROLES_READ_SCOPE);
        return validateRole(withEtag(parseAuthorizationBody(response.body(), OpenRole.class, "system", "version"), response.etag()), roleId);
    }

    public OpenRole createRole(CreateOpenRoleRequest request, String idempotencyKey) {
        var response = requestJsonWithScopeResponse("POST", "/open/v1/roles", request, JsonNode.class,
                idempotencyHeaders(idempotencyKey), ROLES_WRITE_SCOPE);
        return validateRole(withEtag(parseAuthorizationBody(response.body(), OpenRole.class, "system", "version"), response.etag()));
    }

    public OpenRole updateRole(String roleId, UpdateOpenRoleRequest request, String ifMatch) {
        var response = requestJsonWithScopeResponse("PATCH", authorizationPath("roles", roleId, "role"), request,
                JsonNode.class, requiredIfMatchHeaders(ifMatch), ROLES_WRITE_SCOPE);
        return validateRole(withEtag(parseAuthorizationBody(response.body(), OpenRole.class, "system", "version"), response.etag()), roleId);
    }

    public void deleteRole(String roleId, String ifMatch) {
        requestJsonWithScope("DELETE", authorizationPath("roles", roleId, "role"), null, Void.class,
                requiredIfMatchHeaders(ifMatch), ROLES_WRITE_SCOPE);
    }

    public OpenPermissionPage listPermissions(AuthorizationPageOptions options) {
        JsonNode raw = requestJsonWithScope("GET", "/open/v1/permissions" + authorizationPageQuery(options),
                null, JsonNode.class, Map.of(), PERMISSIONS_READ_SCOPE);
        OpenPermissionPage page = parseAuthorizationPage(raw, OpenPermissionPage.class, "version");
        validatePage(page.content(), page.page());
        page.content().forEach(this::validatePermission);
        return page;
    }

    public OpenPermission getPermission(String permissionId) {
        var response = requestJsonWithScopeResponse("GET", authorizationPath("permissions", permissionId, "permission"),
                null, JsonNode.class, Map.of(), PERMISSIONS_READ_SCOPE);
        return validatePermission(withEtag(parseAuthorizationBody(response.body(), OpenPermission.class, "version"), response.etag()), permissionId);
    }

    public OpenPermission createPermission(CreateOpenPermissionRequest request, String idempotencyKey) {
        validatePermissionGrant(request.resource(), request.action());
        var response = requestJsonWithScopeResponse("POST", "/open/v1/permissions", request, JsonNode.class,
                idempotencyHeaders(idempotencyKey), PERMISSIONS_WRITE_SCOPE);
        return validatePermission(withEtag(parseAuthorizationBody(response.body(), OpenPermission.class, "version"), response.etag()));
    }

    public OpenPermission updatePermission(String permissionId, UpdateOpenPermissionRequest request, String ifMatch) {
        var response = requestJsonWithScopeResponse("PATCH", authorizationPath("permissions", permissionId, "permission"),
                request, JsonNode.class, requiredIfMatchHeaders(ifMatch), PERMISSIONS_WRITE_SCOPE);
        return validatePermission(withEtag(parseAuthorizationBody(response.body(), OpenPermission.class, "version"), response.etag()), permissionId);
    }

    public void deletePermission(String permissionId, String ifMatch) {
        requestJsonWithScope("DELETE", authorizationPath("permissions", permissionId, "permission"), null, Void.class,
                requiredIfMatchHeaders(ifMatch), PERMISSIONS_WRITE_SCOPE);
    }

    public OpenRolePermissionPage listRolePermissions(String roleId, AuthorizationPageOptions options) {
        var response = requestJsonWithScopeResponse("GET", authorizationPath("roles", roleId, "role") + "/permissions"
                + authorizationPageQuery(options), null, JsonNode.class, Map.of(), ROLE_PERMISSIONS_READ_SCOPE);
        OpenRolePermissionPage page = withEtag(parseAuthorizationPage(response.body(), OpenRolePermissionPage.class), response.etag());
        validatePage(page.content(), page.page());
        page.content().forEach(binding -> validateRolePermissionBinding(binding, roleId));
        return page;
    }

    public OpenRolePermissionSet replaceRolePermissions(String roleId, List<String> permissionIds, String ifMatch) {
        permissionIds.forEach(id -> authorizationId(id, "permission"));
        var response = requestJsonWithScopeResponse("PUT", authorizationPath("roles", roleId, "role") + "/permissions",
                Map.of("permissionIds", permissionIds), JsonNode.class, requiredIfMatchHeaders(ifMatch),
                ROLE_PERMISSIONS_WRITE_SCOPE);
        return validateRolePermissionSet(withEtag(parseAuthorizationBody(response.body(), OpenRolePermissionSet.class, "version"), response.etag()), roleId);
    }

    public OpenUserRoleAssignmentPage listUserRoles(String userId, AuthorizationPageOptions options) {
        JsonNode raw = requestJsonWithScope("GET", userRolePath(userId) + authorizationPageQuery(options), null,
                JsonNode.class, Map.of(), USER_ROLES_READ_SCOPE);
        OpenUserRoleAssignmentPage page = parseAuthorizationPage(raw, OpenUserRoleAssignmentPage.class, "version");
        validatePage(page.content(), page.page());
        page.content().forEach(assignment -> validateAssignment(assignment, userId));
        return page;
    }

    public OpenUserRoleAssignment createUserRole(String userId, CreateOpenUserRoleRequest request, String idempotencyKey) {
        authorizationId(request.roleId(), "role");
        var response = requestJsonWithScopeResponse("POST", userRolePath(userId), request, JsonNode.class,
                idempotencyHeaders(idempotencyKey), USER_ROLES_WRITE_SCOPE);
        return validateAssignment(withEtag(parseAuthorizationBody(response.body(), OpenUserRoleAssignment.class, "version"), response.etag()), userId, request.roleId(), null);
    }

    public OpenUserRoleAssignment updateUserRole(String userId, String assignmentId,
            UpdateOpenUserRoleRequest request, String ifMatch) {
        var response = requestJsonWithScopeResponse("PATCH", userRolePath(userId) + "/"
                + authorizationId(assignmentId, "assignment"), request, JsonNode.class,
                requiredIfMatchHeaders(ifMatch), USER_ROLES_WRITE_SCOPE);
        return validateAssignment(withEtag(parseAuthorizationBody(response.body(), OpenUserRoleAssignment.class, "version"), response.etag()), userId, null, assignmentId);
    }

    public void deleteUserRole(String userId, String assignmentId, String ifMatch) {
        requestJsonWithScope("DELETE", userRolePath(userId) + "/" + authorizationId(assignmentId, "assignment"),
                null, Void.class, requiredIfMatchHeaders(ifMatch), USER_ROLES_WRITE_SCOPE);
    }

    private RegistrationGrant registrationGrantLifecycle(String grantId, String action) {
        JsonNode response = requestJsonWithScope("POST", registrationGrantPath(grantId) + "/" + action,
                null, JsonNode.class, Map.of(), REGISTRATION_GRANTS_WRITE_SCOPE);
        return parseRegistrationGrantResponse(response, RegistrationGrant.class);
    }

    private <T> T requestJsonWithScope(
            String normalizedMethod,
            String path,
            Object body,
            Class<T> responseType,
            Map<String, String> headers,
            String scope) {
        return requestJsonWithScopeResponse(normalizedMethod, path, body, responseType, headers, scope).body();
    }

    private <T> PortalOpenApiResponse<T> requestJsonWithScopeResponse(
            String normalizedMethod,
            String path,
            Object body,
            Class<T> responseType,
            Map<String, String> headers,
            String scope) {
        String url = portalUrl(path);
        validateExtraHeaders(headers);
        PortalOpenApiMachineToken token = getMachineToken(scope);

        Request.Builder builder = new Request.Builder()
                .url(url)
                .header("Accept", "application/json")
                .header("Authorization", "Bearer " + token.accessToken());
        applyExtraHeaders(builder, headers);

        RequestBody requestBody = requestBody(normalizedMethod, body);
        builder.method(normalizedMethod, requestBody);

        try (Response resp = http.newCall(builder.build()).execute()) {
            if (!resp.isSuccessful()) {
                throw portalError(resp);
            }
            if (responseType == null || responseType == Void.class || resp.code() == 204) {
                closeQuietly(resp.body());
                return new PortalOpenApiResponse<>(null, resp.header("ETag"));
            }
            String raw = readRaw(resp.body());
            if (raw.isBlank()) {
                return new PortalOpenApiResponse<>(null, resp.header("ETag"));
            }
            return new PortalOpenApiResponse<>(mapper.readValue(raw, responseType), resp.header("ETag"));
        } catch (IOException e) {
            throw new PortalOpenApiException("Portal Open API request IO error: " + e.getMessage(),
                    0, "transport_error", null);
        }
    }

    public <T> T get(String path, Class<T> responseType) {
        return requestJson("GET", path, null, responseType);
    }

    public <T> T post(String path, Object body, Class<T> responseType) {
        return requestJson("POST", path, body, responseType);
    }

    public <T> T put(String path, Object body, Class<T> responseType) {
        return requestJson("PUT", path, body, responseType);
    }

    public <T> T patch(String path, Object body, Class<T> responseType) {
        return requestJson("PATCH", path, body, responseType);
    }

    public <T> T delete(String path, Class<T> responseType) {
        return requestJson("DELETE", path, null, responseType);
    }

    private PortalOpenApiMachineToken requestMachineToken(String scope) {
        RequestBody body = new FormBody.Builder()
                .add("grant_type", "client_credentials")
                .add("scope", scope)
                .build();
        Request request = new Request.Builder()
                .url(config.getIssuer() + "/oauth2/token")
                .post(body)
                .header("Accept", "application/json")
                .header("Authorization", Credentials.basic(config.getClientId(), config.getClientSecret()))
                .build();

        try (Response resp = http.newCall(request).execute()) {
            String raw = readRaw(resp.body());
            JsonNode payload = readTree(raw);
            if (!resp.isSuccessful()) {
                String code = firstText(payload, "error", "code", "errorCode");
                if (code == null) {
                    code = "token_request_failed";
                }
                String message = firstText(payload, "error_description", "message", "error");
                if (message == null) {
                    message = "Token request failed with HTTP " + resp.code();
                }
                throw new PortalOpenApiTokenException(message, resp.code(), code, raw);
            }
            String accessToken = textOrNull(payload.path("access_token"));
            if (accessToken == null) {
                throw new PortalOpenApiTokenException("Token response is missing access_token",
                        resp.code(), "missing_bearer_token", raw);
            }
            String tokenType = textOrNull(payload.path("token_type"));
            if (tokenType == null || !"bearer".equalsIgnoreCase(tokenType)) {
                throw new PortalOpenApiTokenException("Token response is missing bearer token_type",
                        resp.code(), "missing_bearer_token", raw);
            }
            JsonNode expiresNode = payload.path("expires_in");
            if (!expiresNode.isNumber() || expiresNode.asDouble() <= 0) {
                throw new PortalOpenApiTokenException("Token response is missing positive expires_in",
                        resp.code(), "invalid_token_response", raw);
            }
            String responseScope = textOrNull(payload.path("scope"));
            if (responseScope != null && !containsScope(responseScope, scope)) {
                throw new PortalOpenApiTokenException("Token response does not include requested scope " + scope,
                        resp.code(), "invalid_scope", raw);
            }
            long ttlMillis = Math.max(0L,
                    (long) ((expiresNode.asDouble() - config.getTokenSkew().toMillis() / 1000.0) * 1000));
            return new PortalOpenApiMachineToken(accessToken, scope, Instant.now().plusMillis(ttlMillis));
        } catch (IOException e) {
            throw new PortalOpenApiTokenException("Portal Open API token IO error: " + e.getMessage(), e);
        }
    }

    private RequestBody requestBody(String method, Object body) {
        if (body == null) {
            if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
                return RequestBody.create(new byte[0], null);
            }
            return null;
        }
        if ("GET".equals(method)) {
            throw new PortalOpenApiException("GET requests must not include a JSON body",
                    0, "invalid_portal_method", null);
        }
        try {
            return RequestBody.create(mapper.writeValueAsBytes(body), JSON);
        } catch (IOException e) {
            throw new PortalOpenApiException("Portal Open API JSON serialize error: " + e.getMessage(),
                    0, "json_serialize_error", null);
        }
    }

    private void applyExtraHeaders(Request.Builder builder, Map<String, String> headers) {
        if (headers == null || headers.isEmpty()) {
            return;
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String key = entry.getKey();
            if (key == null || key.isBlank()) {
                continue;
            }
            builder.header(key, entry.getValue());
        }
    }

    private void validateExtraHeaders(Map<String, String> headers) {
        if (headers == null || headers.isEmpty()) {
            return;
        }
        for (String key : headers.keySet()) {
            if (key == null || key.isBlank()) {
                continue;
            }
            String lowered = key.toLowerCase(Locale.ROOT);
            if (FORBIDDEN_RESOURCE_HEADERS.contains(lowered)) {
                throw new PortalOpenApiException("Portal Open API header is managed by the SDK: " + key,
                        0, "invalid_portal_header", key);
            }
        }
    }

    private PortalOpenApiException portalError(Response resp) throws IOException {
        String raw = readRaw(resp.body());
        JsonNode payload = readTree(raw);
        String code = firstText(payload, "code", "error", "errorCode");
        if (code == null) {
            code = "HTTP_" + resp.code();
        }
        String message = firstText(payload, "message", "error_description", "error");
        if (message == null) {
            message = "Portal Open API request failed with HTTP " + resp.code();
        }
        return new PortalOpenApiException(message, resp.code(), code, raw, resp.header("Retry-After"));
    }

    private String normalizeScope(String scope) {
        if (scope == null || scope.isBlank()) {
            throw new PortalOpenApiTokenException(
                    "Portal Open API token requests require an explicit scope", "invalid_scope");
        }
        String normalized = scope.strip();
        if (!SUPPORTED_SCOPES.contains(normalized)) {
            throw new PortalOpenApiTokenException(
                    "Unsupported Portal Open API scope: " + scope, "invalid_scope");
        }
        return normalized;
    }

    private String registrationGrantPath(String grantId) {
        try {
            UUID parsed = UUID.fromString(grantId);
            if (!parsed.toString().equals(grantId)) {
                throw new IllegalArgumentException("Registration grant id must be canonical");
            }
            return "/open/v1/registration-grants/" + parsed;
        } catch (IllegalArgumentException e) {
            throw new PortalOpenApiException("Registration grant id must be a UUID",
                    0, "invalid_registration_grant_id", null);
        }
    }

    private String organizationPath(String organizationId) {
        return "/open/v1/organizations/" + organizationIdSegment(organizationId, "organization");
    }

    private String organizationInvitationPath(String organizationId, String invitationId) {
        return organizationPath(organizationId) + "/invitations/" + organizationIdSegment(invitationId, "invitation");
    }

    private String organizationMemberPath(String organizationId, String membershipId) {
        return organizationPath(organizationId) + "/members/" + organizationIdSegment(membershipId, "membership");
    }

    private String organizationIdSegment(String value, String resource) {
        try {
            UUID parsed = UUID.fromString(value);
            if (!parsed.toString().equals(value)) {
                throw new IllegalArgumentException(resource + " id must be canonical");
            }
            return parsed.toString();
        } catch (IllegalArgumentException e) {
            throw new PortalOpenApiException(capitalize(resource) + " id must be a UUID",
                    0, "invalid_" + resource + "_id", null);
        }
    }

    private <T> T parseRegistrationGrantResponse(JsonNode response, Class<T> responseType) {
        try {
            return mapper.treeToValue(response, responseType);
        } catch (IOException | IllegalArgumentException e) {
            throw invalidRegistrationGrantResponse();
        }
    }

    private <T> T parseOrganizationResponse(JsonNode response, Class<T> responseType) {
        try {
            return mapper.treeToValue(response, responseType);
        } catch (IOException | IllegalArgumentException e) {
            throw new PortalOpenApiException("Invalid organization management response",
                    0, "invalid_organization_response", null);
        }
    }

    private static Map<String, String> idempotencyHeaders(String idempotencyKey) {
        return idempotencyKey == null ? Map.of() : Map.of("Idempotency-Key", idempotencyKey);
    }

    private static Map<String, String> ifMatchHeaders(String ifMatch) {
        return ifMatch == null ? Map.of() : Map.of("If-Match", ifMatch);
    }

    private static Map<String, String> requiredIfMatchHeaders(String ifMatch) {
        requireEtag(ifMatch);
        return Map.of("If-Match", ifMatch);
    }

    private static String requireEtag(String etag) {
        if (etag == null || !etag.matches("\\\"[0-9]+\\\"")) {
            throw invalidAuthorizationResponse();
        }
        return etag;
    }

    private static String authorizationPageQuery(AuthorizationPageOptions options) {
        AuthorizationPageOptions effective = options == null ? AuthorizationPageOptions.defaults() : options;
        int page = effective.page() == null ? 0 : effective.page();
        int size = effective.size() == null ? 20 : effective.size();
        if (page < 0 || size < 1 || size > 100) throw invalidAuthorizationResponse();
        return "?page=" + page + "&size=" + size;
    }

    private static String authorizationPath(String collection, String id, String resource) {
        return "/open/v1/" + collection + "/" + authorizationId(id, resource);
    }

    private static String userRolePath(String userId) {
        return "/open/v1/users/" + authorizationId(userId, "user") + "/roles";
    }

    private static String authorizationId(String value, String resource) {
        try {
            UUID parsed = UUID.fromString(value);
            if (!parsed.toString().equals(value)) throw new IllegalArgumentException();
            return parsed.toString();
        } catch (RuntimeException e) {
            throw new PortalOpenApiException(resource + " id must be a UUID", 0, "invalid_" + resource + "_id", null);
        }
    }

    private static void validatePermissionGrant(String resource, String action) {
        if (!validPermissionSegment(resource) || !validPermissionSegment(action)
                || ("*".equals(resource) && !"*".equals(action))) throw invalidAuthorizationResponse();
    }

    private static boolean validPermissionSegment(String value) {
        return value != null && ("*".equals(value) || value.matches("[a-z0-9_-]{1,128}"));
    }

    private OpenRole validateRole(OpenRole value) {
        if (value == null || !canonicalUuid(value.id()) || blank(value.key()) || blank(value.name())
                || !validInstant(value.createdAt()) || !validInstant(value.updatedAt())) throw invalidAuthorizationResponse();
        return value;
    }

    private OpenRole validateRole(OpenRole value, String expectedId) {
        validateRole(value);
        if (!expectedId.equals(value.id())) throw invalidAuthorizationResponse();
        return value;
    }

    private OpenPermission validatePermission(OpenPermission value) {
        if (value == null) throw invalidAuthorizationResponse();
        validatePermissionGrant(value.resource(), value.action());
        if (!String.valueOf(value.resource() + ":" + value.action()).equals(value.key()) || !canonicalUuid(value.id())
                || blank(value.name()) || !("CODE".equals(value.source()) || "MANUAL".equals(value.source()))
                || !validInstant(value.createdAt()) || !validInstant(value.updatedAt()))
            throw invalidAuthorizationResponse();
        return value;
    }

    private OpenPermission validatePermission(OpenPermission value, String expectedId) {
        validatePermission(value);
        if (!expectedId.equals(value.id())) throw invalidAuthorizationResponse();
        return value;
    }

    private OpenUserRoleAssignment validateAssignment(OpenUserRoleAssignment value) {
        return validateAssignment(value, null);
    }

    private OpenUserRoleAssignment validateAssignment(OpenUserRoleAssignment value, String expectedUserId) {
        return validateAssignment(value, expectedUserId, null, null);
    }

    private OpenUserRoleAssignment validateAssignment(OpenUserRoleAssignment value, String expectedUserId,
            String expectedRoleId, String expectedAssignmentId) {
        if (value == null || !canonicalUuid(value.id()) || !canonicalUuid(value.userId()) || !canonicalUuid(value.roleId())
                || value.organizationId() != null && !canonicalUuid(value.organizationId())
                || expectedUserId != null && !expectedUserId.equals(value.userId())
                || expectedRoleId != null && !expectedRoleId.equals(value.roleId())
                || expectedAssignmentId != null && !expectedAssignmentId.equals(value.id())
                || !validInstant(value.createdAt()) || !validInstant(value.updatedAt())) throw invalidAuthorizationResponse();
        return value;
    }

    private OpenRolePermissionBinding validateRolePermissionBinding(OpenRolePermissionBinding value, String expectedRoleId) {
        if (value == null || !canonicalUuid(value.roleId()) || !canonicalUuid(value.permissionId())
                || !expectedRoleId.equals(value.roleId())
                || !validInstant(value.createdAt())) throw invalidAuthorizationResponse();
        return value;
    }

    private OpenRolePermissionSet validateRolePermissionSet(OpenRolePermissionSet value) {
        if (value == null || !canonicalUuid(value.roleId()) || value.permissionIds() == null
                || value.permissionIds().stream().anyMatch(id -> !canonicalUuid(id))) throw invalidAuthorizationResponse();
        return value;
    }

    private OpenRolePermissionSet validateRolePermissionSet(OpenRolePermissionSet value, String expectedRoleId) {
        validateRolePermissionSet(value);
        if (!expectedRoleId.equals(value.roleId())) throw invalidAuthorizationResponse();
        return value;
    }

    private <T> T parseAuthorizationBody(JsonNode body, Class<T> type, String... requiredFields) {
        requireAuthorizationFields(body, requiredFields);
        try { return mapper.convertValue(body, type); }
        catch (IllegalArgumentException exception) { throw invalidAuthorizationResponse(); }
    }

    private <T> T parseAuthorizationPage(JsonNode body, Class<T> type, String... requiredItemFields) {
        requireAuthorizationFields(body, "content", "page");
        JsonNode content = body.path("content");
        JsonNode page = body.path("page");
        if (!content.isArray() || !page.isObject()) throw invalidAuthorizationResponse();
        requireAuthorizationFields(page, "size", "number", "totalElements", "totalPages");
        for (JsonNode item : content) requireAuthorizationFields(item, requiredItemFields);
        return parseAuthorizationBody(body, type, "content", "page");
    }

    private static void requireAuthorizationFields(JsonNode body, String... fields) {
        if (body == null || !body.isObject()) throw invalidAuthorizationResponse();
        for (String field : fields) if (!body.hasNonNull(field)) throw invalidAuthorizationResponse();
    }

    private static boolean blank(String value) { return value == null || value.isBlank(); }
    private static void validatePage(List<?> content, AuthorizationPageMetadata page) {
        int expectedPages = page == null || page.size() < 1 ? -1
                : (int) Math.ceil((double) page.totalElements() / page.size());
        long remaining = page == null ? -1 : page.totalElements() - (long) page.number() * page.size();
        int expectedContent = page == null || page.totalElements() == 0 ? 0 : (int) Math.min(page.size(), remaining);
        if (content == null || page == null || page.size() < 1 || page.size() > 100 || page.number() < 0
                || page.totalElements() < 0 || page.totalPages() < 0 || content.size() > page.size()
                || content.size() > page.totalElements()
                || page.totalPages() != expectedPages
                || (page.totalElements() == 0 ? page.number() != 0 : page.number() >= page.totalPages())
                || content.size() != expectedContent)
            throw invalidAuthorizationResponse();
    }
    private static boolean canonicalUuid(String value) {
        if (value == null || !value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")) return false;
        try { return UUID.fromString(value).toString().equals(value); }
        catch (IllegalArgumentException exception) { return false; }
    }
    private static boolean validInstant(String value) {
        if (value == null || !value.endsWith("Z")) return false;
        try { Instant.parse(value); return true; }
        catch (DateTimeParseException exception) { return false; }
    }
    private static OpenRole withEtag(OpenRole value, String etag) {
        if (value == null) throw invalidAuthorizationResponse();
        return value.withEtag(requireEtag(etag));
    }
    private static OpenPermission withEtag(OpenPermission value, String etag) {
        if (value == null) throw invalidAuthorizationResponse();
        return value.withEtag(requireEtag(etag));
    }
    private static OpenRolePermissionPage withEtag(OpenRolePermissionPage value, String etag) {
        if (value == null) throw invalidAuthorizationResponse();
        return value.withEtag(requireEtag(etag));
    }
    private static OpenRolePermissionSet withEtag(OpenRolePermissionSet value, String etag) {
        if (value == null) throw invalidAuthorizationResponse();
        return value.withEtag(requireEtag(etag));
    }
    private static OpenUserRoleAssignment withEtag(OpenUserRoleAssignment value, String etag) {
        if (value == null) throw invalidAuthorizationResponse();
        return value.withEtag(requireEtag(etag));
    }
    private static PortalOpenApiException invalidAuthorizationResponse() {
        return new PortalOpenApiException("Invalid authorization management response", 0,
                "invalid_authorization_response", null);
    }

    private static String capitalize(String value) {
        return Character.toUpperCase(value.charAt(0)) + value.substring(1);
    }

    private static PortalOpenApiException invalidRegistrationGrantResponse() {
        return new PortalOpenApiException("Invalid registration grant response",
                0, "invalid_registration_grant_response", null);
    }

    private String normalizeMethod(String method) {
        if (method == null) {
            throw new PortalOpenApiException("Unsupported Portal Open API method: null",
                    0, "invalid_portal_method", null);
        }
        String normalized = method.strip().toUpperCase(Locale.ROOT);
        if (!SUPPORTED_METHODS.contains(normalized)) {
            throw new PortalOpenApiException("Unsupported Portal Open API method: " + method,
                    0, "invalid_portal_method", method);
        }
        return normalized;
    }

    private String portalUrl(String path) {
        if (path == null || !path.startsWith("/open/v1/")) {
            throw new PortalOpenApiException("Portal Open API path must start with /open/v1/",
                    0, "invalid_portal_path", path);
        }
        return config.getPortalEndpoint() + path;
    }

    private static String scopeForMethod(String method) {
        if ("GET".equals(method)) {
            return PORTAL_OPENAPI_READ_SCOPE;
        }
        return PORTAL_OPENAPI_WRITE_SCOPE;
    }

    private JsonNode readTree(String raw) throws IOException {
        if (raw == null || raw.isBlank()) {
            return mapper.createObjectNode();
        }
        try {
            return mapper.readTree(raw);
        } catch (IOException e) {
            return mapper.createObjectNode();
        }
    }

    private static boolean containsScope(String responseScope, String requestedScope) {
        for (String item : responseScope.split("\\s+")) {
            if (requestedScope.equals(item)) {
                return true;
            }
        }
        return false;
    }

    private static String readRaw(ResponseBody body) throws IOException {
        if (body == null) {
            return "";
        }
        return body.string();
    }

    private static String firstText(JsonNode payload, String... fields) {
        for (String field : fields) {
            String text = textOrNull(payload.path(field));
            if (text != null) {
                return text;
            }
        }
        return null;
    }

    private static String textOrNull(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        String value = node.asText();
        return value == null || value.isBlank() ? null : value;
    }

    private static void closeQuietly(ResponseBody body) {
        if (body != null) {
            body.close();
        }
    }

    private static OkHttpClient defaultHttp(PortalOpenApiClientConfig config) {
        Duration timeout = config.getTimeout();
        long timeoutMs = Math.max(1L, timeout.toMillis());
        return new OkHttpClient.Builder()
                .connectTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .readTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .writeTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .build();
    }

    private record PortalOpenApiResponse<T>(T body, String etag) {}
}
