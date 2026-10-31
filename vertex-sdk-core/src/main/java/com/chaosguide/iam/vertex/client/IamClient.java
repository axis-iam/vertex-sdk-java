package com.chaosguide.iam.vertex.client;

import com.chaosguide.iam.vertex.client.dto.AccountOrganizationResponse;
import com.chaosguide.iam.vertex.client.dto.AccountSecurityOperations.*;
import com.chaosguide.iam.vertex.client.dto.AccountPermissionSummaryResponse;
import com.chaosguide.iam.vertex.client.dto.AccountSecuritySummaryResponse;
import com.chaosguide.iam.vertex.client.dto.AccountUpdateProfileRequest;
import com.chaosguide.iam.vertex.client.dto.EmailVerificationResponse;
import com.chaosguide.iam.vertex.client.dto.OrganizationSwitchRequest;
import com.chaosguide.iam.vertex.client.dto.OrganizationSwitchResponse;
import com.chaosguide.iam.vertex.client.dto.PasswordChangeRequest;
import com.chaosguide.iam.vertex.client.dto.PasswordForgotRequest;
import com.chaosguide.iam.vertex.client.dto.PasswordResetRequest;
import com.chaosguide.iam.vertex.client.dto.PermissionCheckRequest;
import com.chaosguide.iam.vertex.client.dto.PermissionCheckResponse;
import com.chaosguide.iam.vertex.client.dto.PermissionDto;
import com.chaosguide.iam.vertex.client.dto.PermissionListResponse;
import com.chaosguide.iam.vertex.client.dto.PublicOrganizationInvitationAcceptResponse;
import com.chaosguide.iam.vertex.client.dto.PublicOrganizationInvitationPreviewResponse;
import com.chaosguide.iam.vertex.client.dto.ResolveRequest;
import com.chaosguide.iam.vertex.client.dto.ResolveResponse;
import com.chaosguide.iam.vertex.client.dto.SendEmailVerificationRequest;
import com.chaosguide.iam.vertex.client.dto.SessionView;
import com.chaosguide.iam.vertex.client.dto.UserProfileResponse;
import com.chaosguide.iam.vertex.client.dto.VerifyEmailRequest;
import com.chaosguide.iam.vertex.exception.IamSdkException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.Credentials;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * IAM Server HTTP 客户端。
 *
 * <p>职责只覆盖 SDK 需要的三个协议边界：
 *
 * <ul>
 *   <li>{@code /open/v1/permissions:resolve}：运行时根据角色解析权限。</li>
 *   <li>{@code /open/v1/apps/{clientId}/permissions}：Gradle/codegen 拉取权限快照。</li>
 * </ul>
 *
 * <p>{@code clientId} 是 {@code ApplicationClient.clientId}。权限快照和权限上传属于服务端管理调用，
 * 必须使用 WEB/M2M confidential ApplicationClient，并配置对应 {@code clientSecret}。
 */
public class IamClient {

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final Pattern CONCRETE_PERMISSION = Pattern.compile("[a-z0-9_-]{1,128}:[a-z0-9_-]{1,128}");
    private static final Pattern PERMISSION_SEGMENT = Pattern.compile("[a-z0-9_-]{1,128}");
    private static final Pattern CANONICAL_UUID = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    private final OkHttpClient http;
    private final ObjectMapper mapper;
    private final String baseUrl;
    private final String clientId;
    private final String basicAuth;

    public IamClient(String baseUrl, String clientId, String clientSecret, Duration timeout, ObjectMapper mapper) {
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalArgumentException("baseUrl must not be blank");
        }
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.clientId = clientId;
        this.basicAuth = hasText(clientId) && hasText(clientSecret)
                ? Credentials.basic(clientId, clientSecret)
                : null;
        this.mapper = mapper;
        long timeoutMs = timeout == null ? 10_000L : Math.max(1_000L, timeout.toMillis());
        this.http = new OkHttpClient.Builder()
                .connectTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .readTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .writeTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .build();
    }

    // Visible for testing
    IamClient(OkHttpClient http, ObjectMapper mapper, String baseUrl, String clientId, String clientSecret) {
        this.http = http;
        this.mapper = mapper;
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.clientId = clientId;
        this.basicAuth = hasText(clientId) && hasText(clientSecret)
                ? Credentials.basic(clientId, clientSecret)
                : null;
    }

    public String getClientId() {
        return clientId;
    }

    public ResolveResponse resolvePermissions(ResolveRequest request) {
        requireConfidentialClientCredentials("resolvePermissions");
        if (request.roles() == null || request.roles().isEmpty()) {
            return new ResolveResponse(java.util.Set.of());
        }
        // 运行时鉴权路径：JWT 只带 roles，最终 permissions 由 IAM 根据 clientId + roles 解析。
        String url = baseUrl + "/open/v1/permissions:resolve";
        byte[] body = writeJson(request);
        Request.Builder b = new Request.Builder().url(url).post(RequestBody.create(body, JSON));
        if (basicAuth != null) {
            b.header("Authorization", basicAuth);
        }
        try (Response resp = http.newCall(b.build()).execute()) {
            if (!resp.isSuccessful()) {
                throw new IamSdkException("resolvePermissions failed: HTTP " + resp.code());
            }
            JsonNode root = readTree(resp.body());
            requireExactFields(root, "permissions");
            return new ResolveResponse(new java.util.LinkedHashSet<>(parseStrictPermissionKeys(root.path("permissions"), true)));
        } catch (IOException e) {
            throw new IamSdkException("resolvePermissions IO error: " + e.getMessage(), e);
        }
    }

    /**
     * 拉取应用权限快照，主要给 Gradle 插件或管理工具使用。
     *
     * @param ifNoneMatch 可选 ETag。服务端返回 304 时，结果权限列表为空，etag 沿用服务端返回值或入参。
     */
    public PermissionListResponse listPermissions(String appClientId, String ifNoneMatch) {
        requireConfidentialClientCredentials("listPermissions");
        String url = baseUrl + "/open/v1/apps/" + enc(appClientId) + "/permissions";
        Request.Builder b = new Request.Builder().url(url).get();
        if (basicAuth != null) {
            b.header("Authorization", basicAuth);
        }
        if (ifNoneMatch != null && !ifNoneMatch.isBlank()) {
            b.header("If-None-Match", ifNoneMatch);
        }
        try (Response resp = http.newCall(b.build()).execute()) {
            String etag = resp.header("ETag");
            if (resp.code() == 304) {
                return new PermissionListResponse(List.of(), etag != null ? etag : ifNoneMatch);
            }
            if (!resp.isSuccessful()) {
                throw new IamSdkException("listPermissions failed: HTTP " + resp.code());
            }
            JsonNode body = readTree(resp.body());
            return new PermissionListResponse(
                    parsePermissionList(body, appClientId),
                    etag != null ? etag : textOrNull(body.path("etag")));
        } catch (IOException e) {
            throw new IamSdkException("listPermissions IO error: " + e.getMessage(), e);
        }
    }

    /** Fetch the safe current-user authentication context. Never decode an access token for UI context. */
    public com.chaosguide.iam.vertex.client.dto.CurrentUserResponse getCurrentUser(String accessToken) {
        Request request = new Request.Builder().url(baseUrl + "/api/v1/auth/me").get()
                .header("Authorization", "Bearer " + normalizeBearerToken(accessToken)).build();
        try (Response response = http.newCall(request).execute()) {
            if (!response.isSuccessful()) throw new com.chaosguide.iam.vertex.exception.CurrentUserException(response.code());
            try {
                return com.chaosguide.iam.vertex.client.dto.CurrentUserResponse.fromJson(readTree(response.body()));
            } catch (IllegalArgumentException ex) {
                throw new IamSdkException("Invalid current-user view", ex);
            }
        } catch (IOException ex) {
            throw new IamSdkException("Current-user request failed", ex);
        }
    }

    /**
     * Fetches the current user's latest profile via {@code GET /api/v1/auth/me/profile}.
     *
     * <p>This call uses the user's bearer token, not the SDK client secret. It is intended for
     * explicit profile reads and should not be called automatically during every authorization
     * check. Its optional {@code metadata} field is profile metadata, not app-scoped authorization
     * attributes.
     */
    public UserProfileResponse getMe(String accessToken) {
        return getAccountProfile(accessToken);
    }

    /**
     * Fetches the current user's account-center profile.
     */
    public UserProfileResponse getAccountProfile(String accessToken) {
        String token = normalizeBearerToken(accessToken);
        String url = baseUrl + "/api/v1/auth/me/profile";
        Request request =
                new Request.Builder()
                        .url(url)
                        .get()
                        .header("Authorization", "Bearer " + token)
                        .build();
        try (Response resp = http.newCall(request).execute()) {
            if (!resp.isSuccessful()) {
                throw new IamSdkException("getMe failed: HTTP " + resp.code());
            }
            return readJson(resp.body(), UserProfileResponse.class);
        } catch (IOException e) {
            throw new IamSdkException("getMe IO error: " + e.getMessage(), e);
        }
    }

    /**
     * Updates safe scalar current-user profile fields with the user's bearer token.
     */
    public UserProfileResponse updateAccountProfile(String accessToken, AccountUpdateProfileRequest body) {
        String token = normalizeBearerToken(accessToken);
        String url = baseUrl + "/api/v1/auth/me/profile";
        Request request =
                new Request.Builder()
                        .url(url)
                        .patch(RequestBody.create(writeJson(body), JSON))
                        .header("Authorization", "Bearer " + token)
                        .build();
        return executeJson(request, UserProfileResponse.class, "updateAccountProfile");
    }

    /**
     * Fetches the current user's secret-free security summary.
     */
    public AccountSecuritySummaryResponse getAccountSecuritySummary(String accessToken) {
        return bearerGet(accessToken, "/api/v1/auth/me/security", AccountSecuritySummaryResponse.class, "getAccountSecuritySummary");
    }

    /**
     * Sends an opaque public email-verification message for this SDK client id.
     */
    public EmailVerificationResponse sendEmailVerification(String email) {
        Request request =
                new Request.Builder()
                        .url(baseUrl + "/api/v1/auth/email/verification/send")
                        .post(RequestBody.create(writeJson(new SendEmailVerificationRequest(clientId, email)), JSON))
                        .build();
        return executeJson(request, EmailVerificationResponse.class, "sendEmailVerification");
    }

    /**
     * Verifies an email-verification token.
     */
    public EmailVerificationResponse verifyEmail(String token) {
        Request request =
                new Request.Builder()
                        .url(baseUrl + "/api/v1/auth/email/verification/verify")
                        .post(RequestBody.create(writeJson(new VerifyEmailRequest(requireText(token, "token"))), JSON))
                        .build();
        return executeJson(request, EmailVerificationResponse.class, "verifyEmail");
    }

    /**
     * Changes the current user's password with bearer auth. IAM owns step-up and validation errors.
     */
    public void changePassword(String accessToken, PasswordChangeRequest body) {
        String token = normalizeBearerToken(accessToken);
        Request request =
                new Request.Builder()
                        .url(baseUrl + "/api/v1/auth/password/change")
                        .post(RequestBody.create(writeJson(body), JSON))
                        .header("Authorization", "Bearer " + token)
                        .build();
        executeNoContent(request, "changePassword");
    }

    /**
     * Starts the opaque public forgot-password flow for this SDK client id.
     */
    public void requestPasswordReset(String email, String redirectUri) {
        Request request =
                new Request.Builder()
                        .url(baseUrl + "/api/v1/auth/password/forgot")
                        .post(RequestBody.create(writeJson(new PasswordForgotRequest(email, clientId, redirectUri)), JSON))
                        .build();
        executeNoContent(request, "requestPasswordReset");
    }

    /**
     * Completes public password reset.
     */
    public void resetPassword(String token, String newPassword) {
        Request request =
                new Request.Builder()
                        .url(baseUrl + "/api/v1/auth/password/reset")
                        .post(RequestBody.create(writeJson(new PasswordResetRequest(requireText(token, "token"), newPassword)), JSON))
                        .build();
        executeNoContent(request, "resetPassword");
    }

    /**
     * Lists the caller's active sessions.
     */
    public List<SessionView> listAccountSessions(String accessToken) {
        String token = normalizeBearerToken(accessToken);
        Request request =
                new Request.Builder()
                        .url(baseUrl + "/api/v1/auth/sessions")
                        .get()
                        .header("Authorization", "Bearer " + token)
                        .build();
        return executeJson(request, new TypeReference<List<SessionView>>() {}, "listAccountSessions");
    }

    /**
     * Revokes one session owned by the current user.
     */
    public void revokeAccountSession(String accessToken, String sessionId) {
        String token = normalizeBearerToken(accessToken);
        Request request =
                new Request.Builder()
                        .url(baseUrl + "/api/v1/auth/sessions/" + enc(requireText(sessionId, "sessionId")))
                        .delete()
                        .header("Authorization", "Bearer " + token)
                        .build();
        executeNoContent(request, "revokeAccountSession");
    }

    /**
     * Revokes all sessions except the current token's sid.
     */
    public void revokeOtherAccountSessions(String accessToken) {
        String token = normalizeBearerToken(accessToken);
        Request request =
                new Request.Builder()
                        .url(baseUrl + "/api/v1/auth/sessions")
                        .delete()
                        .header("Authorization", "Bearer " + token)
                        .build();
        executeNoContent(request, "revokeOtherAccountSessions");
    }

    /**
     * Revokes the authenticated OAuth token and session.
     */
    public void logoutAccount(String accessToken) {
        String token = normalizeBearerToken(accessToken);
        RequestBody body = RequestBody.create(new byte[0], JSON);
        Request request =
                new Request.Builder()
                        .url(baseUrl + "/api/v1/auth/logout")
                        .post(body)
                        .header("Authorization", "Bearer " + token)
                        .build();
        executeNoContent(request, "logoutAccount");
    }

    /**
     * Lists current user's Application-scoped Organization memberships.
     */
    public List<AccountOrganizationResponse> listAccountOrganizations(String accessToken) {
        String token = normalizeBearerToken(accessToken);
        Request request =
                new Request.Builder()
                        .url(baseUrl + "/api/v1/auth/me/organizations")
                        .get()
                        .header("Authorization", "Bearer " + token)
                        .build();
        return executeJson(request, new TypeReference<List<AccountOrganizationResponse>>() {}, "listAccountOrganizations");
    }

    /**
     * Returns the current Organization context, or {@code null} when the server returns JSON null.
     */
    public AccountOrganizationResponse getCurrentAccountOrganization(String accessToken) {
        return bearerGet(accessToken, "/api/v1/auth/me/organizations/current", AccountOrganizationResponse.class, "getCurrentAccountOrganization");
    }

    /**
     * Switches current Organization context and returns the server continuation. This method does
     * not mutate local JWT claims.
     */
    public OrganizationSwitchResponse switchAccountOrganization(String accessToken, String organizationId) {
        String token = normalizeBearerToken(accessToken);
        Request request =
                new Request.Builder()
                        .url(baseUrl + "/api/v1/auth/me/organizations/current")
                        .post(RequestBody.create(writeJson(new OrganizationSwitchRequest(organizationId)), JSON))
                        .header("Authorization", "Bearer " + token)
                        .build();
        return executeJson(request, OrganizationSwitchResponse.class, "switchAccountOrganization");
    }

    /**
     * Checks membership from the current-user Organization list. This does not call an unbacked
     * membership endpoint.
     */
    public boolean hasAccountOrganizationMembership(String accessToken, String organizationId) {
        String expected = requireText(organizationId, "organizationId");
        return listAccountOrganizations(accessToken).stream()
                .anyMatch(organization -> expected.equals(organization.organizationId()));
    }

    /**
     * Gets IAM's current-user permission summary for the active or explicit Organization context.
     */
    public AccountPermissionSummaryResponse getAccountPermissionSummary(String accessToken, String organizationId) {
        String path = "/api/v1/auth/me/permissions";
        if (hasText(organizationId)) {
            path += "?organizationId=" + enc(organizationId.strip());
        }
        return bearerGet(accessToken, path, AccountPermissionSummaryResponse.class, "getAccountPermissionSummary");
    }

    /**
     * Checks one permission through IAM. Wildcard semantics remain backend-owned.
     */
    public PermissionCheckResponse checkAccountPermission(String accessToken, PermissionCheckRequest body) {
        String token = normalizeBearerToken(accessToken);
        Request request =
                new Request.Builder()
                        .url(baseUrl + "/api/v1/auth/me/permissions:check")
                        .post(RequestBody.create(writeJson(body), JSON))
                        .header("Authorization", "Bearer " + token)
                        .build();
        return executeJson(request, PermissionCheckResponse.class, "checkAccountPermission");
    }

    /**
     * Previews a public Organization invitation without bearer auth.
     */
    public PublicOrganizationInvitationPreviewResponse previewOrganizationInvitation(String invitationToken) {
        String token = requireText(invitationToken, "invitationToken");
        Request request =
                new Request.Builder()
                        .url(baseUrl + "/api/v1/auth/organization-invitations/" + enc(token))
                        .get()
                        .build();
        return executeJson(request, PublicOrganizationInvitationPreviewResponse.class, "previewOrganizationInvitation");
    }

    /**
     * Accepts a public Organization invitation. When {@code accessToken} is blank, IAM may return a
     * login-required continuation response.
     */
    public PublicOrganizationInvitationAcceptResponse acceptOrganizationInvitation(String invitationToken, String accessToken) {
        String token = requireText(invitationToken, "invitationToken");
        Request.Builder request =
                new Request.Builder()
                        .url(baseUrl + "/api/v1/auth/organization-invitations/" + enc(token) + "/accept")
                        .post(RequestBody.create(new byte[0], JSON));
        if (accessToken != null && !accessToken.isBlank()) {
            request.header("Authorization", "Bearer " + normalizeBearerToken(accessToken));
        }
        return executeJson(request.build(), PublicOrganizationInvitationAcceptResponse.class, "acceptOrganizationInvitation");
    }

    /** GET /api/v1/auth/me/identifiers. No implicit mutation replay. */
    public AccountIdentifiers listAccountIdentifiers(String accessToken) {
        return securityRequest(accessToken, "GET", "/api/v1/auth/me/identifiers", null, null,
                new TypeReference<AccountIdentifiers>() {});
    }
    /** GET /api/v1/auth/me/login-methods. No implicit mutation replay. */
    public AccountLoginMethods listAccountLoginMethods(String accessToken) {
        return securityRequest(accessToken, "GET", "/api/v1/auth/me/login-methods", null, null,
                new TypeReference<AccountLoginMethods>() {});
    }
    /** GET /api/v1/auth/me/linkable-identity-providers. No implicit mutation replay. */
    public List<LinkableIdentityProvider> listLinkableIdentityProviders(String accessToken) {
        return securityRequest(accessToken, "GET", "/api/v1/auth/me/linkable-identity-providers",
                null, null, new TypeReference<List<LinkableIdentityProvider>>() {});
    }
    /** POST /api/v1/auth/me/identity-operations. No implicit mutation replay. */
    public IdentityOperation createIdentityOperation(
            String accessToken, IdentityOperationCreate request, String idempotencyKey) {
        return securityRequest(accessToken, "POST", "/api/v1/auth/me/identity-operations",
                SecurityWireCodec.encode(request), SecurityWireCodec.key(idempotencyKey),
                new TypeReference<IdentityOperation>() {});
    }
    /** GET /api/v1/auth/me/identity-operations/{id}. No implicit mutation replay. */
    public IdentityOperation getIdentityOperation(String accessToken, java.util.UUID operationId) {
        return securityRequest(accessToken, "GET",
                "/api/v1/auth/me/identity-operations/" + SecurityWireCodec.id(operationId) + "",
                null, null, new TypeReference<IdentityOperation>() {});
    }
    /** GET /api/v1/auth/me/identity-operations/transfers. No implicit mutation replay. */
    public List<IdentityOperation> listIdentityTransfers(String accessToken) {
        return securityRequest(accessToken, "GET", "/api/v1/auth/me/identity-operations/transfers",
                null, null, new TypeReference<List<IdentityOperation>>() {});
    }
    /**
     * POST /api/v1/auth/me/identity-operations/{id}/reauthenticate. No implicit mutation replay.
     */
    public IdentityOperation reauthenticateIdentityOperation(
            String accessToken, java.util.UUID operationId, Reauthentication request) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/me/identity-operations/" + SecurityWireCodec.id(operationId)
                        + "/reauthenticate",
                SecurityWireCodec.encode(request), null, new TypeReference<IdentityOperation>() {});
    }
    /** POST /api/v1/auth/me/identity-operations/{id}/challenges. No implicit mutation replay. */
    public IdentityOperation challengeIdentityOperation(
            String accessToken, java.util.UUID operationId, TargetProofMethod targetProofMethod) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/me/identity-operations/" + SecurityWireCodec.id(operationId)
                        + "/challenges",
                Map.of("targetProofMethod", java.util.Objects.requireNonNull(targetProofMethod)),
                null, new TypeReference<IdentityOperation>() {});
    }
    /**
     * POST /api/v1/auth/me/identity-operations/{id}/current-account/challenges. No implicit
     * mutation replay.
     */
    public IdentityChallengeResult challengeIdentityCurrentAccount(
            String accessToken, java.util.UUID operationId, java.util.UUID identifierId) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/me/identity-operations/" + SecurityWireCodec.id(operationId)
                        + "/current-account/challenges",
                Map.of("identifierId", SecurityWireCodec.id(identifierId)), null,
                new TypeReference<IdentityChallengeResult>() {});
    }
    /** POST /api/v1/auth/me/identity-operations/{id}/complete. No implicit mutation replay. */
    public IdentityOperation completeIdentityOperation(
            String accessToken, java.util.UUID operationId, IdentityOperationComplete request) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/me/identity-operations/" + SecurityWireCodec.id(operationId)
                        + "/complete",
                SecurityWireCodec.encode(request), null, new TypeReference<IdentityOperation>() {});
    }
    /** POST /api/v1/auth/me/identity-operations/{id}/cancel. No implicit mutation replay. */
    public IdentityOperation cancelIdentityOperation(
            String accessToken, java.util.UUID operationId) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/me/identity-operations/" + SecurityWireCodec.id(operationId)
                        + "/cancel",
                Map.of(), null, new TypeReference<IdentityOperation>() {});
    }
    /**
     * POST /api/v1/auth/me/identity-operations/{id}/confirm-transfer. No implicit mutation replay.
     */
    public IdentityOperation confirmIdentityTransfer(
            String accessToken, java.util.UUID operationId, TransferDecision decision) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/me/identity-operations/" + SecurityWireCodec.id(operationId)
                        + "/confirm-transfer",
                Map.of("decision", java.util.Objects.requireNonNull(decision)), null,
                new TypeReference<IdentityOperation>() {});
    }
    /** POST /api/v1/auth/me/identity-operations/{id}/authorize. No implicit mutation replay. */
    public ProviderAuthorization authorizeIdentityOperation(
            String accessToken, java.util.UUID operationId, IdentityProviderAuthorize request) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/me/identity-operations/" + SecurityWireCodec.id(operationId)
                        + "/authorize",
                SecurityWireCodec.encode(request), null,
                new TypeReference<ProviderAuthorization>() {});
    }
    /**
     * POST /api/v1/auth/me/identity-operations/{id}/provider-callback. No implicit mutation
     * replay.
     */
    public IdentityOperation completeIdentityProviderAuthorization(
            String accessToken, java.util.UUID operationId, ProviderExchange request) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/me/identity-operations/" + SecurityWireCodec.id(operationId)
                        + "/provider-callback",
                SecurityWireCodec.encode(request), null, new TypeReference<IdentityOperation>() {});
    }
    /** GET /api/v1/auth/mfa/capabilities. No implicit mutation replay. */
    /** Read the current unused recovery-code count for the explicit current-user bearer. */
    public RecoveryCodesRemaining getRecoveryCodesRemaining(String accessToken) {
        return securityRequest(accessToken, "GET", "/api/v1/auth/mfa/recovery-codes/remaining",
            null, null, new TypeReference<RecoveryCodesRemaining>() {});
    }

    public MfaCapabilities getMfaCapabilities(String accessToken) {
        return securityRequest(accessToken, "GET", "/api/v1/auth/mfa/capabilities", null, null,
                new TypeReference<MfaCapabilities>() {});
    }
    /** POST /api/v1/auth/mfa/operations. No implicit mutation replay. */
    public MfaOperation createMfaOperation(
            String accessToken, MfaOperationCreate request, String idempotencyKey) {
        return securityRequest(accessToken, "POST", "/api/v1/auth/mfa/operations",
                SecurityWireCodec.encode(request), SecurityWireCodec.key(idempotencyKey),
                new TypeReference<MfaOperation>() {});
    }
    /** GET /api/v1/auth/mfa/operations/{id}. No implicit mutation replay. */
    public MfaOperation getMfaOperation(String accessToken, java.util.UUID operationId) {
        return securityRequest(accessToken, "GET",
                "/api/v1/auth/mfa/operations/" + SecurityWireCodec.id(operationId) + "", null, null,
                new TypeReference<MfaOperation>() {});
    }
    /** POST /api/v1/auth/mfa/operations/{id}/reauthenticate. No implicit mutation replay. */
    public MfaOperation reauthenticateMfaOperation(
            String accessToken, java.util.UUID operationId, Reauthentication request) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/mfa/operations/" + SecurityWireCodec.id(operationId)
                        + "/reauthenticate",
                SecurityWireCodec.encode(request), null, new TypeReference<MfaOperation>() {});
    }
    /** POST /api/v1/auth/mfa/operations/{id}/challenges. No implicit mutation replay. */
    public MfaChallengeResult challengeMfaOperation(
            String accessToken, java.util.UUID operationId, java.util.UUID identifierId) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/mfa/operations/" + SecurityWireCodec.id(operationId) + "/challenges",
                Map.of("method", "EMAIL_OTP", "identifierId", SecurityWireCodec.id(identifierId)),
                null, new TypeReference<MfaChallengeResult>() {});
    }
    /** POST /api/v1/auth/mfa/operations/{id}/authorize. No implicit mutation replay. */
    public ProviderAuthorization authorizeMfaOperation(
            String accessToken, java.util.UUID operationId, MfaProviderAuthorize request) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/mfa/operations/" + SecurityWireCodec.id(operationId) + "/authorize",
                SecurityWireCodec.encode(request), null,
                new TypeReference<ProviderAuthorization>() {});
    }
    /** POST /api/v1/auth/mfa/operations/{id}/provider-callback. No implicit mutation replay. */
    public MfaOperation completeMfaProviderAuthorization(
            String accessToken, java.util.UUID operationId, ProviderExchange request) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/mfa/operations/" + SecurityWireCodec.id(operationId)
                        + "/provider-callback",
                SecurityWireCodec.encode(request), null, new TypeReference<MfaOperation>() {});
    }
    /** POST /api/v1/auth/mfa/operations/{id}/begin. No implicit mutation replay. */
    public TotpBeginResult beginTotpEnrollmentOperation(
            String accessToken, java.util.UUID operationId) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/mfa/operations/" + SecurityWireCodec.id(operationId) + "/begin",
                Map.of(), null, new TypeReference<TotpBeginResult>() {});
    }
    /** POST /api/v1/auth/mfa/operations/{id}/complete. No implicit mutation replay. */
    public MfaCompletionResult completeMfaOperation(
            String accessToken, java.util.UUID operationId, String code) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/mfa/operations/" + SecurityWireCodec.id(operationId) + "/complete",
                code == null ? Map.of() : Map.of("code", SecurityWireCodec.code(code)), null,
                new TypeReference<MfaCompletionResult>() {});
    }
    /** POST /api/v1/auth/mfa/operations/{id}/cancel. No implicit mutation replay. */
    public MfaOperation cancelMfaOperation(String accessToken, java.util.UUID operationId) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/mfa/operations/" + SecurityWireCodec.id(operationId) + "/cancel",
                Map.of(), null, new TypeReference<MfaOperation>() {});
    }
    /** POST /api/v1/auth/me/identity-operations/{id}/step-up/start. No implicit mutation replay. */
    public OperationStepUpChallenge startIdentityOperationStepUp(
            String accessToken, java.util.UUID operationId) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/me/identity-operations/" + SecurityWireCodec.id(operationId)
                        + "/step-up/start",
                Map.of(), null, new TypeReference<OperationStepUpChallenge>() {});
    }
    /**
     * POST /api/v1/auth/me/identity-operations/{id}/step-up/verify. No implicit mutation replay.
     */
    public IdentityOperation verifyIdentityOperationStepUp(
            String accessToken, java.util.UUID operationId, OperationStepUpVerify request) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/me/identity-operations/" + SecurityWireCodec.id(operationId)
                        + "/step-up/verify",
                SecurityWireCodec.encode(request), null, new TypeReference<IdentityOperation>() {});
    }
    /**
     * POST /api/v1/auth/me/identity-operations/{id}/step-up/webauthn/start. No implicit mutation
     * replay.
     */
    public OperationWebAuthnStart startIdentityOperationWebAuthn(
            String accessToken, java.util.UUID operationId, String challengeId) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/me/identity-operations/" + SecurityWireCodec.id(operationId)
                        + "/step-up/webauthn/start",
                Map.of("challengeId", SecurityWireCodec.text(challengeId)), null,
                new TypeReference<OperationWebAuthnStart>() {});
    }
    /**
     * POST /api/v1/auth/me/identity-operations/{id}/step-up/webauthn/verify. No implicit mutation
     * replay.
     */
    public IdentityOperation verifyIdentityOperationWebAuthn(
            String accessToken, java.util.UUID operationId, OperationWebAuthnVerify request) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/me/identity-operations/" + SecurityWireCodec.id(operationId)
                        + "/step-up/webauthn/verify",
                SecurityWireCodec.encode(request), null, new TypeReference<IdentityOperation>() {});
    }
    /** POST /api/v1/auth/mfa/operations/{id}/step-up/start. No implicit mutation replay. */
    public OperationStepUpChallenge startMfaOperationStepUp(
            String accessToken, java.util.UUID operationId) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/mfa/operations/" + SecurityWireCodec.id(operationId)
                        + "/step-up/start",
                Map.of(), null, new TypeReference<OperationStepUpChallenge>() {});
    }
    /** POST /api/v1/auth/mfa/operations/{id}/step-up/verify. No implicit mutation replay. */
    public MfaOperation verifyMfaOperationStepUp(
            String accessToken, java.util.UUID operationId, OperationStepUpVerify request) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/mfa/operations/" + SecurityWireCodec.id(operationId)
                        + "/step-up/verify",
                SecurityWireCodec.encode(request), null, new TypeReference<MfaOperation>() {});
    }
    /**
     * POST /api/v1/auth/mfa/operations/{id}/step-up/webauthn/start. No implicit mutation replay.
     */
    public OperationWebAuthnStart startMfaOperationWebAuthn(
            String accessToken, java.util.UUID operationId, String challengeId) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/mfa/operations/" + SecurityWireCodec.id(operationId)
                        + "/step-up/webauthn/start",
                Map.of("challengeId", SecurityWireCodec.text(challengeId)), null,
                new TypeReference<OperationWebAuthnStart>() {});
    }
    /**
     * POST /api/v1/auth/mfa/operations/{id}/step-up/webauthn/verify. No implicit mutation replay.
     */
    public MfaOperation verifyMfaOperationWebAuthn(
            String accessToken, java.util.UUID operationId, OperationWebAuthnVerify request) {
        return securityRequest(accessToken, "POST",
                "/api/v1/auth/mfa/operations/" + SecurityWireCodec.id(operationId)
                        + "/step-up/webauthn/verify",
                SecurityWireCodec.encode(request), null, new TypeReference<MfaOperation>() {});
    }
    private <T> T securityRequest(String accessToken, String method, String path, Object body,
            String key, TypeReference<T> type) {
        if (Thread.currentThread().isInterrupted())
            throw new com.chaosguide.iam.vertex.exception.AccountSecurityTransportException(false);
        String token = SecurityWireCodec.token(accessToken);
        Request.Builder builder = new Request.Builder()
                                          .url(baseUrl + path)
                                          .header("Authorization", "Bearer " + token)
                                          .header("Accept", "application/json");
        if (key != null)
            builder.header("Idempotency-Key", key);
        if (method.equals("GET"))
            builder.get();
        else {
            byte[] payload = writeJson(body);
            builder.post(new RequestBody() {
                @Override
                public MediaType contentType() {
                    return JSON;
                }
                @Override
                public long contentLength() {
                    return payload.length;
                }
                @Override
                public boolean isOneShot() {
                    return true;
                }
                @Override
                public void writeTo(okio.BufferedSink sink) throws IOException {
                    sink.write(payload);
                }
            });
        }
        // OkHttp's connection recovery must not replay once-only material or unknown mutations.
        java.util.concurrent.atomic.AtomicReference<String> originalRetryAfter =
                new java.util.concurrent.atomic.AtomicReference<>();
        OkHttpClient scoped =
                http.newBuilder()
                        .retryOnConnectionFailure(method.equals("GET"))
                        .followRedirects(false)
                        .followSslRedirects(false)
                        .cache(null)
                        .authenticator(okhttp3.Authenticator.NONE)
                        .proxyAuthenticator(okhttp3.Authenticator.NONE)
                        .addNetworkInterceptor(chain -> {
                            Response received = chain.proceed(chain.request());
                            originalRetryAfter.set(received.header("Retry-After"));
                            // Keep the wire value for our strict parser, but disable OkHttp's
                            // built-in 503 follow-up (including its unbounded integer parsing).
                            return received.code() == 503
                                    ? received.newBuilder().removeHeader("Retry-After").build()
                                    : received;
                        })
                        .build();
        try (Response response = scoped.newCall(builder.build()).execute()) {
            if (response.body() == null)
                throw new com.chaosguide.iam.vertex.exception.AccountSecurityProtocolException();
            byte[] raw;
            var source = response.body().source();
            source.request(1048577L);
            if (source.buffer().size() > 1048576L)
                throw new com.chaosguide.iam.vertex.exception.AccountSecurityProtocolException();
            raw = source.readByteArray();
            if (!response.isSuccessful())
                throw SecurityWireCodec.error(
                        mapper, response.code(), raw, originalRetryAfter.get());
            return SecurityWireCodec.decode(mapper, raw, type);
        } catch (IOException ex) {
            if (ex instanceof java.io.InterruptedIOException
                    && Thread.currentThread().isInterrupted())
                Thread.currentThread().interrupt();
            throw new com.chaosguide.iam.vertex.exception.AccountSecurityTransportException(
                    !method.equals("GET"));
        }
    }

    private byte[] writeJson(Object value) {
        try {
            return mapper.writeValueAsBytes(value);
        } catch (IOException e) {
            throw new IamSdkException("JSON serialize error", e);
        }
    }

    private <T> T readJson(ResponseBody body, Class<T> clazz) throws IOException {
        if (body == null) {
            throw new IamSdkException("empty response body");
        }
        return mapper.readValue(body.byteStream(), clazz);
    }

    private <T> T readJson(ResponseBody body, TypeReference<T> type) throws IOException {
        if (body == null) {
            throw new IamSdkException("empty response body");
        }
        return mapper.readValue(body.byteStream(), type);
    }

    private <T> T bearerGet(String accessToken, String path, Class<T> clazz, String operation) {
        String token = normalizeBearerToken(accessToken);
        Request request =
                new Request.Builder()
                        .url(baseUrl + path)
                        .get()
                        .header("Authorization", "Bearer " + token)
                        .build();
        return executeJson(request, clazz, operation);
    }

    private <T> T executeJson(Request request, Class<T> clazz, String operation) {
        try (Response resp = http.newCall(request).execute()) {
            if (!resp.isSuccessful()) {
                throw new IamSdkException(operation + " failed: HTTP " + resp.code());
            }
            return readJson(resp.body(), clazz);
        } catch (IOException e) {
            throw new IamSdkException(operation + " IO error: " + e.getMessage(), e);
        }
    }

    private <T> T executeJson(Request request, TypeReference<T> type, String operation) {
        try (Response resp = http.newCall(request).execute()) {
            if (!resp.isSuccessful()) {
                throw new IamSdkException(operation + " failed: HTTP " + resp.code());
            }
            return readJson(resp.body(), type);
        } catch (IOException e) {
            throw new IamSdkException(operation + " IO error: " + e.getMessage(), e);
        }
    }

    private void executeNoContent(Request request, String operation) {
        try (Response resp = http.newCall(request).execute()) {
            if (!resp.isSuccessful()) {
                throw new IamSdkException(operation + " failed: HTTP " + resp.code());
            }
        } catch (IOException e) {
            throw new IamSdkException(operation + " IO error: " + e.getMessage(), e);
        }
    }

    private JsonNode readTree(ResponseBody body) throws IOException {
        if (body == null) {
            throw new IamSdkException("empty response body");
        }
        return mapper.reader()
                .with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .readTree(body.byteStream());
    }

    private static List<PermissionDto> parsePermissionList(JsonNode root, String requestedClientId) {
        requireExactFields(root, "applicationId", "clientId", "roles");
        String applicationId = textOrNull(root.path("applicationId"));
        if (applicationId == null || !CANONICAL_UUID.matcher(applicationId).matches()
                || !requestedClientId.equals(textOrNull(root.path("clientId")))) {
            throw new IamSdkException("invalid permission snapshot response");
        }
        Map<String, PermissionDto> out = new LinkedHashMap<>();
        JsonNode roles = root.path("roles");
        if (!roles.isArray()) {
            throw new IamSdkException("invalid permission snapshot response");
        }
        var roleKeys = new HashSet<String>();
        for (JsonNode role : roles) {
            requireExactFields(role, "key", "name", "permissions");
            String roleKey = textOrNull(role.path("key"));
            if (roleKey == null || !PERMISSION_SEGMENT.matcher(roleKey).matches()
                    || textOrNull(role.path("name")) == null || !roleKeys.add(roleKey)) {
                throw new IamSdkException("invalid permission snapshot response");
            }
            for (String key : parseStrictPermissionKeys(role.path("permissions"), true)) {
                PermissionDto dto = parsePermissionKey(key);
                out.putIfAbsent(key, dto);
            }
        }
        return new ArrayList<>(out.values());
    }

    private static List<String> parseStrictPermissionKeys(JsonNode permissions, boolean allowWildcards) {
        if (!permissions.isArray()) throw new IamSdkException("invalid permission response");
        var seen = new HashSet<String>();
        var out = new ArrayList<String>();
        for (JsonNode permission : permissions) {
            String key = permission.isTextual() ? permission.textValue() : null;
            boolean valid = key != null && (CONCRETE_PERMISSION.matcher(key).matches()
                    || allowWildcards && (key.equals("*:*") || key.matches("[a-z0-9_-]{1,128}:\\*")));
            if (!valid
                    || !seen.add(permission.textValue())) {
                throw new IamSdkException("invalid permission response");
            }
            out.add(permission.textValue());
        }
        return out;
    }

    private static void requireExactFields(JsonNode node, String... fields) {
        if (!node.isObject() || node.size() != fields.length) throw new IamSdkException("invalid permission response");
        for (String field : fields) if (!node.has(field)) throw new IamSdkException("invalid permission response");
    }

    private static PermissionDto parsePermissionKey(String key) {
        if (key == null || !(CONCRETE_PERMISSION.matcher(key).matches()
                || key.equals("*:*") || key.matches("[a-z0-9_-]{1,128}:\\*"))) {
            throw new IamSdkException("invalid permission key");
        }
        int idx = key.indexOf(':');
        return new PermissionDto(key.substring(0, idx), key.substring(idx + 1), "");
    }

    private static String textOrNull(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        String value = node.asText();
        return value == null || value.isBlank() ? null : value;
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value.strip();
    }

    private void requireConfidentialClientCredentials(String operation) {
        if (basicAuth == null) {
            throw new IamSdkException(operation
                    + " requires iam.sdk.client-id and iam.sdk.client-secret from a WEB or M2M confidential ApplicationClient");
        }
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static String normalizeBearerToken(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new IllegalArgumentException("accessToken must not be blank");
        }
        String token = accessToken.strip();
        if (token.regionMatches(true, 0, "Bearer ", 0, 7)) {
            token = token.substring(7).strip();
        }
        if (token.isBlank()) {
            throw new IllegalArgumentException("accessToken must not be blank");
        }
        return token;
    }
}
