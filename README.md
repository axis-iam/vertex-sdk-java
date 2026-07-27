# Axis Vertex Java SDK

Spring Boot integration for Axis Vertex. The SDK verifies Axis Vertex-issued JWTs, resolves role-based permissions at runtime, and exposes type-safe permission checks through Spring Security.

## Permission manifest synchronization

Permission publication is explicit and server-only. Use `PermissionManifestClient` or the Gradle
`iamUploadPermissions` task for structured validate/upsert. Runtime Spring auto-configuration never
publishes permissions on application startup. Local code generation is manifest-first and performs no network call.

## Application Client Contract

Create one business Application for your product, then create the ApplicationClients it needs:

- Browser/native frontends use `SPA`/`NATIVE` public clients. They have no secret and must not be used by this Java server SDK.
- Spring Boot resource servers use a confidential server client. Explicit manifest CI/deployment commands use an M2M client whose persisted allowlist contains `permissions:sync` and request only that exact scope.
- If a Java WEB application implements interactive browser login itself, its authorization-code flow must use both the WEB client secret and S256 PKCE (`code_challenge_method=S256` plus matching `code_verifier`). This Java SDK does not implement a browser login/callback helper; it verifies bearer tokens, resolves permissions, and performs server-side IAM calls.
- `iam.sdk.client-id` is `ApplicationClient.clientId`.
- `iam.sdk.client-secret` is the secret for that WEB/M2M confidential ApplicationClient.
- `applicationId` is derived server-side from verified IAM tokens, for example token `app_id`, and is not a public signup/SMS/passwordless configuration value. Public end-user auth context uses OAuth `client_id`.

## Quick Start

### 1. Add dependency

```kotlin
implementation("com.chaosguide.iam:vertex-sdk-core:0.1.0")
```

For tests:

```kotlin
testImplementation("com.chaosguide.iam:vertex-sdk-test:0.1.0")
```

### 2. Configure

```yaml
iam:
  sdk:
    endpoint: https://iam.example.com
    client-id: iam_web_or_m2m_client_id
    client-secret: ${IAM_CLIENT_SECRET}
    permission-cache-ttl: PT5M
    user-profile-cache-ttl: PT1M
```

`iam.sdk.endpoint` controls the network-backed auto-configuration. If it is absent, adding the SDK dependency does not create `IamClient`, `JwtDecoder`, or permission resolver beans.

The SDK derives:

- issuer: `https://iam.example.com`
- JWKS: `https://iam.example.com/oauth2/jwks`
- runtime permission resolve: `POST https://iam.example.com/open/v1/permissions:resolve`

Use Axis Vertex access tokens issued to your React SPA or other connected application. Do not configure this backend with the SPA public client; the Spring Boot API uses its own `WEB` or `M2M` confidential ApplicationClient under the same business Application.

### 3. Enable and use

```java
@SpringBootApplication
@EnableIamSecurity
public class MyApplication {

}
```

```java
public enum MyAppPermissions implements PermissionDefinition {
    ORDERS_READ("orders", "read"),
    ORDERS_CREATE("orders", "create");

    private final PermissionKey key;

    MyAppPermissions(String resource, String action) {
        this.key = new PermissionKey(resource, action);
    }

    @Override
    public PermissionKey key() {
        return key;
    }
}
```

```java
@RestController
class OrderController {

    @RequirePerm(value = MyAppPermissions.class, name = "ORDERS_READ")
    @GetMapping("/orders")
    List<Order> list() {
        return orderService.findAll();
    }

    @GetMapping("/me")
    Map<String, Object> me(@CurrentIamUser IamCurrentUser user) {
        return Map.of("userId", user.subject(), "permissions", user.permissions());
    }
}
```

High-risk routes can require MFA step-up and reject admin impersonation tokens:

```java
@RestController
class BillingController {

    @RequireStepUp(acr = "urn:iam:acr:mfa")
    @RequireNoImpersonation
    @PostMapping("/billing/payouts")
    Payout approvePayout(@RequestBody PayoutRequest request) {
        return billingService.approve(request);
    }
}
```

Minimal production integration:

1. React SPA uses `@axis-iam/vertex-react` with the SPA public `clientId`, Authorization Code + PKCE, and no secret.
2. Axis Vertex serves the hosted login page and issues Axis Vertex tokens.
3. React `PermissionGate` / `usePermission` work from resolved permissions.
4. The SPA calls this Spring Boot API with `Authorization: Bearer <access_token>`.
5. Spring Security validates the JWT through `/oauth2/jwks`, resolves permissions through IAM, and `@RequirePerm` enforces `orders:read`.

See the runnable paired Spring Boot runbook in [`examples/spring-boot-demo/`](./examples/spring-boot-demo/).

## Runtime Contract

JWT access tokens carry identity and roles, not final permissions. `IamJwtAuthenticationConverter` reads `roles` plus `aud`/`app_id`, calls `POST /open/v1/permissions:resolve` for the configured ApplicationClient, caches the resolved permission set locally, and adds each permission as a Spring Security authority.

Permission publication is explicit and server-only. CI/deployment uses the structured manifest client or Gradle upload
task with an exact `permissions:sync` token; runtime startup never mutates permission state.

The Gradle `iamGeneratePermissions` task reads only `iam-permission-manifest.json`, validates it with the same
NFC/key rules, and generates the typed enum locally with zero network access. It never scans classes, JARs,
packages, annotations, or source. `iamUploadPermissions` is the separate server-only validate/upsert path.
Configure the local output plus separate issuer/Portal publication inputs:

```kotlin
iam {
    endpoint.set("https://iam.example.com")
    portalApiEndpoint.set("https://portal.example.com")
    clientId.set(providers.environmentVariable("IAM_M2M_CLIENT_ID"))
    clientSecret.set(providers.environmentVariable("IAM_M2M_CLIENT_SECRET"))
    manifestFile.set(layout.projectDirectory.file("iam-permission-manifest.json"))
    packageName.set("com.example.security")
    className.set("MyAppPermissions")
    idempotencyKey.set(providers.environmentVariable("IAM_IDEMPOTENCY_KEY"))
}
```

Run `./gradlew iamGeneratePermissions` during the local build, then use the generated enum in `@RequirePerm`.
The input file contains exactly `manifestId`, `revision`, and structured `permissions` declarations.
`iamUploadPermissions` uses the V2 client, JCS/NFC preflight, exact-scope token, shared retry budget, and strict
response parser. Remote snapshot-to-source generation is not exposed; generation is manifest-first.

## Portal Open API M2M Client

Portal Open API management calls use a separate server-side client. Use `PortalOpenApiClient` only from a backend service, CLI, or background job that can keep an `M2M` confidential ApplicationClient secret private. Do not use this API from browser, mobile, SPA, or React code.

```java
import com.chaosguide.iam.vertex.portal.PortalOpenApiClient;
import com.chaosguide.iam.vertex.portal.PortalOpenApiClientConfig;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;

PortalOpenApiClient portal = new PortalOpenApiClient(
        PortalOpenApiClientConfig.builder()
                .issuer("https://iam.example.com")          // iam-server for /oauth2/token
                .portalEndpoint("https://portal.example.com") // iam-portal for /open/v1/**
                .clientId(System.getenv("IAM_M2M_CLIENT_ID"))
                .clientSecret(System.getenv("IAM_M2M_CLIENT_SECRET"))
                .build());

JsonNode apps = portal.get("/open/v1/apps", JsonNode.class);
JsonNode created = portal.post("/open/v1/apps", Map.of("name", "Demo"), JsonNode.class);
```

`PortalOpenApiClient` requests OAuth2 `client_credentials` tokens from `{issuer}/oauth2/token` using HTTP Basic auth and an explicit scope:

- `portal:openapi:read` for `GET`
- `portal:openapi:write` for `POST`, `PUT`, `PATCH`, and `DELETE`

Read and write machine tokens are cached separately using `expires_in` minus a 30 second skew by default. A read token is never used for writes, and no-scope token requests are rejected locally. Portal resource requests are restricted to `/open/v1/**` and send only `Authorization: Bearer <machine_token>` for auth. They do not send Basic auth, `X-IAM-Client-Id`, `X-Application-Id`, or `X-App-Key`.

### Server Registration Grant Management

Registration Grant helpers are server-only and require the exact `registration_grants:read`, `registration_grants:write`, and `registration_grants:redemptions:read` M2M scopes.

```java
CreatedRegistrationGrant created = portal.createRegistrationGrant(new CreateRegistrationGrantRequest(
        CreateRegistrationGrantType.ACCESS_CODE, null, null, "example.test", null, null));
if (created.registrationAccessCode() == null) throw new IllegalStateException("missing one-time proof");
// Consume immediately. Never log, cache, or persist the proof.
```

## Current User And Profile

Use request-local context for audit actor fields and authorization-adjacent decisions. This path does not call IAM:

```java
@GetMapping("/audit-preview")
Map<String, Object> preview(@CurrentIamUser IamCurrentUser user) {
    return Map.of(
            "actorUserId", user.subject(),
            "appId", user.applicationId(),
            "sessionId", user.sessionId(),
            "permissions", user.permissions());
}
```

For fresher display/profile data, call IAM explicitly:

```java
UserProfileResponse profile = userProfileService.getCurrentProfile();
UserProfileResponse fresh = userProfileService.getCurrentProfile(CachePolicy.BYPASS);
```

`IamUserProfileService` calls `GET /api/v1/auth/me/profile` with the current bearer token and uses a short local cache. Do not use cached profile data as the authorization source.

Account-center and Organization onboarding helpers use the current user's bearer token, never the SDK client secret:

```java
String accessToken = IamContext.currentAccessToken().orElseThrow();

UserProfileResponse profile = iamClient.getAccountProfile(accessToken);
AccountSecuritySummaryResponse security = iamClient.getAccountSecuritySummary(accessToken);
iamClient.changePassword(accessToken, new PasswordChangeRequest("old", "new"));
List<SessionView> sessions = iamClient.listAccountSessions(accessToken);
iamClient.revokeOtherAccountSessions(accessToken);
List<AccountOrganizationResponse> organizations = iamClient.listAccountOrganizations(accessToken);
OrganizationSwitchResponse switched = iamClient.switchAccountOrganization(accessToken, "org_123");
AccountPermissionSummaryResponse permissions =
        iamClient.getAccountPermissionSummary(accessToken, "org_123");
PermissionCheckResponse allowed =
        iamClient.checkAccountPermission(accessToken, new PermissionCheckRequest("orders:read", "org_123"));
```

Organization switch returns a refresh/reauth continuation such as `REFRESH_OR_REAUTHENTICATE_WITH_ORGANIZATION`; the SDK does not mutate JWT `org_id` claims locally.

Email verification send/verify and password forgot/reset helpers are public connected-app helpers. They use the configured ApplicationClient `clientId` and do not send the SDK client secret. Current-user permission summary/check calls use `/api/v1/auth/me/permissions*`; wildcard behavior is owned by IAM.

Public Organization invitation preview is unauthenticated. Accept can be called without a bearer token and may return `LOGIN_REQUIRED` / `LOGIN_OR_REGISTER_THEN_RETRY_ACCEPT`:

```java
PublicOrganizationInvitationPreviewResponse preview =
        iamClient.previewOrganizationInvitation(invitationTokenFromUrl);
PublicOrganizationInvitationAcceptResponse accepted =
        iamClient.acceptOrganizationInvitation(invitationTokenFromUrl, accessTokenOrNull);
```

Do not persist raw invitation tokens in durable state. Keep them URL/request scoped.

`UserProfileResponse.metadata()` is legacy profile metadata when returned by IAM. It is not App User authorization attributes. App User authorization attributes are app-scoped management-plane fields shown/edited in Portal/Admin App User detail and may be used by IAM policy, ABAC, or token-claim generation. This Java SDK does not add a Portal/Admin App User management client in this scope, and runtime authorization checks continue to use JWT identity plus resolved permissions, never profile metadata or a cached profile.

## Signup Boundary

The Java SDK does not expose an end-user signup client. Customer applications that provide their own registration UI should call IAM server `POST /api/v1/auth/signup` with JSON body fields such as `email`, `password`, and `client_id`, where `client_id` is the public `ApplicationClient.clientId` for that registration surface. Do not send or expose internal application identifiers to end users.

Do not use the IAM Developer Portal registration endpoint from SDK code. `POST /portal/v1/auth/register` is only for IAM's own Developer Portal onboarding and creates platform developer/workspace state, not generic customer application users.

## Configuration Reference

| Property | Default | Description |
| --- | --- | --- |
| `iam.sdk.endpoint` | none | IAM server base URL. Enables network-backed SDK beans. |
| `iam.sdk.client-id` | none | `ApplicationClient.clientId` for a WEB/M2M confidential client used by this backend. |
| `iam.sdk.client-secret` | none | Secret for the confidential server client; never sent to Portal. |
| `iam.sdk.permission-cache-ttl` | `PT5M` | Local role-set permission cache TTL. |
| `iam.sdk.permission-cache-max-size` | `10000` | Max Caffeine cache entries. |
| `iam.sdk.user-profile-cache-enabled` | `true` | Enables cache for explicit current-user profile lookups. |
| `iam.sdk.user-profile-cache-ttl` | `PT1M` | Local `/api/v1/auth/me` profile cache TTL. |
| `iam.sdk.user-profile-cache-max-size` | `10000` | Max profile cache entries. |
| `iam.sdk.fail-mode` | `CLOSE` | On resolve failure, `CLOSE` fails the request; `OPEN` returns no permissions. |
| `iam.sdk.http-timeout` | `PT10S` | IAM HTTP connect/read/write timeout. |

## Tests

## Server Authorization Management

`PortalOpenApiClient` exposes typed Role, Permission, role-permission, and user-role helpers for confidential M2M applications. Read credentials from external configuration, grant only the corresponding exact `roles:*`, `permissions:*`, `role_permissions:*`, or `user_roles:*` scopes, retain returned quoted ETags, and pass them to update/delete/replace calls.

```java
OpenRole role = client.createRole(new CreateOpenRoleRequest("support", "Support", null), requestId);
role = client.updateRole(role.id(), new UpdateOpenRoleRequest(null, "Support agents", null), role.etag());
```

`vertex-sdk-test` provides:

- `@IamTestSecurity` to inject a test `SecurityContext` with roles and permissions.
- `MockPermissionResolver` for unit tests.
- `IamMockWebServer` for integration tests that need JWKS, token issuing, permission resolve, list, and upsert endpoints.

## Publishing

```bash
./gradlew publishToMavenLocal
```

Published modules:

- `com.chaosguide.iam:vertex-sdk-core`
- `com.chaosguide.iam:vertex-gradle-plugin`
- `com.chaosguide.iam:vertex-sdk-test`

Maven Central and GitHub Packages repository blocks are prepared in `buildSrc/src/main/kotlin/iam-publish.gradle.kts`, but credentials must be supplied outside the repository.
