# Axis Vertex Spring Boot Demo

Protected API half of the Phase 1 paired quickstart. Pair this demo with `sdk-js/examples/react-demo`: the React SPA gets Axis Vertex tokens with a SPA public ApplicationClient, then this API verifies `Authorization: Bearer <access_token>`.

## Portal/Admin Setup

Create one business Application for the paired demo, then create two ApplicationClients under it:

| Runtime | Client type | Used by | Secret |
| --- | --- | --- | --- |
| React SPA | `SPA` public | `VITE_IAM_CLIENT_ID` in `sdk-js/examples/react-demo` | No |
| Spring Boot API | `WEB` or `M2M` confidential | `IAM_CLIENT_ID` / `IAM_CLIENT_SECRET` in this backend | Yes |

Use the confidential client only on the server. Do not configure this Spring Boot demo with the browser SPA public client.

This demo is a protected resource server, not a WEB browser login SDK. If you build a server-rendered WEB login flow, use the WEB client secret at token exchange and S256 PKCE for the authorization code (`code_challenge_method=S256` with a matching `code_verifier` stored server-side).

The React SPA redirect URI and allowed origin must match the Vite dev app, normally:

- Redirect URI: `http://localhost:5173/callback`
- Allowed origin: `http://localhost:5173`

App-level IdP selection is configured in IAM and selected by the `iam-server` login page/runtime. The example apps do not call legacy provider authorization routes directly.

## Run

### 1. Publish the SDK locally

From `sdk-java/`:

```powershell
cmd /c gradlew.bat publishToMavenLocal
```

This installs the local SDK artifacts used by the standalone demo.

### 2. Start local IAM

Start the Axis Vertex backend stack so `iam-server` is reachable at `http://localhost:30001`.

Smoke prerequisites used by this runbook:

- Discovery: `GET http://localhost:30001/.well-known/openid-configuration`
- JWKS: `GET http://localhost:30001/oauth2/jwks`

### 3. Configure the backend client

From `sdk-java/examples/spring-boot-demo`:

```powershell
Copy-Item .env.example .env
notepad .env
```

Set:

- `IAM_ENDPOINT` to the IAM issuer/API root, default `http://localhost:30001`.
- `IAM_CLIENT_ID` to the `WEB` or `M2M` confidential `ApplicationClient.clientId`.
- `IAM_CLIENT_SECRET` to that confidential client's one-time secret.

The `.env` file is loaded locally by Spring Boot through `spring.config.import`; real values must stay untracked.

### 4. Start the API

From `sdk-java/examples/spring-boot-demo`:

```powershell
cmd /c ..\..\gradlew.bat bootRun
```

`iam-permission-manifest.json` is the declaration source for the typed `MyAppPermissions` enum. Local generation
does not contact IAM; the runnable server keeps permission-manifest synchronization disabled.

The demo enables CORS for the paired local React dev origin. Override it if your Vite origin differs:

```powershell
$env:APP_CORS_ALLOWED_ORIGIN = "http://localhost:5173"
```

## Endpoints

`GET /public` is anonymous:

```powershell
Invoke-RestMethod http://localhost:8080/public
```

`GET /posts` requires `posts:read`:

```powershell
Invoke-WebRequest http://localhost:8080/posts
$env:TOKEN = "<valid local IAM access token with posts:read>"
Invoke-RestMethod http://localhost:8080/posts -Headers @{ Authorization = "Bearer $env:TOKEN" }
```

`POST /posts` requires `posts:write`:

```powershell
Invoke-RestMethod http://localhost:8080/posts `
  -Method POST `
  -ContentType "application/json" `
  -Headers @{ Authorization = "Bearer $env:TOKEN" } `
  -Body '{"title":"Local smoke"}'
```

Do not commit real tokens or secrets.

## Smoke

With local IAM and this API running:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\phase1-paired-example-smoke.ps1
```

The script checks:

- `GET /.well-known/openid-configuration`
- `GET /oauth2/jwks`
- `GET /public` returns 200
- `GET /posts` without a token returns 401 or 403

To verify the protected success path, provide a valid token that resolves `posts:read`:

```powershell
$env:TOKEN = "<valid local IAM access token with posts:read>"
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\phase1-paired-example-smoke.ps1
```

Override defaults if needed:

```powershell
$env:IAM_ISSUER_URI = "http://localhost:30001"
$env:API_BASE_URL = "http://localhost:8080"
```

## Live Paired E2E Harness

With local `iam-server` and `iam-portal` running, the live harness provisions a temporary Application, SPA public client, WEB confidential client, and app user, then starts both demos and records redacted evidence:

```powershell
$env:IAM_E2E_ADMIN_PASSWORD = "<local developer admin password>"
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\phase1-live-paired-example-e2e.ps1
Remove-Item Env:\IAM_E2E_ADMIN_PASSWORD
```

The script writes a redacted report under `%TEMP%\phase1-live-paired-example-e2e\<run-id>\redacted-report.json`, deletes the temporary Application by default, and never writes token or client secret values to the repo.

## How It Works

1. `@EnableIamSecurity` imports the SDK auto-configuration.
2. `NimbusJwtDecoder` reads JWKS from `{IAM_ENDPOINT}/oauth2/jwks` and verifies incoming bearer JWTs.
3. `IamJwtAuthenticationConverter` extracts identity and roles from the JWT, then calls `POST /open/v1/permissions:resolve` to fetch permissions.
4. `@RequirePerm` enforces `posts:read` on `GET /posts` and `posts:write` on `POST /posts`.
5. Permission publication is an explicit CI/deployment operation through the structured manifest client or
   `iamUploadPermissions`; the runnable server never mutates permission state at startup.

Phase 1 paired path:

```text
React SPA using @axis-iam/vertex-react
  -> Axis Vertex Authorization Code + PKCE / hosted login page
  -> PermissionGate / usePermission from GET /api/v1/auth/me/permissions
  -> Axis Vertex-issued access token
  -> Spring Boot API validates JWT via /oauth2/jwks
  -> Spring Boot resolves permissions via POST /open/v1/permissions:resolve
  -> @RequirePerm enforces posts:read/posts:write
```

The Java side is not a browser login SDK. It verifies bearer tokens, resolves permissions server-side with a confidential ApplicationClient, and protects API routes.

## Permission Constants And Optional Publication

After enabling the Gradle plugin, generate `MyAppPermissions.java` locally from the checked-in manifest:

```powershell
cmd /c ..\..\gradlew.bat iamGeneratePermissions
```

Generation needs no endpoint or credentials. `iamUploadPermissions` is the separate explicit server-only
validate/upsert path and requires an exact-scope M2M client.

## Tests

Uses `spring-security-test` to inject authenticated principals with `posts:read` and `posts:write` authorities:

```powershell
cmd /c ..\..\gradlew.bat test
```
