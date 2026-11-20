# Optional Java Web BFF

Local candidate: `com.chaosguide.iam:vertex-sdk-web:0.1.0`. This version has not been
published. Java 17 classfiles, Spring Boot 3.4.4 / Security 6.4 baseline. The optional
`spring-security-oauth2-client` dependency supplies Spring OAuth request converters
and OIDC validators; the existing Nimbus decoder verifies signatures and JWKS.

The existing core integration keeps `oauth_tokens`. To choose `server_session`, add
this optional module, declare `WebBffConfig`, one shared `WebSessionStore`, and one
`WebSessionCarrier`, import `@EnableWebBff`, and attach
`web.configure(http, protectedBusinessMatcher)` to your own `SecurityFilterChain`.
The dependency alone opens no endpoints. The SDK creates no chain and overrides no
application bean. Configure any Bearer resource server on the same chain: an
explicit Authorization header must have passed its Bearer filter and never falls
back to a Cookie identity. Select all mounted BFF paths in the application chain.

The standalone Maven app in `../examples/bff-spring` consumes coordinates without
project dependencies. The application owns business routes and permissions. The
SDK owns authentication routes, storage transitions and protocol validation.

Configuration requires issuer origin, resource audience, registered confidential
WEB client ID/secret, exact callback, canonical application origin, allowlisted
local destinations, OpenID scopes, provider and process count. Discovery endpoints
must stay on the IAM origin. HTTPS is required; explicit loopback development uses
HTTP. Forwarded headers and proxy trust are not inferred. No credentialed
cross-origin or iframe mode is enabled.

Default base `/auth` is configurable. Host routes follow
`connected-app-bff-c0/1.0.1`: bootstrap/session, Hosted login/callback, finite custom
login/authenticate/challenges/authorize/mfa/complete/cancel/magic, client-bound
auth-methods/auth-policy, registration create/get/challenges/complete/cancel,
EMAIL password recovery/reset, and logout. JSON rejects duplicate keys, trailing
content and unknown request fields. Hosted GET requires an existing bootstrap
binding. All POST actions require exact Origin and bound `X-CSRF-Token`.

Before a protected request reaches business code, the guard loads storage,
enforces deadlines, conditionally refreshes and checks IAM validity online.
`IamContext` reads request-local identity without network access. Permissions come
from IAM; metadata and decoded Access Token text are never authorization sources.
A permission denial keeps the session. Login rotates handle and CSRF. ID Token
signature/algorithm, issuer, audience/azp, time, nonce and user subject are checked.
The resource Access Token stays opaque. Missing RT is supported; expiry requires
new authorization.

Explicitly choose one `MemoryWebSessionStore` shared by the application. It is
volatile and thread safe within one JVM. More than one declared process is
rejected. Defaults are 10000 sessions, 1000 combined prelogin/registration records,
65536 bytes per bounded record, 600-second prelogin TTL, 3600-second absolute/idle
caps, 15-second operation lease and 60-second cleanup. Shorter IAM deadlines win.
Capacity never silently evicts active identities. Reads return isolated copies.
Close clears records/stops cleanup; subsequent operations fail CLOSED. Restart
requires login and implies no remote revocation. No DB, migration or RAM
encryption key is required.

An injected host provider implements linearizable `WebSessionStore` operations.
Conditional replace/rotation is never an upsert; version, immutable creation and
absolute bounds, ownership fence and terminal invalidation must hold across all
instances. Unavailable, capacity, closed and conflict failures are typed and
distinct from absent/expired records. Execute the same contract scenarios for the
claimed topology. A capability flag or process-local lock does not certify a
distributed backend. Persisted credentials need the host storage protection.
Rotation retains a credential-free consumed-handle termination link for the life
of its derived session. Reads/callbacks on the old handle remain absent; a new
bootstrap using it terminates that old local identity before starting again.
This is a fencing link, with at most one per live memory session, not token
response recovery.

`CookieWebSessionCarrier` owns one opaque Cookie: `__Host-axis-session`, Secure,
HttpOnly, SameSite=Lax, host-only, Path=/. HTTP development uses
`axis-dev-session` without Secure. Ports do not isolate Cookies.
`HttpSessionWebSessionCarrier` instead uses the configured native Session Cookie
and only `com.chaosguide.iam.vertex.web.handle.v1`. It preserves unrelated fields,
rotates native IDs when binding, and stores no credential/identity snapshot in
HttpSession. Configure native Cookie flags before affirming its configuration.
Its supported scope is one JVM with native Servlet Session. Spring Session and
distributed automatic-save providers require separate evidence. Stale handles
cannot revive removed provider records; the SDK namespace has one writer.

Refresh acquisition and SEND_INTENT precede HTTP. Token requests have zero
automatic retries. Lost sent leases, sent timeouts, failed credential commits and
lost generations require authorization again. Pre-send ownership can be released
safely. Online read failures preserve identity and return 503. Upstream calls
default to 5 seconds within a shared 10-second authentication budget, including
JWK acquisition. Responses are bounded at 256 KiB. Credential-bearing diagnostics
are redacted.

Logout invalidates locally, clears the owned Cookie and performs bounded IAM
revocation. Valid AT uses current-session logout with its owned RT when present.
Expired AT plus RT revokes the refresh family without asserting IAM session
deletion. Expired AT without RT reports NOT_ATTEMPTED. Logout never refreshes.
503 partial results explicitly report local/cookie/remote/sso outcomes. SSO
logout is never implicit. A lost response can require safe reauthorization; no
token replay or automatic response-recovery endpoint is provided.

Controlled fixtures cover Hosted, custom PASSWORD, Provider code and MFA
continuation. Actual external Provider and email/SMS delivery are separate proof.
Fragment reading/removal and magic-proof submission belong to the shared JS
package because Servlet requests never contain fragments. The BFF matches its
controlled EMAIL transaction/identifier/state/CSRF and consumes the magic action
once. The standalone sample vendors fixed core/React package archives with SHA-256
and uses prebuilt Embedded/Dialog plus Headless useAuthFlow. The browser consumer
runs the actual packages and Java JAR/POM against a controlled IAM fixture. Real IAM,
external Provider and actual delivery still need runtime-owner inputs.

Validation uses exact `WebSessionContractTest` / `WebSessionMemoryTest` selectors,
affected JWT callers and `python3 -B scripts/verify-bff-consumer.py`. The coordinated
chain uses the canonical validation-contract. The runner stages actual core/web
JARs/POMs under `build/bff-consumer`, checks metadata/Java 17 bytecode, and runs a
separate Maven application against HTTP fixtures. No mavenLocal, SDK source
substitution or backend checkout is used at runtime. Candidate hashes and results
are written to `build/bff-consumer/manifest.json`.
