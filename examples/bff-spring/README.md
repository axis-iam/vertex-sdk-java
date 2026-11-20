# Standalone Spring BFF application

This example consumes unpublished local candidate
`com.chaosguide.iam:vertex-sdk-web:0.1.0`. After staging core/web Maven publications,
build the browser from its fixed package archives, then run in this example directory:

```sh
(cd browser && npm ci && npm run build)
mvn -DcandidateRepository=file:///absolute/path/to/candidate-repository spring-boot:run
```

Supply `VERTEX_WEB_ISSUER`, `VERTEX_WEB_AUDIENCE`, `VERTEX_WEB_CLIENT_ID`,
`VERTEX_WEB_CLIENT_SECRET` and `VERTEX_WEB_ORIGIN` through the environment. Register
the exact origin plus `/auth/callback` for one WEB client with secret and S256.
The app explicitly chooses a shared in-process `MemoryWebSessionStore`; no database
or migration is needed. Single JVM only; restart requires login.

For loopback HTTP set `VERTEX_WEB_DEVELOPMENT_LOOPBACK=true`. For native Session
mode set `VERTEX_WEB_NATIVE_SESSION=true`; its Cookie uses HttpOnly, host-only,
Path=/, Secure and SameSite=Lax. Native loopback mode additionally needs
`SERVER_SERVLET_SESSION_COOKIE_SECURE=false`.

`@EnableWebBff` composes beans. The application chain mounts authentication paths
and protects `/api/*`. Hosted entry fetches bootstrap before navigation. Custom
consumers fetch bootstrap and retain csrfToken, then POST same-origin JSON with
Origin and X-CSRF-Token: `/auth/session/login {}`, finite authentication actions,
then `/auth/session/login/complete {}`. PASSWORD uses an explicit typed identifier
with method, identifier and password fields. No credential reaches the browser.

Read `/auth/session` for the safe view and `/api/documents` for the guarded business
API. `/api/admin` demonstrates permission denial while retaining the session.
POST `/auth/session/logout {}` with current CSRF to exit.

The page uses the actual fixed core/React archives in browser/vendor: Hosted navigation,
prebuilt Embedded and Dialog, and Headless through the shared useAuthFlow hook.
Forgot-password uses the shared component. No OAuth state machine is implemented by the app.
The browser receives only the public /web-config response; the WEB secret stays in Java.
The vendor SHA256SUMS.json pins the independently released local JS candidate bytes.

Controlled tests exercise signed OIDC, PASSWORD/MFA, Provider code/MFA/denial and bound email
fragment cleanup with the real browser packages, against an exclusive IAM HTTP fixture.
The browser has no OAuth token in DOM, final callback URL, JS-readable Cookie or browser storage.
Real IAM, external Provider and actual email/SMS delivery remain separate proof requiring
runtime-owner configuration and credentials. This example never starts or switches shared IAM.

The SDK runner copies this example into an isolated Maven project and resolves
the SDK only from produced JAR/POM coordinates. Fixture sources implement an
independent IAM HTTP server. `build/bff-consumer/manifest.json` binds artifacts and
results.
