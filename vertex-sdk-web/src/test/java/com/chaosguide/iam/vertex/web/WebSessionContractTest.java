package com.chaosguide.iam.vertex.web;

import com.chaosguide.iam.vertex.context.IamContext;
import com.chaosguide.iam.vertex.authz.HighRiskGuardAspect;
import com.chaosguide.iam.vertex.authz.RequireStepUp;
import com.chaosguide.iam.vertex.authz.RequireNoImpersonation;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;
import org.springframework.security.access.AccessDeniedException;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import jakarta.servlet.Filter;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.Duration;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import static org.assertj.core.api.Assertions.*;
import static com.chaosguide.iam.vertex.web.WebSessionRecord.Lifecycle.*;

class WebSessionContractTest {
    public static class Guarded {
        @RequireStepUp(acr = "urn:iam:acr:password")
        @RequireNoImpersonation
        public String password() {
            return "allowed";
        }

        @RequireStepUp(acr = "urn:iam:acr:mfa")
        public String mfa() {
            return "mfa";
        }
    }

    TestIam fixture;
    MemoryWebSessionStore store;
    WebSessionService service;
    WebIamClient client;
    WebBffConfig config;

    @BeforeEach
    void setup() throws Exception {
        fixture = new TestIam();
        store = new MemoryWebSessionStore();
        config = fixture.config();
        client = new WebIamClient(config);
        service = new WebSessionService(config, store, client);
    }

    @AfterEach
    void close() throws Exception {
        store.close();
        client.close();
        fixture.close();
        SecurityContextHolder.clearContext();
    }

    WebSessionService.Result prelogin() {
        return service.bootstrap(null);
    }

    WebSessionService.Result login() {
        var p = prelogin();
        fixture.capture(service.hosted(p.handle(), "/"));
        return service.callback(p.handle(), Map.of("code", "fixture-code", "state", fixture.state));
    }

    void expireAccess(String id, boolean noRefresh) {
        var r = store.read(id).orElseThrow();
        var d = r.data().put("accessExpiresAt", Instant.now().minusSeconds(1).toString());
        if (noRefresh) d.remove("refresh");
        assertThat(store.replace(r, r.next(READY, d, r.idleExpiresAt()))).isTrue();
    }

    @Test
    void allFrozenSafeViewVectorsExecuteAgainstPublicValidator() throws Exception {
        JsonNode vectors =
                WebWire.JSON
                        .readTree(getClass().getResourceAsStream("/connected-app-bff/c0-v1.json"))
                        .get("viewVectors");
        for (JsonNode v : vectors) {
            if (v.get("accept").booleanValue())
                assertThatCode(() -> SafeSessionView.validate(v.get("value")))
                        .as(v.path("id").asText())
                        .doesNotThrowAnyException();
            else
                assertThatThrownBy(() -> SafeSessionView.validate(v.get("value")))
                        .as(v.path("id").asText())
                        .isInstanceOf(WebSessionException.class);
        }
        assertThat(vectors.size()).isEqualTo(13);
    }

    @Test
    void publicDiagnosticsAndJsonNeverSerializeBackendCredentials() throws Exception {
        var user = login();
        assertThat(WebWire.JSON.writeValueAsString(user))
                .doesNotContain(user.handle(), "fixture-access", "fixture-refresh");
        assertThat(WebWire.JSON.writeValueAsString(config)).doesNotContain("fixture-secret");
        var credential =
                new WebIamClient.Tokens(
                        "access-sensitive",
                        "refresh-sensitive",
                        Instant.now(),
                        "subject",
                        "nonce-sensitive");
        assertThat(WebWire.JSON.copy().findAndRegisterModules().writeValueAsString(credential))
                .doesNotContain("access-sensitive", "refresh-sensitive", "nonce-sensitive");
        assertThat(credential.toString()).doesNotContain("sensitive");
    }

    @Test
    void hostedRequiresBootstrapAndCallbackBindsStateConsumesOnce() {
        assertThatThrownBy(() -> service.hosted(null, "/")).hasMessage("SESSION_REQUIRED");
        var p = prelogin();
        fixture.capture(service.hosted(p.handle(), "/app"));
        assertThatThrownBy(
                        () ->
                                service.callback(
                                        p.handle(),
                                        Map.of("code", "fixture-code", "state", "wrong")))
                .isInstanceOf(WebSessionException.class);
        assertThatThrownBy(
                        () ->
                                service.callback(
                                        p.handle(),
                                        Map.of(
                                                "code",
                                                "fixture-code",
                                                "state",
                                                fixture.state,
                                                "kind",
                                                "AUTH_CONTINUATION")))
                .isInstanceOf(WebSessionException.class);
        assertThat(fixture.exchanges).hasValue(0);
        var user =
                service.callback(
                        p.handle(), Map.of("code", "fixture-code", "state", fixture.state));
        assertThat(user.handle()).isNotEqualTo(p.handle());
        assertThat(user.view().has("profile")).isTrue();
        assertThat(user.view().path("csrfToken")).isNotEqualTo(p.view().path("csrfToken"));
        assertThat(user.view().toString())
                .doesNotContain(
                        "fixture-access", "fixture-refresh", "fixture-control", "fixture-code");
        assertThatThrownBy(
                        () ->
                                service.callback(
                                        p.handle(),
                                        Map.of("code", "fixture-code", "state", fixture.state)))
                .hasMessage("SESSION_REQUIRED");
        assertThat(fixture.exchanges).hasValue(1);
        assertThatThrownBy(() -> service.hosted(user.handle(), "/"))
                .hasMessage("SESSION_ACTION_PENDING");
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "nonce",
                "audience",
                "issuer",
                "expired",
                "permissions",
                "validity",
                "signature",
                "azp",
                "subject"
            })
    void oidcAndIdentityFailuresNeverCreateSession(String failure) {
        switch (failure) {
            case "nonce" -> fixture.wrongNonce = true;
            case "audience" -> fixture.wrongAudience = true;
            case "issuer" -> fixture.wrongIssuer = true;
            case "expired" -> fixture.expiredId = true;
            case "permissions" -> fixture.invalidPermissions = true;
            case "validity" -> fixture.invalidValidity = true;
            case "signature" -> fixture.wrongSignature = true;
            case "azp" -> fixture.wrongAzp = true;
            case "subject" -> fixture.wrongSubject = true;
        }
        var p = prelogin();
        fixture.capture(service.hosted(p.handle(), "/"));
        assertThatThrownBy(
                        () ->
                                service.callback(
                                        p.handle(),
                                        Map.of("code", "fixture-code", "state", fixture.state)))
                .isInstanceOf(WebSessionException.class);
        assertThat(store.read(p.handle())).isEmpty();
        assertThat(fixture.exchanges).hasValue(1);
    }

    @Test
    void csrfIsExactForAnonymousAndAuthenticatedAndUnknownJsonRejects() {
        var p = prelogin();
        assertThatThrownBy(
                        () ->
                                service.csrf(
                                        p.handle(),
                                        "https://other.test",
                                        p.view().path("csrfToken").asText()))
                .hasMessage("SESSION_CSRF_INVALID");
        assertThatThrownBy(() -> service.csrf(p.handle(), config.origin().toString(), "wrong"))
                .hasMessage("SESSION_CSRF_INVALID");
        assertThatCode(
                        () ->
                                service.csrf(
                                        p.handle(),
                                        config.origin().toString(),
                                        p.view().path("csrfToken").asText()))
                .doesNotThrowAnyException();
        service.custom(p.handle());
        assertThatThrownBy(
                        () ->
                                service.action(
                                        p.handle(),
                                        "authenticate",
                                        WebWire.object()
                                                .put("method", "PASSWORD")
                                                .put("password", "secret")
                                                .put("extra", true)))
                .isInstanceOf(WebSessionException.class);
    }

    @Test
    void customPasswordMfaCompletionAndProviderContinuationUseControlledTransaction() {
        fixture.mfa = true;
        var p = prelogin();
        service.custom(p.handle());
        ObjectNode credentials =
                WebWire.object().put("method", "PASSWORD").put("password", "fixture-password");
        credentials.set(
                "identifier",
                WebWire.object().put("kind", "EMAIL").put("value", "reader@example.test"));
        assertThat(
                        service.action(p.handle(), "authenticate", credentials)
                                .view()
                                .path("state")
                                .asText())
                .isEqualTo("MFA_REQUIRED");
        assertThat(
                        service.callback(
                                        p.handle(),
                                        Map.of(
                                                "kind",
                                                "AUTH_CONTINUATION",
                                                "auth_transaction_id",
                                                fixture.transaction,
                                                "state",
                                                fixture.state))
                                .view()
                                .path("state")
                                .asText())
                .isEqualTo("MFA_REQUIRED");
        assertThat(fixture.exchanges).hasValue(0);
        assertThatThrownBy(
                        () ->
                                service.callback(
                                        p.handle(),
                                        Map.of(
                                                "kind",
                                                "AUTH_CONTINUATION",
                                                "auth_transaction_id",
                                                fixture.transaction,
                                                "state",
                                                fixture.state)))
                .hasMessage("SESSION_ACTION_PENDING");
        service.action(
                p.handle(), "mfa", WebWire.object().put("method", "TOTP").put("code", "123456"));
        assertThat(service.action(p.handle(), "complete", WebWire.object()).view().has("profile"))
                .isTrue();
        assertThat(fixture.exchanges).hasValue(1);
    }

    @Test
    void providerCodeAndCancellationAndMagicBinding() {
        var p = prelogin();
        service.custom(p.handle());
        service.action(
                p.handle(),
                "authorize",
                WebWire.object().put("providerId", "019b0000-0000-7000-8000-000000000004"));
        assertThat(
                        service.callback(
                                        p.handle(),
                                        Map.of("code", "fixture-code", "state", fixture.state))
                                .view()
                                .has("profile"))
                .isTrue();
        var cancelled = prelogin();
        service.custom(cancelled.handle());
        assertThatThrownBy(
                        () ->
                                service.callback(
                                        cancelled.handle(),
                                        Map.of("error", "access_denied", "state", fixture.state)))
                .hasMessage("AUTH_ACCESS_DENIED");
        assertThat(store.read(cancelled.handle())).isEmpty();
        var magic = prelogin();
        service.custom(magic.handle());
        ObjectNode challenge = WebWire.object().put("method", "EMAIL_MAGIC_LINK");
        challenge.set(
                "identifier",
                WebWire.object().put("kind", "EMAIL").put("value", "reader@example.test"));
        service.action(magic.handle(), "challenges", challenge);
        assertThatThrownBy(
                        () ->
                                service.action(
                                        magic.handle(),
                                        "magic",
                                        WebWire.object()
                                                .put("transactionId", fixture.transaction)
                                                .put("state", "wrong")
                                                .put("proof", "one-time")))
                .isInstanceOf(WebSessionException.class);
        assertThat(
                        service.action(
                                        magic.handle(),
                                        "magic",
                                        WebWire.object()
                                                .put("transactionId", fixture.transaction)
                                                .put("state", fixture.state)
                                                .put("proof", "one-time"))
                                .view()
                                .path("nextAction")
                                .asText())
                .isEqualTo("complete");
        assertThatThrownBy(
                        () ->
                                service.action(
                                        magic.handle(),
                                        "magic",
                                        WebWire.object()
                                                .put("transactionId", fixture.transaction)
                                                .put("state", fixture.state)
                                                .put("proof", "one-time")))
                .hasMessage("SESSION_ACTION_PENDING");
    }

    @Test
    void protectedReadsAlwaysValidateAndTransientValidityDoesNotDestroyIdentity() {
        var session = login();
        int before = fixture.validity.get();
        service.session(session.handle());
        assertThat(fixture.validity).hasValue(before + 1);
        fixture.validityStatus = 503;
        int readsBeforeFailure = fixture.validity.get();
        assertThatThrownBy(() -> service.session(session.handle())).hasMessage("IAM_UNAVAILABLE");
        assertThat(fixture.validity).hasValue(readsBeforeFailure + 1);
        assertThat(store.read(session.handle())).isPresent();
        fixture.validityStatus = 401;
        assertThatThrownBy(() -> service.session(session.handle()))
                .hasMessage("SESSION_INVALIDATED");
        assertThat(store.read(session.handle())).isEmpty();
    }

    @Test
    void refreshSingleOwnerAcrossTwoServicesAndLateLogoutCannotResurrect() throws Exception {
        var session = login();
        expireAccess(session.handle(), false);
        CountDownLatch sent = new CountDownLatch(1), release = new CountDownLatch(1);
        fixture.duringRefresh =
                () -> {
                    sent.countDown();
                    try {
                        release.await(5, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                };
        var pool = Executors.newSingleThreadExecutor();
        try {
            var first = pool.submit(() -> service.session(session.handle()));
            assertThat(sent.await(5, TimeUnit.SECONDS)).isTrue();
            var second = new WebSessionService(config, store, client);
            assertThatThrownBy(() -> second.session(session.handle()))
                    .hasMessage("SESSION_ACTION_PENDING");
            assertThat(service.logout(session.handle()).result().path("remote").asText())
                    .isEqualTo("REFRESH_FAMILY_REVOKED");
            release.countDown();
            assertThatThrownBy(first::get).hasCauseInstanceOf(WebSessionException.class);
            assertThat(store.read(session.handle())).isEmpty();
            assertThat(fixture.refreshes).hasValue(1);
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void refreshRotationAndExpiredSentLeaseNeverReplay() {
        var user = login();
        expireAccess(user.handle(), false);
        service.session(user.handle());
        assertThat(fixture.refreshes).hasValue(1);
        var r = store.read(user.handle()).orElseThrow();
        var intent =
                r.next(
                        SEND_INTENT,
                        r.data().put("leaseExpiresAt", Instant.now().minusSeconds(1).toString()),
                        r.idleExpiresAt());
        store.replace(r, intent);
        assertThatThrownBy(() -> service.session(user.handle())).hasMessage("REFRESH_UNCERTAIN");
        assertThat(store.read(user.handle())).isEmpty();
        assertThat(fixture.refreshes).hasValue(1);
    }

    @Test
    void refreshErrorIsTerminalAndNoRefreshTokenExpiryRequiresAuthorization() {
        var user = login();
        expireAccess(user.handle(), false);
        fixture.refreshStatus = 503;
        assertThatThrownBy(() -> service.session(user.handle())).hasMessage("REFRESH_UNCERTAIN");
        assertThat(store.read(user.handle())).isEmpty();
        assertThat(fixture.refreshes).hasValue(1);
        fixture.issueRefresh = false;
        var noRefresh = login();
        expireAccess(noRefresh.handle(), true);
        assertThatThrownBy(() -> service.session(noRefresh.handle()))
                .hasMessage("SESSION_INVALIDATED");
        assertThat(fixture.refreshes).hasValue(1);
    }

    @Test
    void logoutCredentialMatrixNeverRefreshesAndPartialFailureIsExplicit() {
        var a = login();
        assertThat(service.logout(a.handle()).result().path("remote").asText())
                .isEqualTo("SESSION_REVOKED");
        fixture.issueRefresh = false;
        var b = login();
        assertThat(service.logout(b.handle()).result().path("remote").asText())
                .isEqualTo("SESSION_REVOKED");
        var c = login();
        expireAccess(c.handle(), true);
        assertThat(service.logout(c.handle()).result().path("remote").asText())
                .isEqualTo("NOT_ATTEMPTED");
        fixture.issueRefresh = true;
        var d = login();
        expireAccess(d.handle(), false);
        assertThat(service.logout(d.handle()).result().path("remote").asText())
                .isEqualTo("REFRESH_FAMILY_REVOKED");
        assertThat(fixture.refreshes).hasValue(0);
        assertThat(fixture.logouts).hasValue(2);
        assertThat(fixture.revokes).hasValue(1);
    }

    @Test
    void springFilterMapsContextDoesNotFallBackFromBearerAndCleansContext() throws Exception {
        var user = login();
        WebBff bff = new WebBff(config, service, new CookieWebSessionCarrier(config));
        Filter filter = bff.filter(r -> r.getRequestURI().startsWith("/api/"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/documents");
        request.setCookies(new Cookie("axis-dev-session", user.handle()));
        AtomicInteger calls = new AtomicInteger();
        int before = fixture.validity.get();
        filter.doFilter(
                request,
                new MockHttpServletResponse(),
                (req, res) -> {
                    calls.incrementAndGet();
                    assertThat(IamContext.current().hasPermission("documents", "read")).isTrue();
                    assertThat(IamContext.current().hasPermission("documents", "delete")).isFalse();
                    assertThat(IamContext.currentUser().subject())
                            .isEqualTo(user.view().path("profile").path("id").asText());
                    assertThat(IamContext.currentAccessToken()).isEmpty();
                    IamContext.current();
                    AspectJProxyFactory factory = new AspectJProxyFactory(new Guarded());
                    factory.addAspect(new HighRiskGuardAspect());
                    Guarded guarded = factory.getProxy();
                    assertThat(guarded.password()).isEqualTo("allowed");
                    assertThatThrownBy(guarded::mfa).isInstanceOf(AccessDeniedException.class);
                });
        assertThat(fixture.validity).hasValue(before + 1);
        assertThat(IamContext.currentOptional()).isEmpty();
        assertThat(calls).hasValue(1);
        request = new MockHttpServletRequest("GET", "/api/documents");
        request.setCookies(new Cookie("axis-dev-session", user.handle()));
        request.addHeader("Authorization", "Bearer invalid");
        MockHttpServletResponse denied = new MockHttpServletResponse();
        filter.doFilter(request, denied, (a, b) -> calls.incrementAndGet());
        assertThat(denied.getStatus()).isEqualTo(401);
        assertThat(calls).hasValue(1);
    }

    @Test
    void httpRoutesHandleBootstrapCookieCsrfDuplicateCallbackAndNoTokenEndpoint() throws Exception {
        Filter filter =
                new WebBff(config, service, new CookieWebSessionCarrier(config)).filter(r -> false);
        var missing = new MockHttpServletResponse();
        filter.doFilter(
                new MockHttpServletRequest("GET", "/auth/login"),
                missing,
                (a, b) -> fail("unexpected"));
        assertThat(missing.getStatus()).isEqualTo(401);
        var bootstrap = new MockHttpServletResponse();
        filter.doFilter(
                new MockHttpServletRequest("GET", "/auth/session/bootstrap"),
                bootstrap,
                (a, b) -> fail("unexpected"));
        assertThat(bootstrap.getHeader("Set-Cookie"))
                .contains("HttpOnly", "SameSite=Lax", "Path=/");
        assertThat(bootstrap.getHeader("Cache-Control")).isEqualTo("no-store");
        var p = prelogin();
        fixture.capture(service.hosted(p.handle(), "/"));
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/auth/callback");
        req.setCookies(new Cookie("axis-dev-session", p.handle()));
        req.addParameter("code", "fixture-code");
        req.addParameter("state", fixture.state, "duplicate");
        var response = new MockHttpServletResponse();
        filter.doFilter(req, response, (a, b) -> fail("unexpected"));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(fixture.exchanges).hasValue(0);
        req = new MockHttpServletRequest("POST", "/auth/session/login");
        req.setCookies(new Cookie("axis-dev-session", p.handle()));
        req.setContentType("application/json");
        req.setContent("{}".getBytes(StandardCharsets.UTF_8));
        response = new MockHttpServletResponse();
        filter.doFilter(req, response, (a, b) -> fail("unexpected"));
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void nativeSessionLateAttributeSaveCannotRestoreLogoutOrReplaceNewIdentity() throws Exception {
        HttpSessionWebSessionCarrier carrier =
                new HttpSessionWebSessionCarrier(config, "JSESSIONID", true);
        MockHttpSession host = new MockHttpSession();
        host.setAttribute("unrelated", "kept");
        var a = login();
        host.setAttribute(HttpSessionWebSessionCarrier.ATTRIBUTE, a.handle());
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setSession(host);
        String stale = carrier.read(req);
        service.logout(stale);
        carrier.clear(req, new MockHttpServletResponse(), stale);
        host.setAttribute(
                HttpSessionWebSessionCarrier.ATTRIBUTE, stale); // framework late save of old handle
        assertThatThrownBy(() -> service.session(carrier.read(req))).hasMessage("SESSION_REQUIRED");
        fixture.userId = "019b0000-0000-7000-8000-000000000005";
        var b = login();
        host.setAttribute(HttpSessionWebSessionCarrier.ATTRIBUTE, b.handle());
        assertThatThrownBy(
                        () -> carrier.bind(req, new MockHttpServletResponse(), stale, a.handle()))
                .hasMessage("SESSION_ACTION_PENDING");
        assertThat(carrier.read(req)).isEqualTo(b.handle());
        assertThat(host.getAttribute("unrelated")).isEqualTo("kept");
        assertThat(service.session(carrier.read(req)).view().path("profile").path("id").asText())
                .isEqualTo(fixture.userId);
        assertThatThrownBy(() -> new HttpSessionWebSessionCarrier(config, "JSESSIONID", false))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void registrationAndRecoveryArePurposeBoundSafeAndSeparateFromLogin() {
        var p = prelogin();
        ObjectNode body = WebWire.object().put("password", "fixture-password");
        body.set(
                "identifier",
                WebWire.object().put("kind", "EMAIL").put("value", "reader@example.test"));
        ObjectNode r = service.registration(p.handle(), null, "create", body);
        assertThat(r.toString()).doesNotContain("controlSecret", "signup-control");
        String ref = r.path("registrationId").asText();
        assertThat(ref).hasSize(43);
        assertThat(
                        service.registration(
                                        p.handle(),
                                        ref,
                                        "complete",
                                        WebWire.object().put("code", "123456"))
                                .path("status")
                                .asText())
                .isEqualTo("COMPLETED");
        var other = prelogin();
        assertThatThrownBy(() -> service.registration(other.handle(), ref, "get", WebWire.object()))
                .hasMessage("SESSION_REQUIRED");
        service.passwordReset("request", WebWire.object().put("email", "reader@example.test"));
        service.passwordReset(
                "complete",
                WebWire.object()
                        .put("token", "reset-proof")
                        .put("newPassword", "new-fixture-password"));
        assertThat(service.session(p.handle()).view().path("state").asText()).isEqualTo("PRELOGIN");
    }

    @Test
    void explicitEnableDoesNotSupplyMissingStorageOrSecurityChain() {
        new WebApplicationContextRunner()
                .withUserConfiguration(WebBffSpringConfiguration.class)
                .withBean(WebBffConfig.class, () -> config)
                .withBean(WebIamClient.class, () -> client)
                .run(context -> assertThat(context).hasFailed());
        assertThatThrownBy(() -> new WebSessionService(config, null, client))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void beforeSendProviderFailureReleasesOwnershipAndNeverSendsRefresh() {
        var user = login();
        expireAccess(user.handle(), false);
        FaultWebSessionStore fault = new FaultWebSessionStore(store);
        fault.failIntent = true;
        var guarded = new WebSessionService(config, fault, client);
        assertThatThrownBy(() -> guarded.session(user.handle()))
                .hasMessage("SESSION_STORE_UNAVAILABLE");
        assertThat(fixture.refreshes).hasValue(0);
        assertThat(store.read(user.handle()).orElseThrow().lifecycle()).isEqualTo(READY);
        assertThat(guarded.session(user.handle()).view().has("profile")).isTrue();
        assertThat(fixture.refreshes).hasValue(1);
    }

    @Test
    void failedRotatedTokenCommitLeavesSentFenceEvenWhenInvalidateIsUnavailable() {
        var user = login();
        expireAccess(user.handle(), false);
        FaultWebSessionStore fault = new FaultWebSessionStore(store);
        fault.failCommit = true;
        fault.failInvalidate = true;
        var guarded = new WebSessionService(config, fault, client);
        assertThatThrownBy(() -> guarded.session(user.handle())).hasMessage("REFRESH_UNCERTAIN");
        assertThat(store.read(user.handle()).orElseThrow().lifecycle()).isEqualTo(SEND_INTENT);
        assertThatThrownBy(() -> guarded.session(user.handle()))
                .hasMessage("SESSION_ACTION_PENDING");
        fault.failInvalidate = false;
        var future = Clock.offset(Clock.systemUTC(), Duration.ofSeconds(16));
        assertThatThrownBy(
                        () ->
                                new WebSessionService(config, fault, client, future)
                                        .session(user.handle()))
                .hasMessage("REFRESH_UNCERTAIN");
        assertThat(store.read(user.handle())).isEmpty();
        assertThat(fixture.refreshes).hasValue(1);
    }

    @Test
    void sentDisconnectIsNotRetriedAndInvalidGrantIsDeterminateInvalidation() {
        var first = login();
        expireAccess(first.handle(), false);
        fixture.refreshDisconnect = true;
        assertThatThrownBy(() -> service.session(first.handle())).hasMessage("REFRESH_UNCERTAIN");
        assertThat(fixture.refreshes).hasValue(1);
        assertThat(store.read(first.handle())).isEmpty();
        fixture.refreshDisconnect = false;
        var second = login();
        expireAccess(second.handle(), false);
        fixture.refreshStatus = 400;
        assertThatThrownBy(() -> service.session(second.handle()))
                .hasMessage("SESSION_INVALIDATED");
        assertThat(fixture.refreshes).hasValue(2);
    }

    @Test
    void failedProviderReadIs503AndLogoutFailuresReportLocalAndRemoteSeparately() throws Exception {
        var user = login();
        FaultWebSessionStore fault = new FaultWebSessionStore(store);
        var guarded = new WebSessionService(config, fault, client);
        fault.failRead = true;
        assertThatThrownBy(() -> guarded.bootstrap(user.handle()))
                .hasMessage("SESSION_STORE_UNAVAILABLE");
        fault.failRead = false;
        fault.failInvalidate = true;
        var logout = guarded.logout(user.handle());
        assertThat(logout.status()).isEqualTo(503);
        assertThat(logout.result().path("local").asText()).isEqualTo("UNCONFIRMED");
        assertThat(logout.result().path("remote").asText()).isEqualTo("SESSION_REVOKED");
        assertThat(fixture.logouts).hasValue(1);
        fault.failInvalidate = false;
        service.logout(user.handle());
        var second = login();
        fixture.logoutStatus = 503;
        logout = service.logout(second.handle());
        assertThat(logout.status()).isEqualTo(503);
        assertThat(logout.result().path("local").asText()).isEqualTo("INVALIDATED");
        assertThat(logout.result().path("remote").asText()).isEqualTo("UNCONFIRMED");
        fault.failRead = true;
        Filter filter =
                new WebBff(config, guarded, new CookieWebSessionCarrier(config)).filter(r -> false);
        var req = new MockHttpServletRequest("POST", "/auth/session/logout");
        req.setCookies(new Cookie("axis-dev-session", second.handle()));
        req.addHeader("Origin", config.origin().toString());
        req.addHeader("X-CSRF-Token", "c".repeat(43));
        var response = new MockHttpServletResponse();
        filter.doFilter(req, response, (a, b) -> fail("unexpected"));
        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getHeader("Set-Cookie")).contains("Max-Age=0");
        assertThat(
                        WebWire.JSON
                                .readTree(response.getContentAsByteArray())
                                .path("details")
                                .path("local")
                                .asText())
                .isEqualTo("UNCONFIRMED");
    }

    @Test
    void failedHostSessionCommitInvalidatesNewCredentials() throws Exception {
        var pre = prelogin();
        fixture.capture(service.hosted(pre.handle(), "/"));
        WebSessionCarrier broken =
                new WebSessionCarrier() {
                    @Override
                    public String read(HttpServletRequest request) {
                        return pre.handle();
                    }

                    @Override
                    public void bind(
                            HttpServletRequest request,
                            HttpServletResponse response,
                            String old,
                            String next) {
                        throw new WebSessionException(503, "SESSION_STORE_UNAVAILABLE");
                    }

                    @Override
                    public void clear(
                            HttpServletRequest request, HttpServletResponse response, String old) {}
                };
        Filter filter = new WebBff(config, service, broken).filter(r -> false);
        var req = new MockHttpServletRequest("GET", "/auth/callback");
        req.addParameter("code", "fixture-code");
        req.addParameter("state", fixture.state);
        var response = new MockHttpServletResponse();
        filter.doFilter(req, response, (a, b) -> fail("unexpected"));
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString()).contains("AUTH_EXCHANGE_UNCERTAIN");
        assertThat(fixture.logouts).hasValue(1);
        assertThat(store.read(pre.handle())).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"fractional", "zero", "wrong-type", "html"})
    void strictOAuthSuccessShapeNeverBuildsAHostSession(String mode) {
        fixture.tokenShape = mode;
        var p = prelogin();
        fixture.capture(service.hosted(p.handle(), "/"));
        assertThatThrownBy(
                        () ->
                                service.callback(
                                        p.handle(),
                                        Map.of("code", "fixture-code", "state", fixture.state)))
                .isInstanceOf(WebSessionException.class);
        assertThat(store.read(p.handle())).isEmpty();
        assertThat(fixture.exchanges).hasValue(1);
    }

    @Test
    void shortenedIamAbsoluteDeadlineCannotBeExtendedByLaterValidity() {
        var user = login();
        fixture.absoluteSeconds = 120;
        fixture.idleSeconds = 100;
        service.session(user.handle());
        Instant clamped =
                Instant.parse(
                        store.read(user.handle())
                                .orElseThrow()
                                .data()
                                .path("iamAbsoluteDeadline")
                                .asText());
        fixture.absoluteSeconds = 1800;
        fixture.idleSeconds = 900;
        service.session(user.handle());
        var r = store.read(user.handle()).orElseThrow();
        assertThat(r.idleExpiresAt()).isBeforeOrEqualTo(clamped);
        assertThat(Instant.parse(r.data().path("iamAbsoluteDeadline").asText())).isEqualTo(clamped);
    }

    @Test
    void sameLogicalActionReusesIdempotencyKeyAndDifferentBodyGetsNewKey() {
        var p = prelogin();
        service.custom(p.handle());
        ObjectNode mfa = WebWire.object().put("method", "TOTP").put("code", "123456");
        service.action(p.handle(), "mfa", mfa);
        String key = fixture.lastActionKey;
        ObjectNode reordered = WebWire.object().put("code", "123456").put("method", "TOTP");
        service.action(p.handle(), "mfa", reordered);
        assertThat(fixture.lastActionKey).isEqualTo(key);
        service.action(p.handle(), "mfa", mfa.put("code", "654321"));
        assertThat(fixture.lastActionKey).isNotEqualTo(key);
    }

    @Test
    void capabilitiesProjectFrozenPublicFieldsAndRejectMissingConcreteCapabilities()
            throws Exception {
        ObjectNode methods = service.capabilities("auth-methods"),
                policy = service.capabilities("auth-policy");
        assertThat(methods.path("clientId").asText()).isEqualTo("web");
        assertThat(methods.has("identifierMethods")).isTrue();
        assertThat(policy.has("identifierRestrictions")).isTrue();
        assertThat(methods.has("secretExtra")).isFalse();
        assertThat(policy.has("secretExtra")).isFalse();
        ((ObjectNode) methods.path("resend")).put("secretExtra", "hidden");
        assertThat(
                        CapabilityView.project("auth-methods", methods, "web")
                                .path("resend")
                                .has("secretExtra"))
                .isFalse();
        methods.remove("identifierMethods");
        assertThatThrownBy(() -> CapabilityView.project("auth-methods", methods, "web"))
                .hasMessage("IAM_PROTOCOL_ERROR");
    }

    @Test
    void upstreamBodyConsumptionSharesTheFiniteAuthenticationBudget() {
        fixture.server.setDispatcher(
                new Dispatcher() {
                    @Override
                    public MockResponse dispatch(RecordedRequest request) {
                        return TestIam.json(200, "{\"fixture\":true}")
                                .setBodyDelay(1, TimeUnit.SECONDS);
                    }
                });
        assertThatThrownBy(
                        () ->
                                client.request(
                                        "GET",
                                        "/bounded-read",
                                        null,
                                        Map.of(),
                                        new WebIamClient.Budget(Duration.ofMillis(50))))
                .hasMessage("IAM_UNAVAILABLE");
    }

    @Test
    void lostCallbackCookieRebootstrapTerminatesDerivedIdentityBeforeAnotherUser() {
        var pre = prelogin();
        fixture.capture(service.hosted(pre.handle(), "/"));
        var first =
                service.callback(
                        pre.handle(), Map.of("code", "fixture-code", "state", fixture.state));
        var snapshot = store.read(first.handle()).orElseThrow();
        var replacement = service.bootstrap(pre.handle());
        assertThat(store.read(first.handle())).isEmpty();
        assertThatThrownBy(() -> service.session(first.handle())).hasMessage("SESSION_REQUIRED");
        fixture.userId = "019b0000-0000-7000-8000-000000000005";
        fixture.capture(service.hosted(replacement.handle(), "/"));
        var second =
                service.callback(
                        replacement.handle(),
                        Map.of("code", "fixture-code", "state", fixture.state));
        assertThat(
                        store.replace(
                                snapshot,
                                snapshot.next(READY, snapshot.data(), snapshot.idleExpiresAt())))
                .isFalse();
        assertThat(service.session(second.handle()).view().path("profile").path("id").asText())
                .isEqualTo(fixture.userId);
        assertThatThrownBy(
                        () ->
                                service.callback(
                                        pre.handle(),
                                        Map.of("code", "fixture-code", "state", fixture.state)))
                .hasMessage("SESSION_REQUIRED");
        assertThat(fixture.exchanges).hasValue(2);
    }
}
