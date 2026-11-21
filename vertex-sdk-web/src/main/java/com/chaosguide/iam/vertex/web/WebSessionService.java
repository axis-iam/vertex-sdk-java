package com.chaosguide.iam.vertex.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import static com.chaosguide.iam.vertex.web.WebSessionRecord.Kind.*;
import static com.chaosguide.iam.vertex.web.WebSessionRecord.Lifecycle.*;

/** Protocol/lifecycle orchestration, independent of Servlet sessions and business routes. */
public final class WebSessionService {
    public record Result(@JsonIgnore String handle, ObjectNode view) {
        public Result {
            view = view.deepCopy();
        }

        @Override
        public ObjectNode view() {
            return view.deepCopy();
        }

        @Override
        public String toString() {
            return "Result[redacted handle, safe view]";
        }
    }

    public record Logout(int status, ObjectNode result) {}

    private static final SecureRandom RANDOM = new SecureRandom();
    private final WebBffConfig config;
    private final WebSessionStore store;
    private final WebIamClient iam;
    private final Clock clock;

    public WebSessionService(WebBffConfig config, WebSessionStore store, WebIamClient iam) {
        this(config, store, iam, Clock.systemUTC());
    }

    public WebSessionService(
            WebBffConfig config, WebSessionStore store, WebIamClient iam, Clock clock) {
        this.config = config;
        this.store = Objects.requireNonNull(store, "Explicit session provider required");
        this.iam = iam;
        this.clock = clock;
        store.validateTopology(config.declaredProcesses());
    }

    public static String random() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private WebIamClient.Budget budget() {
        return new WebIamClient.Budget(config.authBudget());
    }

    private Optional<WebSessionRecord> optional(String id) {
        if (id == null) return Optional.empty();
        if (!id.matches("[A-Za-z0-9_-]{43}")) throw WebSessionException.absent();
        Optional<WebSessionRecord> result = store.read(id);
        if (result.isPresent()) {
            ObjectNode data = result.get().data();
            if (!config.clientId().equals(data.path("clientId").asText())
                    || !config.issuer().toString().equals(data.path("issuer").asText())
                    || !config.resourceAudience().equals(data.path("resourceAudience").asText()))
                throw new WebSessionException(401, "SESSION_INVALIDATED");
        }
        return result;
    }

    private ObjectNode bound(ObjectNode data) {
        return data.put("clientId", config.clientId())
                .put("issuer", config.issuer().toString())
                .put("resourceAudience", config.resourceAudience());
    }

    private WebSessionRecord require(String id) {
        return optional(id).orElseThrow(WebSessionException::absent);
    }

    public Result bootstrap(String id) {
        Optional<WebSessionRecord> current = optional(id);
        if (current.isPresent()) return session(id);
        // A lost login response may leave the browser with the consumed prelogin handle.
        // Terminate its derived local identity before creating a new generation.
        if (id != null) store.invalidate(id);
        Instant now = clock.instant(), expires = now.plusSeconds(600);
        ObjectNode d = bound(WebWire.object().put("csrfToken", random()).put("state", "PRELOGIN"));
        WebSessionRecord p =
                new WebSessionRecord(random(), PRELOGIN, 0, now, expires, expires, READY, d);
        store.create(p);
        return result(p);
    }

    public Result session(String id) {
        WebSessionRecord r = require(id);
        return result(r.kind() == SESSION ? effective(r) : available(r));
    }

    public void csrf(String id, String origin, String token) {
        if (!config.origin().toString().equals(origin) || token == null)
            throw new WebSessionException(403, "SESSION_CSRF_INVALID");
        WebSessionRecord r = require(id);
        if (!constant(WebWire.text(r.data(), "csrfToken"), token))
            throw new WebSessionException(403, "SESSION_CSRF_INVALID");
    }

    private static boolean constant(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private WebSessionRecord available(WebSessionRecord r) {
        if (r.lifecycle() == READY) return r;
        if (WebWire.time(r.data(), "leaseExpiresAt").isAfter(clock.instant()))
            throw WebSessionException.conflict();
        if (r.lifecycle() == OWNED && r.kind() == SESSION)
            return ready(r, r.data(), r.idleExpiresAt());
        // A lost lease after send intent can never authorize another token send.
        store.invalidate(r.id());
        throw new WebSessionException(
                401, r.kind() == SESSION ? "REFRESH_UNCERTAIN" : "AUTH_EXCHANGE_UNCERTAIN");
    }

    private WebSessionRecord own(WebSessionRecord r) {
        r = available(r);
        ObjectNode d =
                r.data()
                        .put("fence", random())
                        .put("leaseExpiresAt", clock.instant().plusSeconds(15).toString());
        return update(r, r.next(OWNED, d, r.idleExpiresAt()));
    }

    private WebSessionRecord intent(WebSessionRecord r) {
        return update(r, r.next(SEND_INTENT, r.data(), r.idleExpiresAt()));
    }

    private WebSessionRecord update(WebSessionRecord from, WebSessionRecord to) {
        if (!store.replace(from, to)) throw WebSessionException.conflict();
        return to;
    }

    private WebSessionRecord ready(WebSessionRecord r, ObjectNode d, Instant idle) {
        d.remove(Set.of("fence", "leaseExpiresAt"));
        return update(r, r.next(READY, d, idle));
    }

    private Result result(WebSessionRecord r) {
        ObjectNode d = r.data(),
                v =
                        WebWire.object()
                                .put("state", WebWire.text(d, "state"))
                                .put(
                                        "expiresAt",
                                        WebWire.min(r.absoluteExpiresAt(), r.idleExpiresAt())
                                                .toString())
                                .put("csrfToken", WebWire.text(d, "csrfToken"));
        if (r.kind() == SESSION) {
            v.put("owner", WebWire.text(d, "owner")).put("version", r.version());
            v.set("profile", d.get("profile"));
            v.set("permissions", d.get("permissions"));
        } else
            for (String key :
                    Set.of(
                            "nextAction",
                            "challengeExpiresAt",
                            "cooldownSeconds",
                            "authorizationUrl")) if (d.has(key)) v.set(key, d.get(key));
        SafeSessionView.validate(v);
        return new Result(r.id(), v);
    }

    private WebSessionRecord newAttempt(WebSessionRecord r, String returnPath) {
        if (r.kind() != PRELOGIN
                || !"PRELOGIN".equals(r.data().path("state").asText())
                || r.data().has("stateBinding")) throw WebSessionException.conflict();
        if (!config.returnPaths().contains(returnPath)) throw WebSessionException.invalid();
        ObjectNode d =
                r.data()
                        .put("stateBinding", random())
                        .put("verifier", random())
                        .put("nonce", random())
                        .put("returnPath", returnPath)
                        .put("state", "AUTHENTICATING")
                        .put("nextAction", "authenticate");
        return update(r, r.next(READY, d, r.idleExpiresAt()));
    }

    public String hosted(String id, String returnPath) {
        WebSessionRecord r = newAttempt(available(require(id)), returnPath);
        return iam.authorization(
                WebWire.text(r.data(), "stateBinding"),
                WebWire.text(r.data(), "verifier"),
                WebWire.text(r.data(), "nonce"));
    }

    public Result custom(String id) {
        WebSessionRecord owned =
                own(newAttempt(available(require(id)), config.defaultReturnPath()));
        ObjectNode d = owned.data();
        ObjectNode body =
                WebWire.object()
                        .put("client_id", config.clientId())
                        .put("entryMode", "CUSTOM")
                        .put("redirect_uri", config.callback().toString())
                        .put("scope", String.join(" ", config.scopes()))
                        .put("state", WebWire.text(d, "stateBinding"))
                        .put("code_challenge", WebIamClient.challenge(WebWire.text(d, "verifier")))
                        .put("code_challenge_method", "S256")
                        .put("nonce", WebWire.text(d, "nonce"));
        try {
            ObjectNode response =
                    iam.request("POST", "/api/v1/auth/transactions", body, Map.of(), budget());
            d.put("transactionId", WebWire.uuid(response, "transactionId"))
                    .put("controlSecret", WebWire.text(response, "controlSecret"));
            d.put("state", "AUTHENTICATING")
                    .put("nextAction", WebWire.text(response, "nextAction"));
            return result(
                    ready(
                            owned,
                            d,
                            WebWire.min(
                                    owned.idleExpiresAt(), WebWire.time(response, "expiresAt"))));
        } catch (RuntimeException e) {
            store.invalidate(owned.id());
            throw e;
        }
    }

    /**
     * Callback parameter multiplicity is validated at the HTTP boundary before this exact-shape
     * dispatch.
     */
    public Result callback(String id, Map<String, String> query) {
        WebSessionRecord r = available(require(id));
        if (r.kind() != PRELOGIN
                || !constant(
                        WebWire.text(r.data(), "stateBinding"), query.getOrDefault("state", "")))
            throw WebSessionException.invalid();
        Set<String> keys = query.keySet();
        if (keys.equals(Set.of("code", "state")) && !query.get("code").isBlank())
            return exchange(r, query.get("code"), budget());
        if (keys.equals(Set.of("error", "state")) && "access_denied".equals(query.get("error"))) {
            WebSessionRecord owned = own(r);
            store.invalidate(owned.id());
            throw new WebSessionException(401, "AUTH_ACCESS_DENIED");
        }
        if (keys.equals(Set.of("kind", "auth_transaction_id", "state"))
                && "AUTH_CONTINUATION".equals(query.get("kind"))
                && query.get("auth_transaction_id")
                        .equals(r.data().path("transactionId").asText())) {
            if (r.data().path("continuationConsumed").asBoolean())
                throw WebSessionException.conflict();
            WebSessionRecord owned = own(r);
            owned =
                    update(
                            owned,
                            owned.next(
                                    OWNED,
                                    owned.data().put("continuationConsumed", true),
                                    owned.idleExpiresAt()));
            try {
                ObjectNode response = transaction(owned, "GET", "", null, budget());
                if (!"MFA_REQUIRED".equals(WebWire.text(response, "state")))
                    throw WebSessionException.protocol();
                return transactionView(owned, response);
            } catch (RuntimeException e) {
                store.invalidate(owned.id());
                throw e;
            }
        }
        throw WebSessionException.invalid();
    }

    public String returnPath(String id) {
        return WebWire.text(require(id).data(), "returnPath");
    }

    private Result exchange(WebSessionRecord pre, String code, WebIamClient.Budget budget) {
        WebSessionRecord sent = intent(pre.lifecycle() == OWNED ? pre : own(pre));
        try {
            WebIamClient.Tokens tokens = iam.exchange(code, sent.data(), budget);
            WebIamClient.Identity identity = iam.identity(tokens, budget);
            Instant now = clock.instant(),
                    absolute = WebWire.min(now.plusSeconds(3600), identity.absolute());
            ObjectNode d =
                    WebWire.object()
                            .put("state", "AUTHENTICATED")
                            .put("csrfToken", random())
                            .put("owner", random())
                            .put("returnPath", WebWire.text(sent.data(), "returnPath"))
                            .put("iamAbsoluteDeadline", identity.absolute().toString());
            bound(d);
            credentials(d, tokens);
            d.set("profile", identity.profile());
            d.set("permissions", identity.permissions());
            d.put("accessExpiresAt", identity.access().toString());
            WebSessionRecord session =
                    new WebSessionRecord(
                            random(),
                            SESSION,
                            0,
                            now,
                            absolute,
                            WebWire.min(absolute, now.plusSeconds(3600), identity.idle()),
                            READY,
                            d);
            update(sent, session);
            return result(session);
        } catch (RuntimeException e) {
            terminateSent(sent.id(), "AUTH_EXCHANGE_UNCERTAIN");
            if (e instanceof WebSessionException w
                    && w.status() < 500
                    && !w.code().startsWith("SESSION_STORE")) throw w;
            throw new WebSessionException(401, "AUTH_EXCHANGE_UNCERTAIN");
        }
    }

    private static void credentials(ObjectNode d, WebIamClient.Tokens t) {
        d.put("access", t.access())
                .put("accessExpiresAt", t.accessExpiresAt().toString())
                .put("oidcSubject", t.subject())
                .put("oidcNonce", t.nonce());
        if (t.refresh() == null) d.remove("refresh");
        else d.put("refresh", t.refresh());
    }

    private static WebIamClient.Tokens tokens(ObjectNode d) {
        return new WebIamClient.Tokens(
                WebWire.text(d, "access"),
                d.has("refresh") ? WebWire.text(d, "refresh") : null,
                WebWire.time(d, "accessExpiresAt"),
                WebWire.text(d, "oidcSubject"),
                WebWire.text(d, "oidcNonce"));
    }

    private WebSessionRecord effective(WebSessionRecord r) {
        WebSessionRecord owned = own(r);
        WebIamClient.Budget budget = budget();
        ObjectNode d = owned.data();
        WebIamClient.Tokens t = tokens(d);
        boolean refresh =
                t.refresh() != null
                        && !t.accessExpiresAt().isAfter(clock.instant().plusSeconds(30));
        if (!t.accessExpiresAt().isAfter(clock.instant()) && t.refresh() == null) {
            store.invalidate(r.id());
            throw new WebSessionException(401, "SESSION_INVALIDATED");
        }
        WebSessionRecord active = owned;
        try {
            if (refresh) {
                active = intent(owned);
                t = iam.refresh(t, budget);
                credentials(d, t);
            }
            WebIamClient.Identity identity =
                    refresh
                            ? iam.identity(t, budget)
                            : iam.validity(
                                    (ObjectNode) d.get("profile"),
                                    (ObjectNode) d.get("permissions"),
                                    t,
                                    budget);
            if (!d.path("profile").path("id").equals(identity.profile().path("id"))
                    || !d.path("profile")
                            .path("authenticationContext")
                            .path("sessionId")
                            .equals(
                                    identity.profile()
                                            .path("authenticationContext")
                                            .path("sessionId"))
                    || !d.path("profile")
                            .path("authenticationContext")
                            .path("applicationId")
                            .equals(
                                    identity.profile()
                                            .path("authenticationContext")
                                            .path("applicationId")))
                throw WebSessionException.protocol();
            d.set("profile", identity.profile());
            d.set("permissions", identity.permissions());
            d.put("accessExpiresAt", identity.access().toString());
            Instant iamAbsolute =
                    WebWire.min(WebWire.time(d, "iamAbsoluteDeadline"), identity.absolute());
            d.put("iamAbsoluteDeadline", iamAbsolute.toString());
            return ready(
                    active,
                    d,
                    WebWire.min(
                            r.absoluteExpiresAt(),
                            iamAbsolute,
                            identity.idle(),
                            clock.instant().plusSeconds(3600)));
        } catch (WebSessionException e) {
            if (refresh && active.lifecycle() == SEND_INTENT) {
                terminateSent(r.id(), "REFRESH_UNCERTAIN");
                throw new WebSessionException(
                        401,
                        e.code().equals("invalid_grant")
                                ? "SESSION_INVALIDATED"
                                : "REFRESH_UNCERTAIN");
            }
            if (e.status() == 401 || e.status() == 403) {
                store.invalidate(r.id());
                throw new WebSessionException(401, "SESSION_INVALIDATED");
            }
            // A read failure does not prove revocation. Release the unchanged owned generation.
            ready(active, active.data(), active.idleExpiresAt());
            throw e;
        }
    }

    private void terminateSent(String id, String uncertainCode) {
        try {
            store.invalidate(id);
        } catch (WebSessionException e) {
            // Durable SEND_INTENT stays fenced if terminal invalidation cannot be acknowledged.
            throw new WebSessionException(401, uncertainCode);
        }
    }

    private ObjectNode transaction(
            WebSessionRecord r,
            String method,
            String suffix,
            ObjectNode body,
            WebIamClient.Budget budget) {
        ObjectNode d = r.data();
        return iam.request(
                method,
                "/api/v1/auth/transactions/" + WebWire.uuid(d, "transactionId") + suffix,
                body,
                Map.of(
                        "Authentication-Transaction",
                        WebWire.text(d, "controlSecret"),
                        "Idempotency-Key",
                        d.has("actionKey")
                                ? WebWire.text(d, "actionKey")
                                : WebWire.text(d, "fence")),
                budget);
    }

    private Result transactionView(WebSessionRecord owned, ObjectNode response) {
        ObjectNode d = owned.data();
        if (response.has("transactionId")
                && !WebWire.text(d, "transactionId")
                        .equals(WebWire.uuid(response, "transactionId")))
            throw WebSessionException.protocol();
        if (response.has("state")) d.put("state", WebWire.text(response, "state"));
        d.remove(Set.of("challengeExpiresAt", "cooldownSeconds", "authorizationUrl"));
        for (String key :
                Set.of("nextAction", "challengeExpiresAt", "cooldownSeconds", "authorizationUrl"))
            if (response.has(key)) d.set(key, response.get(key));
        if (response.has("authorizationUrl")) {
            WebWire.navigation(
                    WebWire.text(response, "authorizationUrl"), config.developmentLoopback());
            d.put("state", "AWAITING_PROVIDER").put("nextAction", "authorize");
        }
        Instant idle = WebWire.min(owned.idleExpiresAt(), WebWire.time(response, "expiresAt"));
        return result(ready(owned, d, idle));
    }

    public Result action(String id, String action, ObjectNode body) {
        try {
            validateAction(action, body);
        } catch (WebSessionException e) {
            throw WebSessionException.invalid();
        }
        WebSessionRecord r = available(require(id));
        if (r.kind() != PRELOGIN || !r.data().has("transactionId"))
            throw WebSessionException.conflict();
        if (action.equals("magic")) {
            if (r.data().path("magicConsumed").asBoolean()) throw WebSessionException.conflict();
            if (!WebWire.text(body, "transactionId").equals(WebWire.text(r.data(), "transactionId"))
                    || !constant(
                            WebWire.text(body, "state"), WebWire.text(r.data(), "stateBinding"))
                    || !"EMAIL".equals(r.data().path("identifier").path("kind").asText()))
                throw WebSessionException.invalid();
            ObjectNode transformed =
                    WebWire.object()
                            .put("method", "EMAIL_MAGIC_LINK")
                            .put("proof", WebWire.text(body, "proof"));
            transformed.set("identifier", r.data().get("identifier"));
            body = transformed;
            action = "authenticate";
            r = update(r, r.next(READY, r.data().put("magicConsumed", true), r.idleExpiresAt()));
        }
        WebSessionRecord owned = own(r);
        WebIamClient.Budget budget = budget();
        try {
            String actionDigest = WebIamClient.challenge(action + ":" + WebWire.canonical(body));
            if (!actionDigest.equals(owned.data().path("actionDigest").asText())) {
                ObjectNode next =
                        owned.data().put("actionDigest", actionDigest).put("actionKey", random());
                owned = update(owned, owned.next(OWNED, next, owned.idleExpiresAt()));
            }
            if (body.has("identifier")) {
                ObjectNode d = owned.data();
                d.set("identifier", body.get("identifier"));
                if (action.equals("challenges")) d.remove("magicConsumed");
                owned = update(owned, owned.next(OWNED, d, owned.idleExpiresAt()));
            }
            ObjectNode response = transaction(owned, "POST", "/" + action, body, budget);
            if (action.equals("complete")) {
                if (!"authorization_code".equals(WebWire.text(response, "kind"))
                        || !constant(
                                WebWire.text(response, "state"),
                                WebWire.text(owned.data(), "stateBinding"))
                        || !response.path("expiresIn").isIntegralNumber()
                        || response.path("expiresIn").longValue() < 0)
                    throw WebSessionException.protocol();
                return exchange(owned, WebWire.text(response, "code"), budget);
            }
            if (action.equals("cancel")) {
                ObjectNode d = owned.data().put("state", "CANCELLED").put("nextAction", "none");
                Result v = result(owned.next(READY, d, owned.idleExpiresAt()));
                store.invalidate(owned.id());
                return v;
            }
            return transactionView(owned, response);
        } catch (WebSessionException e) {
            // Determinate validation failures leave the same controlled transaction usable.
            Optional<WebSessionRecord> current = store.read(owned.id());
            if (current.isPresent() && current.get().version() == owned.version())
                ready(owned, owned.data(), owned.idleExpiresAt());
            throw e;
        }
    }

    private static void identifier(JsonNode n) {
        WebWire.fields(n, Set.of("kind", "value"), Set.of("region"));
        WebWire.boundedText(n, "value", 1024);
        WebWire.boundedText(n, "kind", 128);
        if (!Set.of("EMAIL", "USERNAME", "PHONE").contains(WebWire.text(n, "kind")))
            throw WebSessionException.invalid();
        if (n.hasNonNull("region")) WebWire.boundedText(n, "region", 16);
    }

    private static void validateAction(String action, ObjectNode body) {
        switch (action) {
            case "authenticate" -> {
                String method = WebWire.text(body, "method");
                boolean password = method.equals("PASSWORD");
                if (!Set.of("PASSWORD", "EMAIL_OTP", "SMS_OTP", "EMAIL_MAGIC_LINK")
                        .contains(method)) throw WebSessionException.invalid();
                WebWire.fields(
                        body,
                        Set.of("method", "identifier", password ? "password" : "proof"),
                        Set.of());
                identifier(body.get("identifier"));
                WebWire.boundedText(body, password ? "password" : "proof", password ? 1024 : 128);
            }
            case "challenges" -> {
                WebWire.fields(body, Set.of("method", "identifier"), Set.of());
                identifier(body.get("identifier"));
                if (!Set.of("EMAIL_OTP", "SMS_OTP", "EMAIL_MAGIC_LINK")
                        .contains(WebWire.text(body, "method")))
                    throw WebSessionException.invalid();
            }
            case "mfa" -> {
                WebWire.fields(body, Set.of("method", "code"), Set.of());
                WebWire.boundedText(body, "code", 128);
                if (!Set.of("TOTP", "RECOVERY_CODE").contains(WebWire.text(body, "method")))
                    throw WebSessionException.invalid();
            }
            case "authorize" -> {
                WebWire.fields(
                        body,
                        Set.of("providerId"),
                        Set.of("registrationGrantToken", "registrationAccessCode"));
                WebWire.uuid(body, "providerId");
                if (body.has("registrationGrantToken") && body.has("registrationAccessCode"))
                    throw WebSessionException.invalid();
                if (body.has("registrationGrantToken"))
                    WebWire.boundedText(body, "registrationGrantToken", 2048);
                if (body.has("registrationAccessCode"))
                    WebWire.boundedText(body, "registrationAccessCode", 128);
            }
            case "magic" -> {
                WebWire.fields(body, Set.of("transactionId", "state", "proof"), Set.of());
                WebWire.uuid(body, "transactionId");
                WebWire.boundedText(body, "state", 512);
                WebWire.boundedText(body, "proof", 128);
            }
            case "complete", "cancel" -> WebWire.fields(body, Set.of(), Set.of());
            default -> throw WebSessionException.invalid();
        }
    }

    public ObjectNode capabilities(String resource) {
        if (!Set.of("auth-methods", "auth-policy").contains(resource))
            throw WebSessionException.invalid();
        ObjectNode response =
                iam.request(
                        "GET",
                        "/api/v1/apps/" + WebIamClient.encode(config.clientId()) + "/" + resource,
                        null,
                        Map.of(),
                        budget());
        return CapabilityView.project(resource, response, config.clientId());
    }

    public Logout logout(String id) {
        WebSessionRecord snapshot = optional(id).orElse(null);
        String local = "NOT_FOUND", remote = "NOT_ATTEMPTED";
        try {
            local = id != null && store.invalidate(id).isPresent() ? "INVALIDATED" : "NOT_FOUND";
        } catch (WebSessionException e) {
            local = "UNCONFIRMED";
        }
        if (snapshot != null && snapshot.kind() == SESSION) {
            try {
                remote = iam.logout(tokens(snapshot.data()), budget());
            } catch (WebSessionException e) {
                remote = "UNCONFIRMED";
            }
        }
        ObjectNode result =
                WebWire.object()
                        .put("local", local)
                        .put("cookie", "CLEARED")
                        .put("remote", remote)
                        .put("sso", "NOT_REQUESTED");
        return new Logout(
                local.equals("UNCONFIRMED") || remote.equals("UNCONFIRMED") ? 503 : 200, result);
    }

    public ObjectNode registration(String binding, String ref, String action, ObjectNode body) {
        require(binding);
        if (ref == null) {
            WebWire.fields(
                    body,
                    Set.of("identifier", "password"),
                    Set.of(
                            "uiLocales",
                            "registrationGrantToken",
                            "registrationAccessCode",
                            "organizationInvitationToken"));
            identifier(body.get("identifier"));
            WebWire.boundedText(body, "password", 128);
            ObjectNode wire = body.deepCopy().put("client_id", config.clientId());
            ObjectNode response =
                    iam.request(
                            "POST",
                            "/api/v1/auth/signup",
                            wire,
                            Map.of("Idempotency-Key", random()),
                            budget());
            Instant now = clock.instant(),
                    expires =
                            WebWire.min(now.plusSeconds(600), WebWire.time(response, "expiresAt"));
            ObjectNode data = bound(response.deepCopy().put("binding", binding));
            WebSessionRecord r =
                    new WebSessionRecord(
                            random(), REGISTRATION, 0, now, expires, expires, READY, data);
            store.create(r);
            return safeRegistration(r, response);
        }
        WebSessionRecord r = available(require(ref));
        if (r.kind() != REGISTRATION || !binding.equals(WebWire.text(r.data(), "binding")))
            throw WebSessionException.absent();
        if (!r.data().hasNonNull("controlSecret")) {
            if ("PENDING_VERIFICATION".equals(WebWire.text(r.data(), "status")))
                throw WebSessionException.protocol();
            if (!action.equals("get")) throw WebSessionException.conflict();
            return safeRegistration(r, r.data());
        }
        if (!Set.of("get", "challenges", "complete", "cancel").contains(action))
            throw WebSessionException.invalid();
        if (action.equals("complete")) {
            WebWire.fields(body, Set.of("code"), Set.of());
            WebWire.boundedText(body, "code", 6);
            if (!WebWire.text(body, "code").matches("[0-9]{6}"))
                throw WebSessionException.invalid();
        } else WebWire.fields(body, Set.of(), Set.of());
        WebSessionRecord owned = own(r);
        ObjectNode d = owned.data(), wire = body.deepCopy();
        String control = WebWire.text(d, "controlSecret");
        Map<String, String> headers =
                action.equals("get")
                        ? Map.of(
                                "Registration-Client",
                                config.clientId(),
                                "Registration-Control",
                                control)
                        : Map.of("Registration-Client", config.clientId());
        if (!action.equals("get")) wire.put("controlSecret", control);
        try {
            ObjectNode response =
                    iam.request(
                            action.equals("get") ? "GET" : "POST",
                            "/api/v1/auth/signup/operations/"
                                    + WebWire.uuid(d, "registrationId")
                                    + (action.equals("get") ? "" : "/" + action),
                            action.equals("get") ? null : wire,
                            headers,
                            budget());
            ObjectNode next = bound(response.deepCopy().put("binding", binding));
            if (!next.hasNonNull("controlSecret")) next.put("controlSecret", control);
            return safeRegistration(
                    ready(
                            owned,
                            next,
                            WebWire.min(r.idleExpiresAt(), WebWire.time(response, "expiresAt"))),
                    response);
        } catch (WebSessionException e) {
            ready(owned, owned.data(), owned.idleExpiresAt());
            throw e;
        }
    }

    private ObjectNode safeRegistration(WebSessionRecord r, ObjectNode response) {
        ObjectNode safe =
                WebWire.object()
                        .put("registrationId", r.id())
                        .put("status", WebWire.text(response, "status"))
                        .put(
                                "expiresAt",
                                WebWire.min(
                                                r.absoluteExpiresAt(),
                                                r.idleExpiresAt(),
                                                WebWire.time(response, "expiresAt"))
                                        .toString())
                        .put("nextAction", WebWire.text(response, "nextAction"));
        if (!response.has("nextChallengeAt")) throw WebSessionException.protocol();
        if (!response.path("nextChallengeAt").isNull()) WebWire.time(response, "nextChallengeAt");
        safe.set("nextChallengeAt", response.get("nextChallengeAt"));
        return safe;
    }

    public void passwordReset(String action, ObjectNode body) {
        ObjectNode wire = body.deepCopy();
        if (action.equals("request")) {
            WebWire.fields(body, Set.of("email"), Set.of());
            WebWire.boundedText(body, "email", 320);
            wire.put("client_id", config.clientId());
            iam.request("POST", "/api/v1/auth/password/forgot", wire, Map.of(), budget());
        } else if (action.equals("complete")) {
            WebWire.fields(body, Set.of("token", "newPassword"), Set.of());
            WebWire.boundedText(body, "token", 2048);
            WebWire.boundedText(body, "newPassword", 128);
            iam.request(
                    "POST",
                    "/api/v1/auth/password/reset",
                    wire,
                    Map.of("Password-Reset-Client", config.clientId()),
                    budget());
        } else throw WebSessionException.invalid();
    }
}
