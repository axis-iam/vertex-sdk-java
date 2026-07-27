package com.chaosguide.iam.vertex.manifest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

class PermissionManifestClientTest {
    private static final PermissionManifestClient.Manifest MANIFEST =
            new PermissionManifestClient.Manifest(
                    "orders-api",
                    "git:abc123",
                    List.of(
                            new PermissionManifestClient.Declaration(
                                    "posts", "read", "Read posts", null)));

    @Test
    void matchesBackendFrozenNullVector() {
        var prepared = PermissionManifestClient.prepare(MANIFEST, PermissionManifestClient.Mode.VALIDATE);
        assertThat(prepared.fingerprint())
                .isEqualTo("bd2036720114f62abecb2850b61c165763a9cf1ee3736eab2bd59b9646aae9b5");
    }

    @Test
    void consumesSharedCanonicalVectors() throws Exception {
        var root = sharedFixture();
        for (var vector : root.path("vectors")) {
            var declarations = new ArrayList<PermissionManifestClient.Declaration>();
            for (var item : vector.path("permissions")) declarations.add(new PermissionManifestClient.Declaration(
                    item.path("resource").textValue(), item.path("action").textValue(), item.path("name").textValue(),
                    item.path("description").isNull() ? null : item.path("description").textValue()));
            var prepared = PermissionManifestClient.prepare(new PermissionManifestClient.Manifest("vector", "1", declarations), PermissionManifestClient.Mode.VALIDATE);
            assertThat(prepared.fingerprint()).as(vector.path("name").textValue()).isEqualTo(vector.path("fingerprint").textValue());
        }
        for (var name : root.path("localReject")) assertLocalReject(name.textValue());
    }

    @Test
    void consumesEverySharedRetryAfterVector() throws Exception {
        var retry = sharedFixture().path("retry");
        for (var value : retry.path("validRetryAfterSeconds")) assertThat(PermissionManifestClient.parseRetryAfter(value.asText())).isEqualTo(value.intValue());
        for (var value : retry.path("invalidRetryAfter")) assertThat(PermissionManifestClient.parseRetryAfter(value.textValue())).isNull();
    }

    @Test
    void consumesEverySharedRetryAndTerminalStatus() throws Exception {
        var retry = sharedFixture().path("retry");
        for (var value : retry.path("statuses")) assertRequestCountForStatus(value.intValue(), 3);
        for (var value : retry.path("terminalStatuses")) assertRequestCountForStatus(value.intValue(), 2);
    }

    private static void assertRequestCountForStatus(int status, int expectedRequests) throws Exception {
        try (var server = new MockWebServer()) {
            server.start();
            server.enqueue(new MockResponse().setBody("{\"access_token\":\"safe\",\"token_type\":\"Bearer\",\"expires_in\":60,\"scope\":\"permissions:sync\"}"));
            String body = "{\"status\":" + status + ",\"error\":\"STATUS_" + status + "\",\"message\":\"failed\",\"timestamp\":\"2026-07-17T00:00:00Z\"}";
            server.enqueue(new MockResponse().setResponseCode(status).setBody(body));
            if (expectedRequests == 3) server.enqueue(new MockResponse().setResponseCode(status).setBody(body));
            var client = new PermissionManifestClient(new PermissionManifestClient.Config(
                    server.url("/").toString(), server.url("/").toString(), "id", "secret",
                    Duration.ofSeconds(5), Duration.ofSeconds(30), 2, Duration.ofMillis(1)));
            assertThatThrownBy(() -> client.validate(MANIFEST)).isInstanceOf(PermissionManifestClient.PermissionManifestException.class);
            assertThat(server.getRequestCount()).as("HTTP status " + status).isEqualTo(expectedRequests);
        }
    }

    @Test
    void sharesThreeAttemptsAndRedactsInvalidTokenResponse() throws Exception {
        try (var server = new MockWebServer()) {
            server.start();
            server.enqueue(new MockResponse().setResponseCode(503).setBody("{}"));
            server.enqueue(new MockResponse().setResponseCode(503).setBody("{}"));
            server.enqueue(new MockResponse().setResponseCode(200).setBody("{\"access_token\":\"sensitive-bearer\",\"token_type\":\"Bearer\",\"expires_in\":60,\"scope\":\"wrong\"}"));
            var observations = new ArrayList<PermissionManifestClient.Observation>();
            var client = new PermissionManifestClient(new PermissionManifestClient.Config(server.url("/").toString(), server.url("/").toString(), "id", "secret", Duration.ofSeconds(5), Duration.ofSeconds(30), 2, Duration.ofMillis(1)), observations::add);
            assertThatThrownBy(() -> client.validate(MANIFEST)).isInstanceOf(PermissionManifestClient.PermissionManifestException.class)
                    .satisfies(error -> { var protocol = (PermissionManifestClient.PermissionManifestException) error; assertThat(protocol.code()).isEqualTo("INVALID_TOKEN_RESPONSE"); assertThat(protocol.details()).isNull(); assertThat(protocol.toString()).doesNotContain("sensitive-bearer"); });
            assertThat(server.getRequestCount()).isEqualTo(3);
            assertThat(observations).singleElement().satisfies(event -> { assertThat(event.mode()).isEqualTo("validate"); assertThat(event.outcome()).isEqualTo("ERROR"); assertThat(event.toString()).doesNotContain("sensitive-bearer"); });
        }
    }

    @Test
    void redactsMalformedTokenJsonAndIssuerDescription() throws Exception {
        try (var server = new MockWebServer()) {
            server.start();
            server.enqueue(new MockResponse().setBody("{\"access_token\":\"sensitive-bearer\""));
            var client = new PermissionManifestClient(new PermissionManifestClient.Config(server.url("/").toString(), server.url("/").toString(), "id", "secret", Duration.ofSeconds(5), Duration.ofSeconds(30), 0, Duration.ofMillis(1)));
            assertThatThrownBy(() -> client.validate(MANIFEST))
                    .isInstanceOf(PermissionManifestClient.PermissionManifestException.class)
                    .satisfies(error -> {
                        var protocol = (PermissionManifestClient.PermissionManifestException) error;
                        assertThat(protocol.code()).isEqualTo("INVALID_JSON_RESPONSE");
                        assertThat(protocol.details()).isNull();
                        assertThat(protocol.getCause()).isNull();
                        assertThat(protocol.toString()).doesNotContain("sensitive-bearer");
                    });
        }
        try (var server = new MockWebServer()) {
            server.start();
            server.enqueue(new MockResponse().setResponseCode(400).setBody("{\"error\":\"invalid_client\",\"error_description\":\"secret diagnostic\"}"));
            var client = new PermissionManifestClient(new PermissionManifestClient.Config(server.url("/").toString(), server.url("/").toString(), "id", "secret", Duration.ofSeconds(5), Duration.ofSeconds(30), 0, Duration.ofMillis(1)));
            assertThatThrownBy(() -> client.validate(MANIFEST))
                    .isInstanceOf(PermissionManifestClient.PermissionManifestException.class)
                    .satisfies(error -> {
                        var protocol = (PermissionManifestClient.PermissionManifestException) error;
                        assertThat(protocol.code()).isEqualTo("invalid_client");
                        assertThat(protocol.getMessage()).isEqualTo("Permission manifest machine token request failed");
                        assertThat(protocol.toString()).doesNotContain("secret diagnostic");
                    });
        }
    }

    @Test
    void usesOneThreeAttemptBudgetAcrossIssuerAndPortal() throws Exception {
        try (var server = new MockWebServer()) {
            server.start();
            String unavailable = "{\"status\":503,\"error\":\"UNAVAILABLE\",\"message\":\"down\",\"timestamp\":\"2026-07-17T00:00:00Z\"}";
            server.enqueue(new MockResponse().setResponseCode(503).setBody(unavailable));
            server.enqueue(new MockResponse().setBody("{\"access_token\":\"safe\",\"token_type\":\"Bearer\",\"expires_in\":60,\"scope\":\"permissions:sync\"}"));
            server.enqueue(new MockResponse().setResponseCode(503).setBody(unavailable));
            var client = new PermissionManifestClient(new PermissionManifestClient.Config(server.url("/").toString(), server.url("/").toString(), "id", "secret", Duration.ofSeconds(5), Duration.ofSeconds(30), 2, Duration.ofMillis(1)));
            assertThatThrownBy(() -> client.validate(MANIFEST)).isInstanceOf(PermissionManifestClient.PermissionManifestException.class)
                    .satisfies(error -> assertThat(((PermissionManifestClient.PermissionManifestException) error).status()).isEqualTo(503));
            assertThat(server.getRequestCount()).isEqualTo(3);
        }
    }

    @Test
    void rejectsFractionalCountsAndMissingResultFields() throws Exception {
        try (var server = new MockWebServer()) {
            server.start();
            server.enqueue(new MockResponse().setBody("{\"access_token\":\"safe\",\"token_type\":\"Bearer\",\"expires_in\":60,\"scope\":\"permissions:sync\"}"));
            var prepared = PermissionManifestClient.prepare(MANIFEST, PermissionManifestClient.Mode.VALIDATE);
            server.enqueue(new MockResponse().setBody("{\"mode\":\"validate\",\"manifestId\":\"orders-api\",\"revision\":\"git:abc123\",\"fingerprint\":\"" + prepared.fingerprint() + "\",\"applied\":false,\"results\":[],\"drift\":[],\"counts\":{\"created\":1.5,\"updated\":0,\"unchanged\":0,\"resurrected\":0,\"conflict\":0,\"drift\":0}}"));
            var client = new PermissionManifestClient(new PermissionManifestClient.Config(server.url("/").toString(), server.url("/").toString(), "id", "secret"));
            assertThatThrownBy(() -> client.validate(MANIFEST)).isInstanceOf(PermissionManifestClient.PermissionManifestException.class)
                    .satisfies(error -> assertThat(((PermissionManifestClient.PermissionManifestException) error).code()).isEqualTo("INVALID_MANIFEST_RESPONSE"));
        }
    }

    @Test
    void rejectsEverySharedResponseVector() throws Exception {
        var prepared = PermissionManifestClient.prepare(MANIFEST, PermissionManifestClient.Mode.VALIDATE);
        String base = "{\"mode\":\"validate\",\"manifestId\":\"orders-api\",\"revision\":\"git:abc123\",\"fingerprint\":\"" + prepared.fingerprint() + "\",\"applied\":false,\"results\":[],\"drift\":[],\"counts\":{\"created\":0,\"updated\":0,\"unchanged\":0,\"resurrected\":0,\"conflict\":0,\"drift\":0}}";
        for (var vector : sharedFixture().path("responseReject")) {
            String name = vector.textValue();
            String responseBody = switch (name) {
                case "missing-required-field" -> "{}";
                case "unknown-result-enum" -> base.replace("\"results\":[]", "\"results\":[{\"key\":\"posts:read\",\"operation\":\"UNKNOWN\",\"reason\":\"DECLARATION_ACCEPTED\"}]");
                case "wrong-counts" -> base.replace("\"created\":0", "\"created\":1");
                case "malformed-json" -> "{";
                case "duplicate-json-member-where-supported" -> base.replaceFirst("\\{\"mode\":\"validate\"", "{\"mode\":\"validate\",\"mode\":\"validate\"");
                default -> throw new AssertionError("unknown shared responseReject vector " + name);
            };
            try (var server = new MockWebServer()) {
                server.start();
                server.enqueue(new MockResponse().setBody("{\"access_token\":\"safe\",\"token_type\":\"Bearer\",\"expires_in\":60,\"scope\":\"permissions:sync\"}"));
                server.enqueue(new MockResponse().setBody(responseBody));
                var client = new PermissionManifestClient(new PermissionManifestClient.Config(server.url("/").toString(), server.url("/").toString(), "id", "secret"));
                assertThatThrownBy(() -> client.validate(MANIFEST)).isInstanceOf(PermissionManifestClient.PermissionManifestException.class)
                        .satisfies(error -> assertThat(((PermissionManifestClient.PermissionManifestException) error).code()).isIn("INVALID_MANIFEST_RESPONSE", "INVALID_JSON_RESPONSE"));
            }
        }
    }

    private static com.fasterxml.jackson.databind.JsonNode sharedFixture() throws Exception {
        return new ObjectMapper().readTree(Files.readString(Path.of("../../docs/fixtures/permission-manifest-vectors.json")));
    }

    private static void assertLocalReject(String name) {
        var declaration = MANIFEST.permissions().get(0);
        var candidate = switch (name) {
            case "duplicate-resource-action-key" -> new PermissionManifestClient.Manifest("orders-api", "1", List.of(declaration, declaration));
            case "non-nfc-string" -> new PermissionManifestClient.Manifest("orders-api", "1", List.of(new PermissionManifestClient.Declaration("posts", "read", "Cafe\u0301", null)));
            case "malformed-or-wildcard-key" -> new PermissionManifestClient.Manifest("orders-api", "1", List.of(new PermissionManifestClient.Declaration("*", "read", "Read", null)));
            case "name-over-128-utf16-units" -> new PermissionManifestClient.Manifest("orders-api", "1", List.of(new PermissionManifestClient.Declaration("posts", "read", "x".repeat(129), null)));
            case "description-over-512-utf16-units" -> new PermissionManifestClient.Manifest("orders-api", "1", List.of(new PermissionManifestClient.Declaration("posts", "read", "Read", "x".repeat(513))));
            default -> throw new AssertionError("unknown shared localReject vector " + name);
        };
        assertThatThrownBy(() -> PermissionManifestClient.prepare(candidate, PermissionManifestClient.Mode.VALIDATE)).as(name).isInstanceOf(RuntimeException.class);
    }

    @Test
    void malformedErrorEnvelopeUsesStableCode() throws Exception {
        try (var server = new MockWebServer()) {
            server.start(); server.enqueue(new MockResponse().setResponseCode(400).setBody("{}"));
            var client = new PermissionManifestClient(new PermissionManifestClient.Config(server.url("/").toString(), server.url("/").toString(), "id", "secret"));
            assertThatThrownBy(() -> client.validate(MANIFEST)).isInstanceOf(PermissionManifestClient.PermissionManifestException.class)
                    .satisfies(error -> assertThat(((PermissionManifestClient.PermissionManifestException) error).code()).isEqualTo("INVALID_ERROR_RESPONSE"));
        }
    }

    @Test
    void sortsStructuredDeclarationsAndRejectsDuplicateAndNonNfc() {
        var prepared =
                PermissionManifestClient.prepare(
                        new PermissionManifestClient.Manifest(
                                "orders-api",
                                "1",
                                List.of(
                                        new PermissionManifestClient.Declaration(
                                                "users", "read", "Read users", null),
                                        new PermissionManifestClient.Declaration(
                                                "orders", "write", "Café", "café/日"))),
                        PermissionManifestClient.Mode.UPSERT);
        assertThat(prepared.permissions())
                .extracting(PermissionManifestClient.Declaration::key)
                .containsExactly("orders:write", "users:read");

        assertThatThrownBy(
                        () ->
                                PermissionManifestClient.prepare(
                                        new PermissionManifestClient.Manifest(
                                                "orders-api",
                                                "1",
                                                List.of(
                                                        MANIFEST.permissions().get(0),
                                                        MANIFEST.permissions().get(0))),
                                        PermissionManifestClient.Mode.VALIDATE))
                .hasMessageContaining("duplicate");
        assertThatThrownBy(
                        () ->
                                PermissionManifestClient.prepare(
                                        new PermissionManifestClient.Manifest(
                                                "orders-api",
                                                "1",
                                                List.of(
                                                        new PermissionManifestClient.Declaration(
                                                                "posts",
                                                                "read",
                                                                "Cafe\u0301",
                                                                null))),
                                        PermissionManifestClient.Mode.VALIDATE))
                .hasMessageContaining("NFC");
        for (var invalid : List.of(
                new PermissionManifestClient.Declaration("*", "read", "Read", null),
                new PermissionManifestClient.Declaration("posts", "read", "x".repeat(129), null),
                new PermissionManifestClient.Declaration("posts", "read", "Read", "x".repeat(513))))
            assertThatThrownBy(() -> PermissionManifestClient.prepare(
                    new PermissionManifestClient.Manifest("orders-api", "1", List.of(invalid)), PermissionManifestClient.Mode.VALIDATE));
    }

    @Test
    void disabledStartupPerformsNoClientConstructionOrNetwork() {
        assertThat(
                        PermissionManifestClient.runStartup(
                                null,
                                MANIFEST,
                                new PermissionManifestClient.StartupOptions(
                                        PermissionManifestClient.StartupMode.DISABLED,
                                        null,
                                        null,
                                        null)))
                .isEqualTo(new PermissionManifestClient.StartupResult(false, false, null));
    }

    @Test
    void developmentStartupRequiresExplicitFailurePolicy() {
        assertThatThrownBy(
                        () ->
                                PermissionManifestClient.runStartup(
                                        null,
                                        MANIFEST,
                                        new PermissionManifestClient.StartupOptions(
                                                PermissionManifestClient.StartupMode.DEVELOPMENT_STARTUP,
                                                null,
                                                "idempotency-key",
                                                null)))
                .hasMessageContaining("failurePolicy");
    }

    @Test
    void developmentContinueRequiresAndEmitsRedactedHandler() throws Exception {
        assertThatThrownBy(() -> PermissionManifestClient.runStartup(
                        null, MANIFEST, new PermissionManifestClient.StartupOptions(
                                PermissionManifestClient.StartupMode.DEVELOPMENT_STARTUP,
                                PermissionManifestClient.FailurePolicy.CONTINUE,
                                "idempotency-key", null)))
                .hasMessageContaining("continueHandler");
        try (var server = new MockWebServer()) {
            server.start();
            server.enqueue(new MockResponse().setBody("{\"access_token\":\"safe\",\"token_type\":\"Bearer\",\"expires_in\":60,\"scope\":\"permissions:sync\"}"));
            server.enqueue(new MockResponse().setResponseCode(503).setBody("{\"status\":503,\"error\":\"UNAVAILABLE\",\"message\":\"down\",\"timestamp\":\"2026-07-17T00:00:00Z\"}"));
            var events = new ArrayList<PermissionManifestClient.StartupContinuation>();
            var client = new PermissionManifestClient(new PermissionManifestClient.Config(server.url("/").toString(), server.url("/").toString(), "id", "secret", Duration.ofSeconds(5), Duration.ofSeconds(30), 0, Duration.ofMillis(1)));
            var result = PermissionManifestClient.runStartup(client, MANIFEST, new PermissionManifestClient.StartupOptions(
                    PermissionManifestClient.StartupMode.DEVELOPMENT_STARTUP,
                    PermissionManifestClient.FailurePolicy.CONTINUE,
                    "idempotency-key", events::add));
            assertThat(result).isEqualTo(new PermissionManifestClient.StartupResult(true, true, null));
            assertThat(events).containsExactly(new PermissionManifestClient.StartupContinuation("DEVELOPMENT_STARTUP", "CONTINUED", 503, "UNAVAILABLE"));
            assertThat(events.toString()).doesNotContain("down");
        }
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "IAM_PERMISSION_MANIFEST_NEGATIVE_E2E", matches = "terminal|rate")
    void realBackendTerminalAndRateLimitRetryPolicy() {
        String mode = env("IAM_PERMISSION_MANIFEST_NEGATIVE_E2E");
        var manifest = new PermissionManifestClient.Manifest("m3-negative-java-" + mode, "1", List.of());
        String clientId = env(mode.equals("rate") ? "IAM_NEG_RATE_CLIENT_ID" : "IAM_NEG_CLIENT_ID");
        String secret = env(mode.equals("rate") ? "IAM_NEG_RATE_CLIENT_SECRET" : "IAM_NEG_CLIENT_SECRET");
        java.util.function.Function<String, PermissionManifestClient> client =
                portal ->
                        new PermissionManifestClient(
                                new PermissionManifestClient.Config(
                                        env("IAM_NEG_ISSUER"), portal, clientId, secret,
                                        Duration.ofSeconds(5), Duration.ofSeconds(30),
                                        mode.equals("rate") ? 1 : 2, Duration.ofMillis(1)));
        if (mode.equals("terminal")) {
            client.apply(env("IAM_NEG_PORTAL")).upsert(manifest, "sdk-java-terminal-key");
            assertThatThrownBy(() -> client.apply(env("IAM_NEG_PROXY")).upsert(
                            new PermissionManifestClient.Manifest(manifest.manifestId(), "2", List.of()),
                            "sdk-java-terminal-key"))
                    .isInstanceOf(PermissionManifestClient.PermissionManifestException.class)
                    .satisfies(error -> assertThat(((PermissionManifestClient.PermissionManifestException) error).status()).isEqualTo(409));
            return;
        }
        assertThatThrownBy(() -> client.apply(env("IAM_NEG_PROXY")).validate(manifest))
                .isInstanceOf(PermissionManifestClient.PermissionManifestException.class)
                .satisfies(error -> assertThat(((PermissionManifestClient.PermissionManifestException) error).status()).isEqualTo(429));
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "IAM_PERMISSION_MANIFEST_E2E", matches = "1")
    void realBackendSyncReplayAndAuthorizationNegatives() {
        var manifest =
                new PermissionManifestClient.Manifest(
                        env("IAM_MANIFEST_ID"),
                        "e2e-1",
                        List.of(
                                new PermissionManifestClient.Declaration(
                                        "orders", "write", "Café", "café/日"),
                                new PermissionManifestClient.Declaration(
                                        "users", "read", "Read users", null)));
        var config =
                new PermissionManifestClient.Config(
                        env("IAM_MANIFEST_ISSUER"),
                        env("IAM_MANIFEST_PORTAL"),
                        env("IAM_MANIFEST_CLIENT_ID"),
                        env("IAM_MANIFEST_CLIENT_SECRET"));
        var client = new PermissionManifestClient(config);
        var validate = client.validate(manifest);
        var first = client.upsert(manifest, "sdk-java-replay-key");
        var replay = client.upsert(manifest, "sdk-java-replay-key");
        var stored = client.validate(manifest);
        assertThat(validate.fingerprint()).isEqualTo(first.fingerprint());
        assertThat(replay).isEqualTo(first);
        assertThat(stored.results()).allMatch(item -> "UNCHANGED".equals(item.operation()));
        var changed =
                new PermissionManifestClient.Manifest(
                        manifest.manifestId(), "e2e-2", manifest.permissions());
        assertThatThrownBy(() -> client.upsert(changed, "sdk-java-replay-key"))
                .isInstanceOf(PermissionManifestClient.PermissionManifestException.class)
                .satisfies(
                        error ->
                                assertThat(
                                                ((PermissionManifestClient.PermissionManifestException)
                                                                error)
                                                        .status())
                                        .isEqualTo(409));
        var wrong =
                new PermissionManifestClient(
                        new PermissionManifestClient.Config(
                                env("IAM_MANIFEST_ISSUER"),
                                env("IAM_MANIFEST_PORTAL"),
                                env("IAM_MANIFEST_WRONG_CLIENT_ID"),
                                env("IAM_MANIFEST_WRONG_CLIENT_SECRET")));
        assertThatThrownBy(() -> wrong.validate(manifest))
                .isInstanceOf(PermissionManifestClient.PermissionManifestException.class)
                .satisfies(
                        error ->
                                assertThat(
                                                ((PermissionManifestClient.PermissionManifestException)
                                                                error)
                                                        .status())
                                        .isEqualTo(401));
        var cross =
                new PermissionManifestClient(
                        new PermissionManifestClient.Config(
                                env("IAM_MANIFEST_ISSUER"),
                                env("IAM_MANIFEST_PORTAL"),
                                env("IAM_MANIFEST_CROSS_CLIENT_ID"),
                                env("IAM_MANIFEST_CROSS_CLIENT_SECRET")));
        assertThatThrownBy(() -> cross.validate(manifest))
                .isInstanceOf(PermissionManifestClient.PermissionManifestException.class)
                .satisfies(
                        error ->
                                assertThat(
                                                ((PermissionManifestClient.PermissionManifestException)
                                                                error)
                                                        .status())
                                        .isEqualTo(404));
        var crossApplication =
                new PermissionManifestClient(
                        new PermissionManifestClient.Config(
                                env("IAM_MANIFEST_ISSUER"),
                                env("IAM_MANIFEST_PORTAL"),
                                env("IAM_MANIFEST_APP_B_CLIENT_ID"),
                                env("IAM_MANIFEST_APP_B_CLIENT_SECRET")));
        assertThat(crossApplication.validate(manifest).results())
                .allMatch(item -> "CREATE".equals(item.operation()));
    }

    private static String env(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalStateException(name + " is required");
        return value;
    }
}
