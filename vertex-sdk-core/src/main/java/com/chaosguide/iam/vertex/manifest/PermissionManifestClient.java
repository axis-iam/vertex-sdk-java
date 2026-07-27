package com.chaosguide.iam.vertex.manifest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.Credentials;
import okhttp3.FormBody;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CountDownLatch;
import java.util.regex.Pattern;

/** Server-only client for the exact-scope permission-manifest protocol. */
public final class PermissionManifestClient {
    public static final String PERMISSIONS_SYNC_SCOPE = "permissions:sync";
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final Pattern MANIFEST_ID = Pattern.compile("[a-z0-9][a-z0-9._-]{0,127}");
    private static final Pattern REVISION = Pattern.compile("[A-Za-z0-9._:@/+~-]{1,128}");
    private static final Pattern SEGMENT = Pattern.compile("[a-z0-9_-]{1,128}");
    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern IDEMPOTENCY = Pattern.compile("[\\x21-\\x7e]{8,128}");
    private static final Set<Integer> RETRYABLE = Set.of(408, 429, 502, 503, 504);
    private static final Set<String> OPERATIONS =
            Set.of("CREATE", "UPDATE", "UNCHANGED", "RESURRECT", "CONFLICT");
    private static final Set<String> REASONS =
            Set.of(
                    "DECLARATION_ACCEPTED",
                    "MANUAL_COLLISION",
                    "LEGACY_CODE_UNATTRIBUTED",
                    "CODE_OWNER_COLLISION");
    private static final Set<String> DRIFT_KINDS =
            Set.of(
                    "MANUAL_COLLISION",
                    "LEGACY_CODE_UNATTRIBUTED",
                    "CODE_OWNER_COLLISION",
                    "ABSENT_DECLARATION");
    private static final Set<String> SOURCES = Set.of("CODE", "MANUAL");

    private final Config config;
    private final OkHttpClient http;
    private final ObjectMapper mapper;
    private final ObservationObserver observer;
    private volatile MachineToken token;

    public PermissionManifestClient(Config config) {
        this(config, event -> {});
    }

    public PermissionManifestClient(Config config, ObservationObserver observer) {
        this(config, new ObjectMapper(JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build()), observer);
    }

    PermissionManifestClient(Config config, ObjectMapper mapper) {
        this(config, mapper, event -> {});
    }

    PermissionManifestClient(Config config, ObjectMapper mapper, ObservationObserver observer) {
        this.config = requireConfig(config);
        this.mapper = mapper;
        this.observer = observer;
        this.http =
                new OkHttpClient.Builder()
                        .retryOnConnectionFailure(false)
                        .connectTimeout(config.timeout())
                        .readTimeout(config.timeout())
                        .writeTimeout(config.timeout())
                        .callTimeout(config.timeout())
                        .build();
    }

    public Result validate(Manifest manifest) {
        var prepared = prepare(manifest, Mode.VALIDATE);
        return observed(prepared, () -> send(prepared, "/open/v1/permission-manifests:sync", null));
    }

    public Result upsert(Manifest manifest, String idempotencyKey) {
        requireIdempotencyKey(idempotencyKey);
        var prepared = prepare(manifest, Mode.UPSERT);
        return observed(prepared, () -> send(
                prepared,
                "/open/v1/permission-manifests:sync",
                idempotencyKey));
    }

    private Result observed(PreparedManifest manifest, java.util.function.Supplier<Result> command) {
        long started = System.nanoTime();
        try { Result result = command.get(); observer.record(new Observation(manifest.mode(), "SUCCESS", 200, Duration.ofNanos(System.nanoTime() - started))); return result; }
        catch (RuntimeException error) { int status = error instanceof PermissionManifestException protocol ? protocol.status() : 0; observer.record(new Observation(manifest.mode(), "ERROR", status, Duration.ofNanos(System.nanoTime() - started))); throw error; }
    }

    public void clearTokenCache() {
        token = null;
    }

    public static PreparedManifest prepare(Manifest manifest, Mode mode) {
        if (manifest == null || mode == null) throw new IllegalArgumentException("manifest and mode are required");
        if (!MANIFEST_ID.matcher(manifest.manifestId()).matches())
            throw new IllegalArgumentException("permission manifest manifestId is invalid");
        if (!REVISION.matcher(manifest.revision()).matches())
            throw new IllegalArgumentException("permission manifest revision is invalid");
        if (manifest.permissions() == null || manifest.permissions().size() > 1000)
            throw new IllegalArgumentException("permissions must contain at most 1000 declarations");
        var permissions = new ArrayList<Declaration>(manifest.permissions().size());
        for (Declaration declaration : manifest.permissions()) permissions.add(validate(declaration));
        permissions.sort(Comparator.comparing(Declaration::key));
        var keys = new HashSet<String>();
        for (Declaration declaration : permissions) {
            if (!keys.add(declaration.key()))
                throw new IllegalArgumentException("permission manifest contains a duplicate permission key");
        }
        List<Declaration> immutable = List.copyOf(permissions);
        return new PreparedManifest(
                mode.wire(),
                manifest.manifestId(),
                manifest.revision(),
                sha256(canonicalManifest(immutable)),
                immutable);
    }

    public static String declarationRevision(Declaration declaration) {
        return sha256(canonicalDeclaration(validate(declaration)));
    }

    public static StartupResult runStartup(
            PermissionManifestClient client, Manifest manifest, StartupOptions options) {
        StartupOptions effective =
                options == null
                        ? new StartupOptions(StartupMode.DISABLED, null, null, null)
                        : options;
        if (effective.mode() == StartupMode.DISABLED) return new StartupResult(false, false, null);
        if (effective.mode() == StartupMode.DEVELOPMENT_STARTUP
                && effective.failurePolicy() == null)
            throw new IllegalArgumentException(
                    "DEVELOPMENT_STARTUP requires explicit failurePolicy");
        if (effective.mode() == StartupMode.DEVELOPMENT_STARTUP
                && effective.failurePolicy() == FailurePolicy.CONTINUE
                && effective.continueHandler() == null)
            throw new IllegalArgumentException(
                    "DEVELOPMENT_STARTUP with CONTINUE requires continueHandler");
        if (client == null) throw new IllegalArgumentException("permission manifest client is required");
        try {
            Result result = switch (effective.mode()) {
                case CI_VALIDATE -> client.validate(manifest);
                case DEPLOYMENT_UPSERT ->
                        client.upsert(manifest, requiredStartupKey(effective));
                case DEVELOPMENT_STARTUP ->
                        client.upsert(manifest, requiredStartupKey(effective));
                case DISABLED -> throw new IllegalStateException("disabled startup must return before client use");
            };
            return new StartupResult(true, false, result);
        } catch (RuntimeException exception) {
            if (effective.mode() != StartupMode.DEVELOPMENT_STARTUP
                    || effective.failurePolicy() == FailurePolicy.FAIL_FAST) throw exception;
            effective.continueHandler().accept(new StartupContinuation(
                    "DEVELOPMENT_STARTUP", "CONTINUED",
                    exception instanceof PermissionManifestException protocol ? protocol.status() : 0,
                    exception instanceof PermissionManifestException protocol ? protocol.code() : "UNEXPECTED_ERROR"));
            return new StartupResult(true, true, null);
        }
    }

    private Result send(PreparedManifest manifest, String path, String idempotencyKey) {
        String json;
        try {
            json = mapper.writeValueAsString(manifest);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("unable to serialize permission manifest", exception);
        }
        CommandBudget budget = new CommandBudget(3, Instant.now().plusSeconds(15));
        MachineToken machineToken = machineToken(budget);
        var builder =
                new Request.Builder()
                        .url(config.portalApiEndpoint() + path)
                        .header("Authorization", "Bearer " + machineToken.accessToken())
                        .header("Accept", "application/json")
                        .post(RequestBody.create(json, JSON));
        if (idempotencyKey != null) builder.header("Idempotency-Key", idempotencyKey);
        try (Response response = executeWithRetry(builder.build(), budget)) {
            JsonNode body = parseBody(response);
            if (!response.isSuccessful()) throw protocolError(response, body);
            return parseResult(body, manifest);
        }
    }

    private synchronized MachineToken machineToken(CommandBudget budget) {
        if (token != null && token.expiresAt().isAfter(Instant.now())) return token;
        Request request =
                new Request.Builder()
                        .url(config.issuerEndpoint() + "/oauth2/token")
                        .header("Authorization", Credentials.basic(config.clientId(), config.clientSecret()))
                        .header("Accept", "application/json")
                        .post(
                                new FormBody.Builder()
                                        .add("grant_type", "client_credentials")
                                        .add("scope", PERMISSIONS_SYNC_SCOPE)
                                        .build())
                        .build();
        try (Response response = executeWithRetry(request, budget)) {
            JsonNode body = parseTokenBody(response);
            if (!response.isSuccessful()) throw tokenProtocolError(response, body);
            JsonNode accessTokenNode = body == null ? null : body.get("access_token");
            JsonNode tokenTypeNode = body == null ? null : body.get("token_type");
            JsonNode expires = body.get("expires_in");
            if (accessTokenNode == null || !accessTokenNode.isTextual() || accessTokenNode.textValue().isEmpty()
                    || tokenTypeNode == null || !tokenTypeNode.isTextual()
                    || !"bearer".equalsIgnoreCase(tokenTypeNode.textValue())
                    || expires == null
                    || !expires.isIntegralNumber()
                    || expires.asDouble() <= 0
                    || body.get("scope") == null
                    || !body.get("scope").isTextual()
                    || !PERMISSIONS_SYNC_SCOPE.equals(body.get("scope").textValue()))
                throw invalidResponse("INVALID_TOKEN_RESPONSE", null);
            long ttlMillis =
                    Math.max(
                            0,
                            Math.round(
                                    (expires.asDouble() - config.tokenSkew().toSeconds()) * 1000));
            token = new MachineToken(accessTokenNode.textValue(), Instant.now().plusMillis(ttlMillis));
            return token;
        }
    }

    private Response executeWithRetry(Request request, CommandBudget budget) {
        IOException lastFailure = null;
        for (int attempt = 0; attempt <= config.maxRetries(); attempt++) {
            budget.consume();
            if (Thread.currentThread().isInterrupted())
                throw new PermissionManifestException(
                        0, "REQUEST_CANCELLED", "Permission manifest request was cancelled", null, null, null);
            try {
                Response response = http.newCall(request).execute();
                if (!RETRYABLE.contains(response.code()) || attempt == config.maxRetries() || budget.empty()) return response;
                long delay = retryDelayMillis(response.header("Retry-After"), attempt);
                response.close();
                budget.pause(delay);
            } catch (IOException exception) {
                lastFailure = exception;
                if (attempt == config.maxRetries() || budget.empty()) break;
                budget.pause(Math.min(250L << attempt, config.maxRetryDelay().toMillis()));
            }
        }
        throw new PermissionManifestException(
                0,
                "TRANSPORT_ERROR",
                "Permission manifest request failed",
                null,
                null,
                lastFailure);
    }

    private long retryDelayMillis(String retryAfter, int attempt) {
        Integer seconds = parseRetryAfter(retryAfter);
        long delay = seconds == null ? 250L << attempt : seconds * 1000L;
        return Math.min(delay, config.maxRetryDelay().toMillis());
    }

    private static final class CommandBudget {
        private int attempts;
        private final Instant deadline;
        CommandBudget(int attempts, Instant deadline) { this.attempts = attempts; this.deadline = deadline; }
        void consume() {
            if (attempts == 0 || !Instant.now().isBefore(deadline))
                throw new PermissionManifestException(0, "COMMAND_TIMEOUT", "Permission manifest command budget exhausted", null, null, null);
            attempts--;
        }
        boolean empty() { return attempts == 0; }
        void pause(long millis) {
            long remaining = Duration.between(Instant.now(), deadline).toMillis();
            if (remaining <= millis) throw new PermissionManifestException(0, "COMMAND_TIMEOUT", "Permission manifest command budget exhausted", null, null, null);
            try { new CountDownLatch(1).await(millis, TimeUnit.MILLISECONDS); } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new PermissionManifestException(0, "REQUEST_CANCELLED", "Permission manifest request was cancelled", null, null, null);
            }
        }
    }

    private JsonNode parseBody(Response response) {
        try {
            String body = response.body() == null ? "" : response.body().string();
            return mapper.readTree(body);
        } catch (IOException | RuntimeException exception) {
            throw new PermissionManifestException(
                    response.code(), "INVALID_JSON_RESPONSE", "IAM returned malformed JSON", null, null, exception);
        }
    }

    private JsonNode parseTokenBody(Response response) {
        try {
            String body = response.body() == null ? "" : response.body().string();
            return mapper.readTree(body);
        } catch (IOException | RuntimeException exception) {
            throw new PermissionManifestException(
                    response.code(), "INVALID_JSON_RESPONSE", "IAM token endpoint returned malformed JSON", null, null, null);
        }
    }

    private static PermissionManifestException protocolError(Response response, JsonNode body) {
        try {
            int status = integer(body, "status");
            if (!hasOnlyFields(body, Set.of("status", "error", "message", "timestamp", "details", "correlationId")) || status != response.code()) return invalidResponse("INVALID_ERROR_RESPONSE", null);
            return new PermissionManifestException(
                    status, requiredText(body, "error"), requiredText(body, "message"),
                    optionalText(body, "correlationId"), parseRetryAfter(response.header("Retry-After")), body);
        } catch (PermissionManifestException exception) {
            return invalidResponse("INVALID_ERROR_RESPONSE", null);
        }
    }

    private static PermissionManifestException tokenProtocolError(Response response, JsonNode body) {
        if (body != null && body.isObject() && body.path("error").isTextual() && !body.path("error").textValue().isEmpty())
            return new PermissionManifestException(response.code(), body.path("error").textValue(),
                    "Permission manifest machine token request failed", null, null, null);
        return new PermissionManifestException(response.code(), "INVALID_ERROR_RESPONSE", "Invalid machine token error response", null, null, null);
    }

    private static Result parseResult(JsonNode body, PreparedManifest request) {
        if (!body.isObject()
                || !hasOnlyFields(body, Set.of("mode", "manifestId", "revision", "fingerprint", "applied", "results", "drift", "counts"))
                || !request.mode().equals(requiredText(body, "mode"))
                || !request.manifestId().equals(requiredText(body, "manifestId"))
                || !request.revision().equals(requiredText(body, "revision"))
                || !request.fingerprint().equals(requiredText(body, "fingerprint"))
                || !SHA256.matcher(requiredText(body, "fingerprint")).matches()
                || !body.path("applied").isBoolean()
                || body.path("applied").asBoolean() != "upsert".equals(request.mode())
                || !body.path("results").isArray()
                || !body.path("drift").isArray()) throw invalidResponse("INVALID_MANIFEST_RESPONSE", body);
        var items = new ArrayList<Item>();
        for (JsonNode node : body.path("results")) {
            if (!hasOnlyFields(node, Set.of("key", "operation", "reason"))) throw invalidResponse("INVALID_MANIFEST_RESPONSE", body);
            String key = requiredText(node, "key");
            String operation = requiredText(node, "operation");
            String reason = requiredText(node, "reason");
            if (!validKey(key) || !OPERATIONS.contains(operation) || !REASONS.contains(reason))
                throw invalidResponse("INVALID_MANIFEST_RESPONSE", body);
            items.add(new Item(key, operation, reason));
        }
        var drift = new ArrayList<Drift>();
        for (JsonNode node : body.path("drift")) {
            if (!hasOnlyFields(node, Set.of("key", "kind", "source"))) throw invalidResponse("INVALID_MANIFEST_RESPONSE", body);
            String key = requiredText(node, "key");
            String kind = requiredText(node, "kind");
            String source = requiredText(node, "source");
            if (!validKey(key) || !DRIFT_KINDS.contains(kind) || !SOURCES.contains(source))
                throw invalidResponse("INVALID_MANIFEST_RESPONSE", body);
            drift.add(new Drift(key, kind, source));
        }
        if (!strictlySorted(items.stream().map(Item::key).toList())
                || !strictlySorted(drift.stream().map(Drift::key).toList()))
            throw invalidResponse("INVALID_MANIFEST_RESPONSE", body);
        JsonNode countsNode = body.path("counts");
        if (!hasOnlyFields(countsNode, Set.of("created", "updated", "unchanged", "resurrected", "conflict", "drift"))) throw invalidResponse("INVALID_MANIFEST_RESPONSE", body);
        Counts counts =
                new Counts(
                        integer(countsNode, "created"),
                        integer(countsNode, "updated"),
                        integer(countsNode, "unchanged"),
                        integer(countsNode, "resurrected"),
                        integer(countsNode, "conflict"),
                        integer(countsNode, "drift"));
        if (counts.created() != count(items, "CREATE")
                || counts.updated() != count(items, "UPDATE")
                || counts.unchanged() != count(items, "UNCHANGED")
                || counts.resurrected() != count(items, "RESURRECT")
                || counts.conflict() != count(items, "CONFLICT")
                || counts.drift() != drift.size())
            throw invalidResponse("INVALID_MANIFEST_RESPONSE", body);
        return new Result(
                request.mode(),
                request.manifestId(),
                request.revision(),
                request.fingerprint(),
                body.path("applied").asBoolean(),
                List.copyOf(items),
                List.copyOf(drift),
                counts);
    }

    private static Declaration validate(Declaration value) {
        if (value == null
                || value.resource() == null
                || value.action() == null
                || !SEGMENT.matcher(value.resource()).matches()
                || !SEGMENT.matcher(value.action()).matches())
            throw new IllegalArgumentException("permission manifest contains an invalid concrete permission key");
        validateText(value.name(), 128, "name");
        if (value.description() != null) validateText(value.description(), 512, "description");
        requireNfc(value.resource(), "resource");
        requireNfc(value.action(), "action");
        requireNfc(value.name(), "name");
        if (value.description() != null) requireNfc(value.description(), "description");
        return value;
    }

    private static void validateText(String value, int max, String field) {
        if (value == null
                || value.isEmpty()
                || value.length() > max
                || !value.equals(value.strip())
                || value.chars().anyMatch(Character::isISOControl))
            throw new IllegalArgumentException("permission manifest " + field + " is invalid");
    }

    private static void requireNfc(String value, String field) {
        if (!Normalizer.isNormalized(value, Normalizer.Form.NFC))
            throw new IllegalArgumentException("permission manifest " + field + " must already be NFC");
    }

    private static byte[] canonicalManifest(List<Declaration> permissions) {
        var json = new StringBuilder("{\"permissions\":[");
        for (int index = 0; index < permissions.size(); index++) {
            if (index > 0) json.append(',');
            json.append(new String(canonicalDeclaration(permissions.get(index)), StandardCharsets.UTF_8));
        }
        return json.append("]}").toString().getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] canonicalDeclaration(Declaration declaration) {
        var json = new StringBuilder("{\"action\":");
        appendString(json, declaration.action());
        json.append(",\"description\":");
        if (declaration.description() == null) json.append("null");
        else appendString(json, declaration.description());
        json.append(",\"name\":");
        appendString(json, declaration.name());
        json.append(",\"resource\":");
        appendString(json, declaration.resource());
        return json.append('}').toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void appendString(StringBuilder json, String value) {
        json.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (Character.isHighSurrogate(character)) {
                if (index + 1 == value.length() || !Character.isLowSurrogate(value.charAt(index + 1)))
                    throw new IllegalArgumentException("JCS string contains an unpaired surrogate");
                json.append(character).append(value.charAt(++index));
                continue;
            }
            if (Character.isLowSurrogate(character))
                throw new IllegalArgumentException("JCS string contains an unpaired surrogate");
            switch (character) {
                case '"' -> json.append("\\\"");
                case '\\' -> json.append("\\\\");
                case '\b' -> json.append("\\b");
                case '\f' -> json.append("\\f");
                case '\n' -> json.append("\\n");
                case '\r' -> json.append("\\r");
                case '\t' -> json.append("\\t");
                default -> {
                    if (character <= 0x1f) json.append(String.format("\\u%04x", (int) character));
                    else json.append(character);
                }
            }
        }
        json.append('"');
    }

    private static String sha256(byte[] value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            var result = new StringBuilder(64);
            for (byte item : digest) result.append(String.format("%02x", item));
            return result.toString();
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static Config requireConfig(Config value) {
        if (value == null) throw new IllegalArgumentException("permission manifest config is required");
        return value.validated();
    }

    private static void requireIdempotencyKey(String value) {
        if (value == null || !IDEMPOTENCY.matcher(value).matches())
            throw new IllegalArgumentException("Idempotency-Key must be 8-128 visible ASCII characters");
    }

    private static String requiredStartupKey(StartupOptions options) {
        requireIdempotencyKey(options.idempotencyKey());
        return options.idempotencyKey();
    }

    private static int count(List<Item> items, String operation) {
        return Math.toIntExact(items.stream().filter(item -> operation.equals(item.operation())).count());
    }

    private static boolean strictlySorted(List<String> values) {
        for (int index = 1; index < values.size(); index++)
            if (values.get(index - 1).compareTo(values.get(index)) >= 0) return false;
        return true;
    }

    private static boolean validKey(String key) {
        String[] parts = key.split(":", -1);
        return parts.length == 2
                && SEGMENT.matcher(parts[0]).matches()
                && SEGMENT.matcher(parts[1]).matches();
    }

    private static boolean hasOnlyFields(JsonNode node, Set<String> allowed) {
        if (node == null || !node.isObject()) return false;
        var names = node.fieldNames();
        while (names.hasNext()) if (!allowed.contains(names.next())) return false;
        return true;
    }

    private static String requiredText(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        if (value == null || !value.isTextual() || value.textValue().isEmpty())
            throw invalidResponse("INVALID_MANIFEST_RESPONSE", node);
        return value.textValue();
    }

    private static String text(JsonNode node, String field, String fallback) {
        JsonNode value = node == null ? null : node.get(field);
        return value != null && value.isTextual() && !value.textValue().isEmpty()
                ? value.textValue()
                : fallback;
    }

    private static String optionalText(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        return value != null && value.isTextual() && !value.textValue().isEmpty()
                ? value.textValue()
                : null;
    }

    private static int integer(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        if (value == null || !value.isIntegralNumber() || !value.canConvertToInt() || value.intValue() < 0)
            throw invalidResponse("INVALID_MANIFEST_RESPONSE", node);
        return value.intValue();
    }

    static Integer parseRetryAfter(String value) {
        if (value == null || !value.matches("[1-9][0-9]{0,4}")) return null;
        int seconds = Integer.parseInt(value);
        return seconds <= 86_400 ? seconds : null;
    }

    private static PermissionManifestException invalidResponse(String code, Object details) {
        return new PermissionManifestException(0, code, "Invalid IAM response", null, null, details);
    }

    public enum Mode {
        VALIDATE("validate"),
        UPSERT("upsert");

        private final String wire;

        Mode(String wire) {
            this.wire = wire;
        }

        String wire() {
            return wire;
        }
    }

    public enum StartupMode {
        DISABLED,
        CI_VALIDATE,
        DEPLOYMENT_UPSERT,
        DEVELOPMENT_STARTUP
    }

    public enum FailurePolicy {
        FAIL_FAST,
        CONTINUE
    }

    public record Declaration(String resource, String action, String name, String description) {
        public String key() {
            return resource + ":" + action;
        }
    }

    public record Manifest(String manifestId, String revision, List<Declaration> permissions) {}

    public record PreparedManifest(
            String mode,
            String manifestId,
            String revision,
            String fingerprint,
            List<Declaration> permissions) {}

    public record Item(String key, String operation, String reason) {}

    public record Drift(String key, String kind, String source) {}

    public record Counts(
            int created,
            int updated,
            int unchanged,
            int resurrected,
            int conflict,
            int drift) {}

    public record Result(
            String mode,
            String manifestId,
            String revision,
            String fingerprint,
            boolean applied,
            List<Item> results,
            List<Drift> drift,
            Counts counts) {}

    public record Observation(String mode, String outcome, int status, Duration duration) {}
    @FunctionalInterface public interface ObservationObserver { void record(Observation observation); }

    public record StartupContinuation(String mode, String outcome, int status, String code) {}
    public record StartupResult(boolean networkAttempted, boolean continued, Result result) {}

    public record StartupOptions(
            StartupMode mode,
            FailurePolicy failurePolicy,
            String idempotencyKey,
            java.util.function.Consumer<StartupContinuation> continueHandler) {}

    public record Config(
            String issuerEndpoint,
            String portalApiEndpoint,
            String clientId,
            String clientSecret,
            Duration timeout,
            Duration tokenSkew,
            int maxRetries,
            Duration maxRetryDelay) {
        public Config(
                String issuerEndpoint,
                String portalApiEndpoint,
                String clientId,
                String clientSecret) {
            this(
                    issuerEndpoint,
                    portalApiEndpoint,
                    clientId,
                    clientSecret,
                    Duration.ofSeconds(5),
                    Duration.ofSeconds(30),
                    2,
                    Duration.ofSeconds(5));
        }

        Config validated() {
            if (timeout != null && timeout.compareTo(Duration.ofSeconds(5)) > 0)
                throw new IllegalArgumentException("permission manifest timeout exceeds five seconds");
            return new Config(
                    endpoint(issuerEndpoint, "issuerEndpoint"),
                    endpoint(portalApiEndpoint, "portalApiEndpoint"),
                    required(clientId, "clientId"),
                    required(clientSecret, "clientSecret"),
                    positive(timeout, "timeout"),
                    nonNegative(tokenSkew, "tokenSkew"),
                    nonNegative(maxRetries, "maxRetries"),
                    positive(maxRetryDelay, "maxRetryDelay"));
        }

        private static String endpoint(String value, String field) {
            String result = required(value, field);
            while (result.endsWith("/")) result = result.substring(0, result.length() - 1);
            return result;
        }

        private static String required(String value, String field) {
            if (value == null || value.isBlank())
                throw new IllegalArgumentException("permission manifest " + field + " is required");
            return value.strip();
        }

        private static Duration positive(Duration value, String field) {
            if (value == null || value.isZero() || value.isNegative())
                throw new IllegalArgumentException("permission manifest " + field + " must be positive");
            return value;
        }

        private static Duration nonNegative(Duration value, String field) {
            if (value == null || value.isNegative())
                throw new IllegalArgumentException(
                        "permission manifest " + field + " must be non-negative");
            return value;
        }

        private static int nonNegative(int value, String field) {
            if (value < 0)
                throw new IllegalArgumentException(
                        "permission manifest " + field + " must be non-negative");
            return value;
        }
    }

    public static final class PermissionManifestException extends RuntimeException {
        private final int status;
        private final String code;
        private final String correlationId;
        private final Integer retryAfterSeconds;
        private final Object details;

        PermissionManifestException(
                int status,
                String code,
                String message,
                String correlationId,
                Integer retryAfterSeconds,
                Object details) {
            super(message, details instanceof Throwable throwable ? throwable : null);
            this.status = status;
            this.code = code;
            this.correlationId = correlationId;
            this.retryAfterSeconds = retryAfterSeconds;
            this.details = details;
        }

        public int status() {
            return status;
        }

        public String code() {
            return code;
        }

        public String correlationId() {
            return correlationId;
        }

        public Integer retryAfterSeconds() {
            return retryAfterSeconds;
        }

        public Object details() {
            return details;
        }
    }

    private record MachineToken(String accessToken, Instant expiresAt) {}
}
