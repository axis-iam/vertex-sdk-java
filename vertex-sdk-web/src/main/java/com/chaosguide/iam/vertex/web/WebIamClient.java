package com.chaosguide.iam.vertex.web;

import com.chaosguide.iam.vertex.client.dto.CurrentUserResponse;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.util.UriComponentsBuilder;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.MediaType;
import okhttp3.Response;
import okio.BufferedSink;
import java.util.concurrent.TimeUnit;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.HashSet;
import java.security.NoSuchAlgorithmException;
import java.util.Set;
import java.util.stream.Collectors;

/** Bounded IAM transport. Spring supplies OAuth request conversion and OIDC/JWK verification. */
public final class WebIamClient implements AutoCloseable {
    public static final class Budget {
        private final long end;
        public Budget(Duration duration) {
            if (duration == null || duration.isNegative() || duration.isZero() || duration.compareTo(Duration.ofMinutes(1)) > 0)
                throw new IllegalArgumentException("Positive bounded request budget required");
            end = System.nanoTime() + duration.toNanos();
        }
        Duration remaining() {
            long n = end - System.nanoTime();
            if (n <= 0) throw new WebSessionException(503, "IAM_UNAVAILABLE");
            return Duration.ofNanos(Math.min(n, Duration.ofSeconds(5).toNanos()));
        }
    }
    public record Tokens(@JsonIgnore String access, @JsonIgnore String refresh, Instant accessExpiresAt,
            @JsonIgnore String subject, @JsonIgnore String nonce) {
        @Override public String toString() { return "Tokens[redacted]"; }
    }
    public record Identity(ObjectNode profile, ObjectNode permissions, Instant absolute, Instant idle, Instant access) {
        public Identity { profile = profile.deepCopy(); permissions = permissions.deepCopy(); }
        @Override public ObjectNode profile() { return profile.deepCopy(); }
        @Override public ObjectNode permissions() { return permissions.deepCopy(); }
    }
    private final WebBffConfig config;
    private final HttpClient http;
    private final OkHttpClient transport;
    private final ClientRegistration registration;
    private final NimbusJwtDecoder idDecoder;
    private final String authorizeEndpoint;
    private final ThreadLocal<Budget> verificationBudget = new ThreadLocal<>();

    public WebIamClient(WebBffConfig config) {
        this.config = config;
        http = HttpClient.newBuilder().connectTimeout(config.upstreamTimeout()).followRedirects(HttpClient.Redirect.NEVER).build();
        transport = new OkHttpClient.Builder().connectTimeout(config.upstreamTimeout())
                .readTimeout(config.upstreamTimeout()).callTimeout(config.upstreamTimeout())
                .retryOnConnectionFailure(false).followRedirects(false).followSslRedirects(false)
                .addNetworkInterceptor(chain -> {
                    Response response=chain.proceed(chain.request());
                    // OkHttp 4.12 may otherwise follow 503 Retry-After:0 even with connection retries disabled.
                    return response.code()==503 ? response.newBuilder().removeHeader("Retry-After").build() : response;
                }).build();
        ObjectNode discovery = request("GET", "/.well-known/openid-configuration", null, Map.of(), new Budget(config.authBudget()));
        if (!config.issuer().toString().equals(WebWire.text(discovery, "issuer"))) throw WebSessionException.protocol();
        authorizeEndpoint = endpoint(discovery, "authorization_endpoint");
        String token = endpoint(discovery, "token_endpoint");
        String jwks = endpoint(discovery, "jwks_uri");
        JsonNode algorithms = discovery.get("id_token_signing_alg_values_supported");
        WebWire.strings(algorithms);
        Set<String> allowed = new HashSet<>();
        algorithms.forEach(a -> { if (Set.of("RS256", "ES256").contains(a.textValue())) allowed.add(a.textValue()); });
        if (allowed.isEmpty()) throw WebSessionException.protocol();
        registration = ClientRegistration.withRegistrationId("axis-vertex-web")
                .clientId(config.clientId()).clientSecret(config.clientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(config.callback().toString()).scope(config.scopes())
                .authorizationUri(authorizeEndpoint).tokenUri(token).jwkSetUri(jwks)
                .issuerUri(config.issuer().toString()).build();
        RestTemplate jwkTransport = new RestTemplate((uri,method) -> {
            Budget current = verificationBudget.get();
            if (current == null) throw new IllegalStateException("OIDC verification requires a request budget");
            JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(http);
            factory.setReadTimeout(current.remaining());
            return factory.createRequest(uri,method);
        });
        idDecoder = NimbusJwtDecoder.withJwkSetUri(jwks).restOperations(jwkTransport)
                .jwsAlgorithms(a -> { a.clear(); allowed.forEach(s -> a.add(SignatureAlgorithm.from(s))); }).build();
        idDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(config.issuer().toString()), new OidcIdTokenValidator(registration)));
    }
    private Jwt decodeId(String encoded, Budget budget) {
        verificationBudget.set(budget);
        try { Jwt verified=idDecoder.decode(encoded); budget.remaining(); return verified; }
        finally { verificationBudget.remove(); }
    }
    @Override public void close() {
        transport.dispatcher().executorService().shutdownNow(); transport.connectionPool().evictAll();
    }
    private String endpoint(ObjectNode discovery, String key) {
        URI value = URI.create(WebWire.text(discovery, key));
        WebBffConfig.validateOrigin(value, config.developmentLoopback());
        if (!sameOrigin(value, config.issuer())) throw WebSessionException.protocol();
        return value.toString();
    }
    private static boolean sameOrigin(URI a, URI b) {
        return a.getScheme().equals(b.getScheme()) && a.getHost().equals(b.getHost()) && a.getPort() == b.getPort();
    }
    public String authorization(String state, String verifier, String nonce) {
        return UriComponentsBuilder.fromUriString(authorizeEndpoint).queryParam("response_type", "code")
                .queryParam("client_id", config.clientId()).queryParam("redirect_uri", config.callback())
                .queryParam("scope", String.join(" ", config.scopes())).queryParam("state", state)
                .queryParam("code_challenge", challenge(verifier)).queryParam("code_challenge_method", "S256")
                .queryParam("nonce", nonce).build().encode().toUriString();
    }
    public static String challenge(String verifier) {
        try { return Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII))); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException("SHA-256 unavailable"); }
    }
    public Tokens exchange(String code, ObjectNode prelogin, Budget budget) {
        String state = WebWire.text(prelogin, "stateBinding");
        OAuth2AuthorizationRequest auth = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(authorizeEndpoint).clientId(config.clientId()).redirectUri(config.callback().toString())
                .scopes(config.scopes()).state(state).attributes(a -> a.put("code_verifier", WebWire.text(prelogin, "verifier"))).build();
        OAuth2AuthorizationResponse response = OAuth2AuthorizationResponse.success(code).state(state)
                .redirectUri(config.callback().toString()).build();
        RequestEntity<?> req = new OAuth2AuthorizationCodeGrantRequestEntityConverter().convert(
                new OAuth2AuthorizationCodeGrantRequest(registration, new OAuth2AuthorizationExchange(auth, response)));
        ObjectNode result = tokenRequest(req, budget);
        Jwt id;
        try { id = decodeId(WebWire.text(result, "id_token"),budget); }
        catch (JwtException e) { throw WebSessionException.protocol(); }
        if (!WebWire.text(prelogin, "nonce").equals(id.getClaimAsString("nonce"))) throw WebSessionException.protocol();
        return tokens(result, null, id.getSubject(), WebWire.text(prelogin, "nonce"));
    }
    public Tokens refresh(Tokens previous, Budget budget) {
        OAuth2AccessToken access = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, previous.access(),
                previous.accessExpiresAt().minusSeconds(3600), previous.accessExpiresAt());
        RequestEntity<?> request = new OAuth2RefreshTokenGrantRequestEntityConverter().convert(
                new OAuth2RefreshTokenGrantRequest(registration, access, new OAuth2RefreshToken(previous.refresh(), null)));
        ObjectNode result = tokenRequest(request, budget);
        if (result.has("id_token")) {
            try {
                Jwt id = decodeId(WebWire.text(result,"id_token"),budget);
                if (!previous.subject().equals(id.getSubject())
                        || (id.hasClaim("nonce") && !previous.nonce().equals(id.getClaimAsString("nonce"))))
                    throw WebSessionException.protocol();
            } catch (JwtException e) { throw WebSessionException.protocol(); }
        }
        return tokens(result, previous.refresh(), previous.subject(), previous.nonce());
    }
    private Tokens tokens(ObjectNode result, String oldRefresh, String subject, String nonce) {
        String access = WebWire.text(result, "access_token");
        if (!"Bearer".equalsIgnoreCase(WebWire.text(result, "token_type")) || !result.path("expires_in").isIntegralNumber()
                || !result.path("expires_in").canConvertToInt() || result.path("expires_in").intValue() <= 0
                || (result.has("scope") && !result.get("scope").isTextual())) throw WebSessionException.protocol();
        String refresh = result.has("refresh_token") ? WebWire.text(result, "refresh_token") : null;
        if (oldRefresh != null && (refresh == null || refresh.equals(oldRefresh))) throw WebSessionException.protocol();
        return new Tokens(access, refresh, Instant.now().plusSeconds(result.path("expires_in").intValue()), subject, nonce);
    }
    private ObjectNode tokenRequest(RequestEntity<?> req, Budget budget) {
        if (!(req.getBody() instanceof MultiValueMap<?, ?> form)) throw WebSessionException.protocol();
        String body = form.entrySet().stream().flatMap(e -> e.getValue().stream()
                .map(v -> encode(e.getKey().toString()) + "=" + encode(v.toString()))).collect(Collectors.joining("&"));
        Request.Builder builder = new Request.Builder().url(req.getUrl().toString())
                .post(oneShot(body,MediaType.get("application/x-www-form-urlencoded")));
        req.getHeaders().forEach((k,v) -> v.forEach(x -> builder.addHeader(k,x)));
        return send(builder.build(),budget);
    }
    static String encode(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }
    public ObjectNode request(String method, String path, ObjectNode body, Map<String,String> headers, Budget budget) {
        if (!path.startsWith("/") || path.startsWith("//")) throw new IllegalArgumentException("Fixed IAM path required");
        Request.Builder b = new Request.Builder().url(config.issuer().resolve(path).toString()).header("Accept","application/json");
        headers.forEach(b::header);
        b.method(method,body == null ? null : oneShot(body.toString(),MediaType.get("application/json")));
        return send(b.build(),budget);
    }
    private static RequestBody oneShot(String encoded, MediaType type) {
        byte[] bytes=encoded.getBytes(StandardCharsets.UTF_8);
        return new RequestBody() {
            @Override public MediaType contentType() { return type; }
            @Override public long contentLength() { return bytes.length; }
            @Override public boolean isOneShot() { return true; }
            @Override public void writeTo(BufferedSink sink) throws IOException { sink.write(bytes); }
        };
    }
    private ObjectNode send(Request req, Budget budget) {
        var call = transport.newCall(req);
        call.timeout().timeout(budget.remaining().toNanos(), TimeUnit.NANOSECONDS);
        try (Response response = call.execute()) {
            if (response.body() == null) throw WebSessionException.protocol();
            byte[] bytes = response.body().byteStream().readNBytes(262145);
            if (bytes.length > 262144) throw WebSessionException.protocol();
            int status = response.code();
            if (status < 200 || status >= 300) {
                if (status >= 500) throw new WebSessionException(503, "IAM_UNAVAILABLE");
                if (status == 429) {
                    String retry = response.header("Retry-After", "");
                    Integer delay = retry.matches("[0-9]{1,9}") ? Integer.valueOf(retry) : null;
                    throw new WebSessionException(429, "RATE_LIMITED", delay);
                }
                if (status < 400) throw WebSessionException.protocol();
                ObjectNode err = bytes.length == 0 ? WebWire.object() : WebWire.parse(bytes);
                String code = err.path("error").asText();
                if (!code.matches("[A-Za-z][A-Za-z0-9_]{0,127}")) code = "IAM_REQUEST_REJECTED";
                throw new WebSessionException(status, code);
            }
            if (bytes.length == 0) return WebWire.object();
            if (!response.header("Content-Type", "").startsWith("application/json"))
                throw WebSessionException.protocol();
            return WebWire.parse(bytes);
        } catch (IOException e) { throw new WebSessionException(503, "IAM_UNAVAILABLE"); }
    }
    public Identity identity(Tokens tokens, Budget budget) {
        ObjectNode profile = request("GET", "/api/v1/auth/me", null, bearer(tokens), budget);
        CurrentUserResponse user;
        try { user = CurrentUserResponse.fromJson(profile); }
        catch (IllegalArgumentException e) { throw WebSessionException.protocol(); }
        if (!user.id().equals(tokens.subject())) throw WebSessionException.protocol();
        WebWire.uuid(profile,"id"); WebWire.uuid(profile.get("authenticationContext"),"applicationId");
        if (!config.clientId().equals(user.authenticationContext().clientId())) throw WebSessionException.protocol();
        profile=SafeSessionView.profileProjection(profile);
        ObjectNode permissions = request("GET", "/api/v1/auth/me/permissions" +
                (user.authenticationContext().organizationId() == null ? "" : "?organizationId=" +
                WebWire.uuid(profile.get("authenticationContext"), "organizationId")), null, bearer(tokens), budget);
        SafeSessionView.permissions(profile, permissions);
        return validity(profile, SafeSessionView.permissionProjection(permissions), tokens, budget);
    }
    public Identity validity(ObjectNode profile, ObjectNode permissions, Tokens tokens, Budget budget) {
        ObjectNode v = request("GET", "/api/v1/auth/session/validity", null, bearer(tokens), budget);
        JsonNode c = profile.path("authenticationContext");
        for (String key : Set.of("sessionId", "clientId", "applicationId"))
            if (!WebWire.text(c, key).equals(WebWire.text(v, key))) throw WebSessionException.protocol();
        Instant absolute = WebWire.time(v,"expiresAt"), idle = WebWire.time(v,"idleExpiresAt"), access = WebWire.time(v,"accessExpiresAt");
        if (!absolute.isAfter(Instant.now()) || !idle.isAfter(Instant.now()) || !access.isAfter(Instant.now()))
            throw new WebSessionException(401, "SESSION_INVALIDATED");
        return new Identity(profile, permissions, absolute, idle, WebWire.min(access, tokens.accessExpiresAt()));
    }
    private Map<String,String> bearer(Tokens t) { return Map.of("Authorization", "Bearer " + t.access()); }
    public String logout(Tokens t, Budget budget) {
        if (t.accessExpiresAt().isAfter(Instant.now())) {
            ObjectNode body = WebWire.object(); if (t.refresh() != null) body.put("refresh_token", t.refresh());
            request("POST", "/api/v1/auth/logout", body, bearer(t), budget); return "SESSION_REVOKED";
        }
        if (t.refresh() == null) return "NOT_ATTEMPTED";
        String basic = Base64.getEncoder().encodeToString((encode(config.clientId()) + ":" + encode(config.clientSecret()))
                .getBytes(StandardCharsets.UTF_8));
        send(new Request.Builder().url(config.issuer().resolve("/oauth2/revoke").toString())
                .header("Authorization", "Basic " + basic).header("Content-Type", "application/x-www-form-urlencoded")
                .post(oneShot("token=" + encode(t.refresh()) + "&token_type_hint=refresh_token",
                        MediaType.get("application/x-www-form-urlencoded"))).build(),budget);
        return "REFRESH_FAMILY_REVOKED";
    }
}
