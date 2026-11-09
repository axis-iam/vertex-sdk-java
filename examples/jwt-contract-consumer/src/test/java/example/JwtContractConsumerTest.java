package example;

import com.chaosguide.iam.vertex.EnableIamSecurity;
import com.chaosguide.iam.vertex.authz.PermissionResolver;
import com.chaosguide.iam.vertex.context.IamContext;
import com.chaosguide.iam.vertex.jwt.IamJwtAuthenticationConverter;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = JwtContractConsumerTest.App.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JwtContractConsumerTest {
    private static final String AUDIENCE = "api://clean-consumer";
    private static final String CLIENT_ID = "consumer-confidential-client";
    private static final String APP_ID = "11111111-1111-4111-8111-111111111111";
    private static final AtomicInteger RESOLVES = new AtomicInteger();
    private static MockWebServer iam;
    private static RSAKey key;
    @LocalServerPort int port;

    @BeforeAll
    static void startIam() throws Exception {
        key = new RSAKeyGenerator(2048).keyID("consumer-key").generate();
        iam = new MockWebServer();
        iam.setDispatcher(new Dispatcher() {
            @Override public MockResponse dispatch(RecordedRequest request) {
                if (!"/oauth2/jwks".equals(request.getPath())) {
                    return new MockResponse().setResponseCode(404);
                }
                return new MockResponse().setHeader("Content-Type", "application/json")
                        .setBody(new JWKSet(key.toPublicJWK()).toString());
            }
        });
        iam.start();
    }

    @AfterAll static void stopIam() throws Exception { iam.shutdown(); }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("iam.sdk.endpoint", JwtContractConsumerTest::issuer);
        registry.add("iam.sdk.resource-audience", () -> AUDIENCE);
        registry.add("iam.sdk.client-id", () -> CLIENT_ID);
        registry.add("iam.sdk.client-secret", () -> "fixture-secret");
    }

    @Test
    void candidateEnforcesSignedResourceContractOverRealHttp() throws Exception {
        assertThat(Runtime.version().feature()).isEqualTo(17);
        assertThat(AUDIENCE).isNotEqualTo(CLIENT_ID).isNotEqualTo(APP_ID);
        HttpResponse<String> valid = call(sign(issuer(), AUDIENCE, APP_ID, List.of("reader")));
        assertThat(valid.statusCode()).isEqualTo(200);
        assertThat(valid.body()).isEqualTo(APP_ID);
        int acceptedResolves = RESOLVES.get();
        assertThat(acceptedResolves).isEqualTo(1);
        assertThat(call(sign("https://wrong-issuer.invalid", AUDIENCE, APP_ID, List.of("reader")))
                .statusCode()).isEqualTo(401);
        assertThat(call(sign(issuer(), CLIENT_ID, APP_ID, List.of("reader"))).statusCode()).isEqualTo(401);
        assertThat(call(sign(issuer(), AUDIENCE, null, List.of())).statusCode()).isEqualTo(401);
        assertThat(call(sign(issuer(), AUDIENCE, "   ", List.of())).statusCode()).isEqualTo(401);
        assertThat(RESOLVES.get()).isEqualTo(acceptedResolves);
        assertThat(HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                        URI.create("http://localhost:" + port + "/contract")).GET().build(),
                HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(401);
        System.out.println("CONTRACT: Java17; signed valid issuer/resourceAudience/app_id -> 200; " +
                "wrong issuer/clientId-as-aud/missing-or-blank-app_id/no-token -> 401; resolver saw app_id only");
    }

    private HttpResponse<String> call(String token) throws Exception {
        return HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                        URI.create("http://localhost:" + port + "/contract"))
                .header("Authorization", "Bearer " + token).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String issuer() { return iam.url("/").toString().replaceAll("/+$", ""); }

    private static String sign(String issuer, String audience, String appId, List<String> roles) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                new JWTClaimsSet.Builder().subject("fixture-user").issuer(issuer).audience(audience)
                        .claim("app_id", appId).claim("roles", roles)
                        .issueTime(Date.from(Instant.now()))
                        .expirationTime(Date.from(Instant.now().plusSeconds(300))).build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @EnableIamSecurity
    @Import(Api.class)
    static class App {
        @Bean PermissionResolver permissionResolver() {
            return (appId, roles) -> {
                assertThat(appId).isEqualTo(APP_ID);
                assertThat(roles).containsExactly("reader");
                RESOLVES.incrementAndGet();
                return Set.of("contract:read");
            };
        }

        @Bean SecurityFilterChain chain(HttpSecurity http, IamJwtAuthenticationConverter converter) throws Exception {
            http.csrf(AbstractHttpConfigurer::disable)
                    .authorizeHttpRequests(auth -> auth.anyRequest().hasAuthority("contract:read"))
                    .oauth2ResourceServer(resource -> resource.jwt(jwt -> jwt.jwtAuthenticationConverter(converter)));
            return http.build();
        }
    }

    @RestController
    static class Api {
        @GetMapping("/contract") String contract() {
            return IamContext.requireCurrentUser().applicationId();
        }
    }
}
