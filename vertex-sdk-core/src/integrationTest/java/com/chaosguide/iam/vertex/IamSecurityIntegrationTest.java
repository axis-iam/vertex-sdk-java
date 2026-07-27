package com.chaosguide.iam.vertex;

import com.chaosguide.iam.vertex.authz.DefinesPermission;
import com.chaosguide.iam.vertex.authz.PermissionDefinition;
import com.chaosguide.iam.vertex.authz.PermissionKey;
import com.chaosguide.iam.vertex.authz.RequireNoImpersonation;
import com.chaosguide.iam.vertex.authz.RequirePerm;
import com.chaosguide.iam.vertex.authz.RequireStepUp;
import com.chaosguide.iam.vertex.jwt.IamJwtAuthenticationConverter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEObjectType;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = {
        IamSecurityIntegrationTest.TestApp.class,
        IamSecurityIntegrationTest.Sec.class,
        IamSecurityIntegrationTest.Api.class
})
@AutoConfigureMockMvc
class IamSecurityIntegrationTest {

    private static MockWebServer server;
    private static RSAKey signingKey;
    private static final AtomicInteger resolveCount = new AtomicInteger(0);

    @BeforeAll
    static void start() throws Exception {
        server = new MockWebServer();
        signingKey = new RSAKeyGenerator(2048).keyID("itest-kid").generate();
        ObjectMapper mapper = new ObjectMapper();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest req) {
                String path = req.getPath() == null ? "" : req.getPath();
                try {
                    if (path.endsWith("/oauth2/jwks")) {
                        return new MockResponse()
                                .setHeader("Content-Type", "application/json")
                                .setBody(new JWKSet(signingKey.toPublicJWK()).toString());
                    }
                    if (path.endsWith("/open/v1/permissions:resolve")) {
                        resolveCount.incrementAndGet();
                        ObjectNode body = mapper.createObjectNode();
                        ArrayNode arr = body.putArray("permissions");
                        var node = mapper.readTree(req.getBody().readUtf8());
                        node.path("roles").forEach(r -> {
                            if ("admin".equals(r.asText())) {
                                arr.add("posts:read");
                                arr.add("posts:write");
                            } else if ("viewer".equals(r.asText())) {
                                arr.add("posts:read");
                            }
                        });
                        return new MockResponse()
                                .setHeader("Content-Type", "application/json")
                                .setBody(mapper.writeValueAsString(body));
                    }
                } catch (Exception e) {
                    return new MockResponse().setResponseCode(500);
                }
                return new MockResponse().setResponseCode(404);
            }
        });
        server.start();
    }

    @AfterAll
    static void stop() throws Exception {
        if (server != null) server.shutdown();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        String base = server.url("/").toString().replaceAll("/+$", "");
        registry.add("iam.sdk.endpoint", () -> base);
        registry.add("iam.sdk.client-id", () -> "integration-test-app");
        registry.add("iam.sdk.client-secret", () -> "secret");
    }

    @Autowired MockMvc mvc;

    @Test
    void rejectsWithoutToken() throws Exception {
        mvc.perform(get("/posts")).andExpect(status().isUnauthorized());
    }

    @Test
    void allowsWithTokenHavingResolvedPermission() throws Exception {
        String token = issueToken("alice", Set.of("admin"));
        mvc.perform(get("/posts").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void deniesWhenResolvedPermissionMissing() throws Exception {
        String token = issueToken("bob", Set.of("viewer"));
        mvc.perform(get("/admin/purge").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void allowsHighRiskRouteWhenMfaAndNotImpersonating() throws Exception {
        String token = issueToken("alice", Set.of("admin"), "urn:iam:acr:mfa", null);
        mvc.perform(get("/transfer").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void deniesHighRiskRouteWhenStepUpMissing() throws Exception {
        String token = issueToken("alice", Set.of("admin"));
        mvc.perform(get("/transfer").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void deniesHighRiskRouteWhenImpersonating() throws Exception {
        String token = issueToken("alice", Set.of("admin"), "urn:iam:acr:mfa", "admin-1");
        mvc.perform(get("/transfer").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    private static String issueToken(String subject, Set<String> roles) throws Exception {
        return issueToken(subject, roles, null, null);
    }

    private static String issueToken(String subject, Set<String> roles, String acr, String actorSubject) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(signingKey.getKeyID())
                .type(JOSEObjectType.JWT)
                .build();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .subject(subject)
                .audience("integration-test-app")
                .issuer(server.url("/").toString().replaceAll("/+$", ""))
                .claim("roles", List.copyOf(new LinkedHashSet<>(roles)))
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(600)));
        if (acr != null) {
            claims.claim("acr", acr);
        }
        if (actorSubject != null) {
            claims.claim("act", Map.of("sub", actorSubject));
        }
        SignedJWT jwt = new SignedJWT(header, claims.build());
        jwt.sign(new RSASSASigner(signingKey.toPrivateKey()));
        return jwt.serialize();
    }

    @SpringBootApplication
    @EnableIamSecurity
    static class TestApp {
    }

    @Configuration
    static class Sec {
        @Bean SecurityFilterChain chain(HttpSecurity http, IamJwtAuthenticationConverter conv) throws Exception {
            http.csrf(AbstractHttpConfigurer::disable)
                    .authorizeHttpRequests(a -> a.anyRequest().authenticated())
                    .oauth2ResourceServer(o -> o.jwt(j -> j.jwtAuthenticationConverter(conv)));
            return http.build();
        }
    }

    @RestController
    static class Api {
        @GetMapping("/posts")
        @RequirePerm(value = Perms.class, name = "POSTS_READ")
        String list() { return "[]"; }

        @GetMapping("/admin/purge")
        @RequirePerm(value = Perms.class, name = "ADMIN_PURGE")
        String purge() { return "purged"; }

        @GetMapping("/transfer")
        @RequireStepUp(acr = "urn:iam:acr:mfa")
        @RequireNoImpersonation
        String transfer() { return "ok"; }
    }

    enum Perms implements PermissionDefinition {
        @DefinesPermission(resource = "posts", action = "read") POSTS_READ,
        @DefinesPermission(resource = "admin", action = "purge") ADMIN_PURGE;

        @Override public PermissionKey key() {
            try {
                DefinesPermission a = Perms.class.getField(name()).getAnnotation(DefinesPermission.class);
                return new PermissionKey(a.resource(), a.action());
            } catch (NoSuchFieldException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
