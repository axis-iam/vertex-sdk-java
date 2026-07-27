package com.chaosguide.iam.vertex.context;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.nio.file.Files;
import java.nio.file.Path;
import com.fasterxml.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

class IamContextTest {

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void currentBuildsUserFromJwtAndAuthorities() {
        Jwt jwt =
                Jwt.withTokenValue("access-token")
                        .header("alg", "none")
                        .subject("user-1")
                        .audience(List.of("aud-client"))
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(300))
                        .claim("app_id", "app-1")
                        .claim("email", "user@example.com")
                        .claim("email_verified", true)
                        .claim("username", "alice")
                        .claim("org_id", "org-1")
                        .claim("org_slug", "acme")
                        .claim("org_role", "ADMIN")
                        .claim("workspace_id", "workspace-1")
                        .claim("sid", "session-1")
                        .claim("roles", List.of("admin"))
                        .claim("amr", List.of("pwd", "mfa"))
                        .claim("acr", "urn:iam:acr:mfa")
                        .claim("act", Map.of("sub", "admin-1"))
                        .build();
        var auth =
                new JwtAuthenticationToken(
                        jwt,
                        List.of(
                                new SimpleGrantedAuthority("ROLE_admin"),
                                new SimpleGrantedAuthority("orders:*")));
        SecurityContextHolder.getContext().setAuthentication(auth);

        IamContext context = IamContext.requireCurrent();
        IamCurrentUser user = context.user();

        assertThat(user.subject()).isEqualTo("user-1");
        assertThat(context.getUserId()).isEqualTo("user-1");
        assertThat(context.getEmail()).isEqualTo("user@example.com");
        assertThat(user.applicationId()).isEqualTo("app-1");
        assertThat(user.email()).isEqualTo("user@example.com");
        assertThat(user.username()).isEqualTo("alice");
        assertThat(user.roles()).containsExactly("admin");
        assertThat(user.permissions()).containsExactly("orders:*");
        assertThat(user.hasPermission("orders", "read")).isTrue();
        assertThat(user.hasMfa()).isTrue();
        assertThat(user.isImpersonating()).isTrue();
        assertThat(user.actor().subject()).isEqualTo("admin-1");
        assertThat(IamContext.currentAccessToken()).contains("access-token");
    }

    @Test
    void currentReturnsEmptyWhenNoJwtAuthentication() {
        assertThat(IamContext.currentOptional()).isEmpty();
        assertThat(IamContext.currentAccessToken()).isEmpty();
    }

    @Test
    void consumesSharedWildcardVectors() throws Exception {
        var fixture = new ObjectMapper().readTree(Files.readString(
                Path.of("../../docs/fixtures/permission-manifest-vectors.json")));
        for (var vector : fixture.path("codeGeneration").path("wildcardMatch")) {
            String[] target = vector.path("target").textValue().split(":", -1);
            var user = new IamCurrentUser(
                    "user", "app", null, false, null, null, null, null, null, null,
                    Set.of(), Set.of(vector.path("granted").textValue()), List.of(), null, null, Map.of());
            assertThat(user.hasPermission(target[0], target[1]))
                    .as(vector.path("granted").textValue() + " -> " + vector.path("target").textValue())
                    .isEqualTo(vector.path("matches").booleanValue());
        }
    }
}
