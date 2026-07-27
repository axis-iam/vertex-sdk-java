package com.chaosguide.iam.vertex.authz;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HighRiskGuardAspectTest {

    public static class Target {
        @RequireStepUp
        public String defaultMfa() { return "mfa"; }

        @RequireStepUp(acr = "urn:iam:acr:phishing-resistant")
        public String phishingResistant() { return "strong"; }

        @RequireNoImpersonation
        public String directOnly() { return "direct"; }
    }

    @RequireStepUp(acr = "urn:iam:acr:mfa")
    public static class ClassGuardedTarget {
        public String call() { return "class"; }
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void allowsWhenAcrMatchesDefaultMfa() {
        authenticate("urn:iam:acr:mfa", null);

        assertThat(proxy(new Target()).defaultMfa()).isEqualTo("mfa");
    }

    @Test
    void allowsCustomAcr() {
        authenticate("urn:iam:acr:phishing-resistant", null);

        assertThat(proxy(new Target()).phishingResistant()).isEqualTo("strong");
    }

    @Test
    void deniesWhenAcrMissingOrDifferent() {
        authenticate(null, null);

        assertThatThrownBy(() -> proxy(new Target()).defaultMfa())
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("urn:iam:acr:mfa");
    }

    @Test
    void allowsClassLevelStepUpGuard() {
        authenticate("urn:iam:acr:mfa", null);

        assertThat(proxy(new ClassGuardedTarget()).call()).isEqualTo("class");
    }

    @Test
    void allowsDirectUserForNoImpersonationGuard() {
        authenticate("urn:iam:acr:mfa", null);

        assertThat(proxy(new Target()).directOnly()).isEqualTo("direct");
    }

    @Test
    void deniesImpersonatedUserForNoImpersonationGuard() {
        authenticate("urn:iam:acr:mfa", Map.of("sub", "admin-1"));

        assertThatThrownBy(() -> proxy(new Target()).directOnly())
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Impersonated sessions");
    }

    @Test
    void deniesWhenSecurityContextDoesNotContainJwt() {
        TestingAuthenticationToken auth = new TestingAuthenticationToken("user-1", "N/A", List.of());
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertThatThrownBy(() -> proxy(new Target()).defaultMfa())
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Authentication required");
    }

    private static <T> T proxy(T target) {
        AspectJProxyFactory factory = new AspectJProxyFactory(target);
        factory.addAspect(new HighRiskGuardAspect());
        return factory.getProxy();
    }

    private static void authenticate(String acr, Object actor) {
        Jwt.Builder builder = Jwt.withTokenValue("access-token")
                .header("alg", "none")
                .subject("user-1")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300));
        if (acr != null) {
            builder.claim("acr", acr);
        }
        if (actor != null) {
            builder.claim("act", actor);
        }
        SecurityContextHolder.getContext()
                .setAuthentication(new JwtAuthenticationToken(builder.build(), List.of()));
    }
}
