package com.chaosguide.iam.vertex.jwt;

import com.chaosguide.iam.vertex.IamSecurityProperties;
import com.chaosguide.iam.vertex.authz.PermissionResolver;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IamJwtAuthenticationConverterTest {
    private static final String APP_ID = "11111111-1111-4111-8111-111111111111";
    private final IamSecurityProperties props = defaultProps();

    @Test
    void rolesOnly_resolvesPermissionsViaResolver() {
        PermissionResolver resolver = (appId, roles) -> Set.of("posts:read", "posts:write");
        IamJwtAuthenticationConverter converter = new IamJwtAuthenticationConverter(resolver, props);
        AbstractAuthenticationToken token = converter.convert(jwt(Map.of(
                "roles", List.of("admin"), "app_id", APP_ID, "aud", List.of("api://business"),
                "permissions", List.of("untrusted:claim"))));
        assertThat(names(token.getAuthorities())).containsExactlyInAnyOrder(
                "ROLE_admin", "posts:read", "posts:write");
    }

    @Test
    void noRolesWithAppIdReturnsEmptyWithoutResolverCall() {
        PermissionResolver resolver = (appId, roles) -> { throw new AssertionError("resolver called"); };
        IamJwtAuthenticationConverter converter = new IamJwtAuthenticationConverter(resolver, props);
        assertThat(converter.convert(jwt(Map.of("app_id", APP_ID))).getAuthorities()).isEmpty();
    }

    @Test
    void appIdAloneIsPassedToResolverRegardlessOfAudienceAndClientId() {
        AtomicInteger calls = new AtomicInteger();
        PermissionResolver resolver = (appId, roles) -> {
            assertThat(appId).isEqualTo(APP_ID);
            assertThat(roles).containsExactly("admin");
            calls.incrementAndGet();
            return Set.of();
        };
        IamJwtAuthenticationConverter converter = new IamJwtAuthenticationConverter(resolver, props);
        converter.convert(jwt(Map.of("roles", List.of("admin"), "app_id", APP_ID,
                "aud", List.of("api://resource-one", "api://resource-two"))));
        converter.convert(jwt(Map.of("roles", List.of("admin"), "app_id", APP_ID)));
        assertThat(calls).hasValue(2);
    }

    @Test
    void missingBlankAndMalformedAppIdNeverFallBackEvenWithoutRoles() {
        PermissionResolver resolver = (appId, roles) -> { throw new AssertionError("resolver called"); };
        IamJwtAuthenticationConverter converter = new IamJwtAuthenticationConverter(resolver, props);
        for (List<String> roles : List.of(List.of("admin"), List.<String>of())) {
            Map<String, Object> claims = new HashMap<>();
            claims.put("roles", roles);
            claims.put("aud", List.of("api://business"));
            assertInvalid(converter, claims);
            for (Object invalid : List.of("", "   ", 42, List.of(APP_ID))) {
                claims.put("app_id", invalid);
                assertInvalid(converter, claims);
            }
        }
    }

    private static void assertInvalid(IamJwtAuthenticationConverter converter, Map<String, Object> claims) {
        assertThatThrownBy(() -> converter.convert(jwt(claims)))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, failure ->
                        assertThat(failure.getError().getErrorCode()).isEqualTo("invalid_token"));
    }

    private static IamSecurityProperties defaultProps() {
        IamSecurityProperties p = new IamSecurityProperties();
        p.setEndpoint("http://iam");
        p.setClientId("configured-client");
        p.setResourceAudience("api://business");
        return p;
    }

    private static Jwt jwt(Map<String, Object> claims) {
        Map<String, Object> c = new HashMap<>(claims);
        c.putIfAbsent("sub", "user-1");
        return new Jwt("test-token", Instant.now(), Instant.now().plusSeconds(60), Map.of("alg", "RS256"), c);
    }

    private static List<String> names(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream().map(GrantedAuthority::getAuthority).toList();
    }
}
