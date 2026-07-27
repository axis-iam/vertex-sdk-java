package com.chaosguide.iam.vertex.jwt;

import com.chaosguide.iam.vertex.IamSecurityProperties;
import com.chaosguide.iam.vertex.authz.PermissionResolver;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class IamJwtAuthenticationConverterTest {

    private final IamSecurityProperties props = defaultProps();

    @Test
    void rolesOnly_resolvesPermissionsViaResolver() {
        PermissionResolver resolver = (appId, roles) -> Set.of("posts:read", "posts:write");
        IamJwtAuthenticationConverter converter = new IamJwtAuthenticationConverter(resolver, props);

        Jwt jwt = jwt(Map.of("roles", List.of("admin"), "aud", List.of("my-app")));

        AbstractAuthenticationToken token = converter.convert(jwt);

        assertThat(names(token.getAuthorities()))
                .contains("ROLE_admin", "posts:read", "posts:write");
    }

    @Test
    void noRoles_returnsEmpty() {
        PermissionResolver resolver = (appId, roles) -> Set.of("should-not-be-called");
        IamJwtAuthenticationConverter converter = new IamJwtAuthenticationConverter(resolver, props);

        Jwt jwt = jwt(Map.of());

        AbstractAuthenticationToken token = converter.convert(jwt);

        assertThat(token.getAuthorities()).isEmpty();
    }

    @Test
    void audClaimIsPassedToResolverAsAppId() {
        boolean[] called = {false};
        PermissionResolver resolver = (appId, roles) -> {
            assertThat(appId).isEqualTo("my-app-xxx");
            called[0] = true;
            return Set.of();
        };
        IamJwtAuthenticationConverter converter = new IamJwtAuthenticationConverter(resolver, props);

        converter.convert(jwt(Map.of(
                "roles", List.of("admin"),
                "aud", List.of("my-app-xxx"))));

        assertThat(called[0]).isTrue();
    }

    @Test
    void audMissing_fallsBackToConfiguredClientId() {
        boolean[] called = {false};
        PermissionResolver resolver = (appId, roles) -> {
            assertThat(appId).isEqualTo("configured-app");
            called[0] = true;
            return Set.of();
        };
        IamJwtAuthenticationConverter converter = new IamJwtAuthenticationConverter(resolver, props);

        converter.convert(jwt(Map.of("roles", List.of("admin"))));

        assertThat(called[0]).isTrue();
    }

    private static IamSecurityProperties defaultProps() {
        IamSecurityProperties p = new IamSecurityProperties();
        p.setEndpoint("http://iam");
        p.setClientId("configured-app");
        return p;
    }

    private static Jwt jwt(Map<String, Object> claims) {
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "RS256");
        Map<String, Object> c = new HashMap<>(claims);
        c.putIfAbsent("sub", "user-1");
        return new Jwt("token", Instant.now(), Instant.now().plusSeconds(60), headers, c);
    }

    private static List<String> names(java.util.Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
    }
}
