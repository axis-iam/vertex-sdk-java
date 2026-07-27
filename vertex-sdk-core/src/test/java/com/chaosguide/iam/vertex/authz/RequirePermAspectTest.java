package com.chaosguide.iam.vertex.authz;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RequirePermAspectTest {

    enum Perms implements PermissionDefinition {
        POSTS_READ("posts", "read");

        private final PermissionKey key;

        Perms(String resource, String action) {
            this.key = new PermissionKey(resource, action);
        }

        @Override public PermissionKey key() { return key; }
    }

    public static class Target {
        @RequirePerm(value = Perms.class, name = "POSTS_READ")
        public String read() { return "ok"; }

        @RequirePerm(value = Perms.class, name = "DOES_NOT_EXIST")
        public String broken() { return "nope"; }
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private Target proxy() {
        AspectJProxyFactory factory = new AspectJProxyFactory(new Target());
        factory.addAspect(new RequirePermAspect());
        return factory.getProxy();
    }

    @Test
    void allowsWhenAuthorityMatches() {
        authenticate("posts:read");

        assertThat(proxy().read()).isEqualTo("ok");
    }

    @Test
    void allowsResourceWildcard() {
        authenticate("posts:*");
        assertThat(proxy().read()).isEqualTo("ok");
    }

    @Test
    void allowsGlobalWildcard() {
        authenticate("*:*");
        assertThat(proxy().read()).isEqualTo("ok");
    }

    @Test
    void deniesWhenAuthorityMissing() {
        authenticate("posts:write");

        assertThatThrownBy(() -> proxy().read())
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("posts:read");
    }

    @Test
    void deniesResourceWildcardWithWrongResource() {
        authenticate("users:*");
        assertThatThrownBy(() -> proxy().read()).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void deniesUnsupportedResourceAgnosticActionWildcard() {
        authenticate("*:read");
        assertThatThrownBy(() -> proxy().read()).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void deniesWhenAuthMissing() {
        SecurityContextHolder.clearContext();

        assertThatThrownBy(() -> proxy().read())
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Authentication required");
    }

    @Test
    void throwsOnUnknownEnumConstant() {
        authenticate("posts:read");

        assertThatThrownBy(() -> proxy().broken())
                .isInstanceOf(IllegalStateException.class);
    }

    private static void authenticate(String authority) {
        TestingAuthenticationToken auth = new TestingAuthenticationToken("u", "p",
                List.of(new SimpleGrantedAuthority(authority)));
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
