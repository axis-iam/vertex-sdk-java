package com.chaosguide.iam.vertex.test;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class MockPermissionResolverTest {

    @Test
    void returnsEmptySetWhenNoRolesProvided() {
        MockPermissionResolver resolver = new MockPermissionResolver();
        resolver.given("admin").hasPermissions("posts:read");

        assertThat(resolver.resolve("app-1", Set.of())).isEmpty();
        assertThat(resolver.resolve("app-1", null)).isEmpty();
    }

    @Test
    void returnsPermissionsForSingleRole() {
        MockPermissionResolver resolver = new MockPermissionResolver();
        resolver.given("admin").hasPermissions("posts:read", "posts:write");

        assertThat(resolver.resolve("app-1", Set.of("admin")))
                .containsExactlyInAnyOrder("posts:read", "posts:write");
    }

    @Test
    void unionsPermissionsAcrossMultipleRoles() {
        MockPermissionResolver resolver = new MockPermissionResolver();
        resolver.given("admin").hasPermissions("posts:write");
        resolver.given("viewer").hasPermissions("posts:read");

        assertThat(resolver.resolve("app-1", Set.of("admin", "viewer")))
                .containsExactlyInAnyOrder("posts:read", "posts:write");
    }

    @Test
    void returnsEmptyForUnknownRole() {
        MockPermissionResolver resolver = new MockPermissionResolver();
        resolver.given("admin").hasPermissions("posts:read");

        assertThat(resolver.resolve("app-1", Set.of("ghost"))).isEmpty();
    }

    @Test
    void clearRemovesAllBindings() {
        MockPermissionResolver resolver = new MockPermissionResolver();
        resolver.given("admin").hasPermissions("posts:read");

        resolver.clear();

        assertThat(resolver.resolve("app-1", Set.of("admin"))).isEmpty();
    }

    @Test
    void bindingIsAdditive() {
        MockPermissionResolver resolver = new MockPermissionResolver();
        resolver.given("admin").hasPermissions("posts:read");
        resolver.given("admin").hasPermissions("posts:write");

        assertThat(resolver.resolve("app-1", Set.of("admin")))
                .containsExactlyInAnyOrder("posts:read", "posts:write");
    }

    @Test
    void bindingReturnsResolverForChaining() {
        MockPermissionResolver resolver = new MockPermissionResolver();

        MockPermissionResolver chained = resolver.given("a").hasPermissions("a:r")
                .given("b").hasPermissions("b:r");

        assertThat(chained).isSameAs(resolver);
    }
}
