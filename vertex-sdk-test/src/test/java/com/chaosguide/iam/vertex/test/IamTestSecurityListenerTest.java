package com.chaosguide.iam.vertex.test;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.TestContext;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import static org.assertj.core.api.Assertions.assertThat;

class IamTestSecurityListenerTest {

    private final IamTestSecurityListener listener = new IamTestSecurityListener();

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @IamTestSecurity(username = "alice",
            roles = {"admin"},
            permissions = {"posts:read", "posts:write"})
    static class MethodFixture {
        void target() {}
    }

    @IamTestSecurity(permissions = {"class-level:perm"})
    static class ClassLevelFixture {
        void target() {}
    }

    static class NoAnnotationFixture {
        void target() {}
    }

    static class DefaultsFixture {
        @IamTestSecurity
        void target() {}
    }

    @Test
    void injectsPrincipalAndAuthoritiesFromMethodAnnotation() throws Exception {
        TestContext ctx = mockContextFor(MethodFixture.class);

        listener.beforeTestMethod(ctx);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        assertThat(auth).isNotNull();
        assertThat(auth.isAuthenticated()).isTrue();
        assertThat(auth.getName()).isEqualTo("alice");
        assertThat(auth.getAuthorities())
                .extracting(Object::toString)
                .containsExactlyInAnyOrder("ROLE_admin", "posts:read", "posts:write");
    }

    @Test
    void honorsClassLevelAnnotation() throws Exception {
        TestContext ctx = mockContextFor(ClassLevelFixture.class);

        listener.beforeTestMethod(ctx);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        assertThat(auth).isNotNull();
        assertThat(auth.getAuthorities())
                .extracting(Object::toString)
                .containsExactly("class-level:perm");
    }

    @Test
    void usesDefaultUsernameAndEmptyAuthorities() throws Exception {
        TestContext ctx = mockContextFor(DefaultsFixture.class);

        listener.beforeTestMethod(ctx);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        assertThat(auth).isNotNull();
        assertThat(auth.getName()).isEqualTo("test-user");
        assertThat(auth.getAuthorities()).isEmpty();
    }

    @Test
    void leavesContextEmptyWhenNotAnnotated() throws Exception {
        TestContext ctx = mockContextFor(NoAnnotationFixture.class);

        listener.beforeTestMethod(ctx);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void afterTestMethodClearsContext() throws Exception {
        TestContext ctx = mockContextFor(MethodFixture.class);
        listener.beforeTestMethod(ctx);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();

        listener.afterTestMethod(ctx);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    private static TestContext mockContextFor(Class<?> testClass) throws NoSuchMethodException {
        Method m = testClass.getDeclaredMethod("target");
        return (TestContext) Proxy.newProxyInstance(
                TestContext.class.getClassLoader(),
                new Class<?>[] {TestContext.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getTestClass" -> testClass;
                    case "getTestMethod" -> m;
                    case "hasAttribute" -> false;
                    case "attributeNames" -> new String[0];
                    case "removeAttribute" -> null;
                    case "toString" -> "TestContext(" + testClass.getName() + "#" + m.getName() + ")";
                    default -> defaultValue(method.getReturnType());
                });
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == char.class) {
            return '\0';
        }
        if (type == byte.class) {
            return (byte) 0;
        }
        if (type == short.class) {
            return (short) 0;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == float.class) {
            return 0F;
        }
        if (type == double.class) {
            return 0D;
        }
        return null;
    }
}
