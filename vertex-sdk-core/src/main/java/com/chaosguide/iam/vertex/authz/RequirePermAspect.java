package com.chaosguide.iam.vertex.authz;

import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/** 拦截 {@link RequirePerm} 注解，把枚举常量解析为权限字符串后检查当前 Spring Security 身份。 */
@Aspect
public class RequirePermAspect {

    /** 注解里的 enum constant 到 {@code resource:action} 的转换结果是稳定的，可以缓存起来。 */
    private final ConcurrentMap<Key, PermissionKey> permissionCache = new ConcurrentHashMap<>();

    @Before("@annotation(require)")
    public void checkMethod(RequirePerm require) {
        check(require);
    }

    @Before("@within(require)")
    public void checkClass(RequirePerm require) {
        check(require);
    }

    private void check(RequirePerm require) {
        PermissionKey permission = permissionFor(require);
        String authority = permission.toAuthority();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new AccessDeniedException("Authentication required for " + authority);
        }
        boolean granted = auth.getAuthorities().stream()
                .anyMatch(a -> PermissionMatcher.matches(permission, a.getAuthority()));
        if (!granted) {
            throw new AccessDeniedException("Missing permission: " + authority);
        }
    }

    private PermissionKey permissionFor(RequirePerm require) {
        Key key = new Key(require.value(), require.name());
        return permissionCache.computeIfAbsent(key, this::resolve);
    }

    private PermissionKey resolve(Key key) {
        Class<? extends PermissionDefinition> clazz = key.clazz;
        if (!clazz.isEnum()) {
            throw new IllegalStateException(clazz + " must be an enum implementing PermissionDefinition");
        }
        // name 使用字符串是 Java 注解限制导致的折中：注解参数不能直接传 enum 常量的动态类型。
        for (PermissionDefinition constant : clazz.getEnumConstants()) {
            Enum<?> e = (Enum<?>) constant;
            if (e.name().equals(key.name)) {
                return constant.key();
            }
        }
        throw new IllegalStateException("No enum constant " + key.name + " on " + clazz.getName());
    }

    private record Key(Class<? extends PermissionDefinition> clazz, String name) {
    }
}
