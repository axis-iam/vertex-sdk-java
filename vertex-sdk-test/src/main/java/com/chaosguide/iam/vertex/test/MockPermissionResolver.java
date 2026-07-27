package com.chaosguide.iam.vertex.test;

import com.chaosguide.iam.vertex.authz.PermissionResolver;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * 单元测试用的内存版 {@link PermissionResolver}。
 *
 * <p>通过 {@link #given(String)} 配置角色到权限的映射，用来模拟 IAM 的权限解析结果。
 *
 * <pre>
 * var resolver = new MockPermissionResolver();
 * resolver.given("admin").hasPermissions("posts:read", "posts:write");
 * resolver.given("viewer").hasPermissions("posts:read");
 * </pre>
 */
public class MockPermissionResolver implements PermissionResolver {

    private final Map<String, Set<String>> rolePermissions = new LinkedHashMap<>();

    public Binding given(String role) {
        return new Binding(role);
    }

    public void clear() {
        rolePermissions.clear();
    }

    @Override
    public Set<String> resolve(String appId, Set<String> roles) {
        if (roles == null || roles.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> out = new LinkedHashSet<>();
        for (String role : roles) {
            // 多角色权限取并集，和真实 resolver 的语义一致。
            out.addAll(rolePermissions.getOrDefault(role, Set.of()));
        }
        return out;
    }

    public final class Binding {
        private final String role;

        private Binding(String role) {
            this.role = role;
        }

        /** 为当前 role 追加一组权限。 */
        public MockPermissionResolver hasPermissions(String... perms) {
            rolePermissions.computeIfAbsent(role, k -> new LinkedHashSet<>())
                    .addAll(Set.of(perms));
            return MockPermissionResolver.this;
        }
    }
}
