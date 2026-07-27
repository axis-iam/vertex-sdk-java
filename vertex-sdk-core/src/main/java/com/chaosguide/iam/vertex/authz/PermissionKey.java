package com.chaosguide.iam.vertex.authz;

import java.util.Objects;

/** 不可变的权限标识，统一用 {@code resource:action} 表示，并直接作为 Spring Security authority。 */
public record PermissionKey(String resource, String action) {

    public PermissionKey {
        Objects.requireNonNull(resource, "resource");
        Objects.requireNonNull(action, "action");
        if (resource.isBlank() || action.isBlank()) {
            throw new IllegalArgumentException("resource and action must be non-blank");
        }
    }

    public String toAuthority() {
        return resource + ":" + action;
    }

    /** 从 authority 字符串反向解析权限 key；格式不合法时尽早失败，避免生成半截权限。 */
    public static PermissionKey parse(String authority) {
        Objects.requireNonNull(authority, "authority");
        int idx = authority.indexOf(':');
        if (idx <= 0 || idx == authority.length() - 1) {
            throw new IllegalArgumentException("invalid authority: " + authority);
        }
        return new PermissionKey(authority.substring(0, idx), authority.substring(idx + 1));
    }

    @Override
    public String toString() {
        // 日志和断言中直接输出标准 authority，避免 record 默认格式干扰排查。
        return toAuthority();
    }
}
