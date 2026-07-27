package com.chaosguide.iam.vertex.client.dto;

import java.util.Set;

/** 运行时权限解析响应，permissions 使用 Spring Security authority 直接可用的 {@code resource:action} 格式。 */
public record ResolveResponse(Set<String> permissions) {
    public ResolveResponse {
        permissions = permissions == null ? Set.of() : Set.copyOf(permissions);
    }
}
