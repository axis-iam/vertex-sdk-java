package com.chaosguide.iam.vertex.client.dto;

/** IAM 接口层的一条权限声明，最终会组合成 {@code resource:action}。 */
public record PermissionDto(String resource, String action, String description) {
    public PermissionDto(String resource, String action) {
        this(resource, action, "");
    }
}
