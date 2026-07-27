package com.chaosguide.iam.vertex.client.dto;

import java.util.List;

/** 权限快照响应，供 Gradle 同步任务生成本地权限枚举。 */
public record PermissionListResponse(List<PermissionDto> permissions, String etag) {
    public PermissionListResponse {
        permissions = permissions == null ? List.of() : List.copyOf(permissions);
    }
}
