package com.chaosguide.iam.vertex.client.dto;

import java.util.Set;

/** 运行时权限解析请求：IAM 根据 {@code ApplicationClient.clientId} 和 JWT 中的角色集合返回最终权限。 */
public record ResolveRequest(String clientId, Set<String> roles) {
}
