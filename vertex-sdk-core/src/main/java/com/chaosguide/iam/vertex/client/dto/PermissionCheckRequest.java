package com.chaosguide.iam.vertex.client.dto;

/**
 * Request body for current-user permission checks.
 */
public record PermissionCheckRequest(String permission, String organizationId) {
}
