package com.chaosguide.iam.vertex.client.dto;

import java.util.List;

/**
 * Current-user permission check result returned by IAM.
 */
public record PermissionCheckResponse(
        String applicationId,
        String organizationId,
        String permission,
        boolean allowed,
        List<String> roles) {

    public PermissionCheckResponse {
        roles = roles == null ? List.of() : List.copyOf(roles);
    }
}
