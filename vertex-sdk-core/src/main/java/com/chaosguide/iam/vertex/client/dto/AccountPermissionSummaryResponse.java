package com.chaosguide.iam.vertex.client.dto;

import java.util.List;

/**
 * Current-user permission summary resolved by IAM for the active or explicit Organization context.
 */
public record AccountPermissionSummaryResponse(
        String applicationId,
        String organizationId,
        List<String> roles,
        List<String> permissions) {

    public AccountPermissionSummaryResponse {
        roles = roles == null ? List.of() : List.copyOf(roles);
        permissions = permissions == null ? List.of() : List.copyOf(permissions);
    }
}
