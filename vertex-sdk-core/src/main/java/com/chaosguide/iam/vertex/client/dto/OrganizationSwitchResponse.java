package com.chaosguide.iam.vertex.client.dto;

/**
 * Current Organization switch result.
 */
public record OrganizationSwitchResponse(
        String organizationId,
        String continuation,
        boolean tokenRefreshRequired,
        String message) {
}
