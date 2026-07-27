package com.chaosguide.iam.vertex.client.dto;

/**
 * Current user's Application-scoped Organization membership.
 */
public record AccountOrganizationResponse(
        String organizationId,
        String name,
        String slug,
        String role,
        String joinedAt,
        boolean current) {
}
