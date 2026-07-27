package com.chaosguide.iam.vertex.client.dto;

/**
 * Organization invitation accept result. {@code LOGIN_REQUIRED} is a continuation state, not a
 * generic SDK error.
 */
public record PublicOrganizationInvitationAcceptResponse(
        String status,
        String continuation,
        String applicationId,
        String organizationId,
        String organizationName,
        String role,
        String acceptedAt) {
}
