package com.chaosguide.iam.vertex.client.dto;

/**
 * Public, safe Organization invitation preview. The raw invitation token is never represented here.
 */
public record PublicOrganizationInvitationPreviewResponse(
        String applicationId,
        String applicationName,
        String organizationId,
        String organizationName,
        String inviteeEmail,
        String role,
        String status,
        String expiresAt) {
}
