package com.chaosguide.iam.vertex.portal;

/** Safe Organization invitation detail. It never contains a raw invitation redemption proof. */
public record OpenOrganizationInvitation(
        String id,
        String email,
        OrganizationMemberRole role,
        OrganizationInvitationStatus status,
        OrganizationInvitationDeliveryStatus deliveryStatus,
        String expiresAt,
        String createdAt,
        String updatedAt) {}
