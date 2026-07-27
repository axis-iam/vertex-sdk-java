package com.chaosguide.iam.vertex.portal;

/** Safe registration-grant representation. Raw create proofs are never part of this type. */
public record RegistrationGrant(
        String id,
        RegistrationGrantType type,
        RegistrationGrantStatus status,
        String displayName,
        String allowedEmail,
        String allowedDomain,
        String expiresAt,
        Integer maxUses,
        int usedCount,
        String sourceType,
        String createdAt,
        String updatedAt,
        String revokedAt,
        String revokeReason) {}
