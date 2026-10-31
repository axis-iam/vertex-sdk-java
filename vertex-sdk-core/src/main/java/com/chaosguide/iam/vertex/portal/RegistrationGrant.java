package com.chaosguide.iam.vertex.portal;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;

/** Safe registration-grant representation. Raw create proofs are never part of this type. */
public record RegistrationGrant(
        String id,
        @JsonProperty(value = "version", required = true) @JsonSetter(nulls = Nulls.FAIL) long version,
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
        String revokeReason) {
    public RegistrationGrant {
        if (version < 0) throw new IllegalArgumentException("Invalid registration grant version");
    }
}
