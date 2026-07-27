package com.chaosguide.iam.vertex.portal;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Request for a manually created EMAIL_LINK or ACCESS_CODE registration grant. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CreateRegistrationGrantRequest(
        CreateRegistrationGrantType type,
        String displayName,
        String allowedEmail,
        String allowedDomain,
        String expiresAt,
        Integer maxUses) {
    public CreateRegistrationGrantRequest {
        if (type == null) {
            throw new IllegalArgumentException("Registration grant type is required");
        }
    }
}
