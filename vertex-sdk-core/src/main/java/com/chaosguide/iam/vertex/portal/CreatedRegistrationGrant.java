package com.chaosguide.iam.vertex.portal;

/** A newly created grant and the only copy of its type-matched raw proof. */
public record CreatedRegistrationGrant(
        RegistrationGrant grant,
        String registrationGrantToken,
        String registrationAccessCode) {
    public CreatedRegistrationGrant {
        boolean hasToken = registrationGrantToken != null && !registrationGrantToken.isBlank();
        boolean hasCode = registrationAccessCode != null && !registrationAccessCode.isBlank();
        if (grant == null || grant.type() == null || hasToken == hasCode
                || (grant.type() != RegistrationGrantType.EMAIL_LINK && grant.type() != RegistrationGrantType.ACCESS_CODE)
                || (grant.type() == RegistrationGrantType.EMAIL_LINK && !hasToken)
                || (grant.type() == RegistrationGrantType.ACCESS_CODE && !hasCode)) {
            throw new IllegalArgumentException("Invalid registration grant create response");
        }
    }
}
