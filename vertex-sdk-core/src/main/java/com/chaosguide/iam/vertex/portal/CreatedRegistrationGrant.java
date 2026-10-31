package com.chaosguide.iam.vertex.portal;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import java.net.URI;

/** One-time create/rotate material, or a replay with no secret reissued. */
public record CreatedRegistrationGrant(
        RegistrationGrant grant,
        String registrationGrantToken,
        String registrationAccessCode,
        String registrationInvitationUrl,
        @JsonProperty(value = "secretAlreadyIssued", required = true) @JsonSetter(nulls = Nulls.FAIL) boolean secretAlreadyIssued) {
    public CreatedRegistrationGrant {
        boolean hasToken = registrationGrantToken != null && !registrationGrantToken.isBlank();
        boolean hasCode = registrationAccessCode != null && !registrationAccessCode.isBlank();
        boolean hasUrl = registrationInvitationUrl != null && !registrationInvitationUrl.isBlank();
        if (grant == null || grant.type() == null
                || (grant.type() != RegistrationGrantType.EMAIL_LINK && grant.type() != RegistrationGrantType.ACCESS_CODE)
                || (secretAlreadyIssued
                    ? registrationGrantToken != null || registrationAccessCode != null || registrationInvitationUrl != null
                    : grant.type() == RegistrationGrantType.EMAIL_LINK
                        ? !hasToken || !hasUrl || registrationAccessCode != null
                        : !hasCode || registrationGrantToken != null || registrationInvitationUrl != null)) {
            throw new IllegalArgumentException("Invalid registration grant create response");
        }
        if (hasUrl) {
            URI uri = URI.create(registrationInvitationUrl);
            if (!("https".equals(uri.getScheme()) || "http".equals(uri.getScheme()))
                    || uri.getHost() == null || uri.getUserInfo() != null || uri.getFragment() != null) {
                throw new IllegalArgumentException("Invalid registration invitation URL");
            }
        }
    }
}
