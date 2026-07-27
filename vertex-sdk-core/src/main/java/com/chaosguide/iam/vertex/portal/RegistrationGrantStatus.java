package com.chaosguide.iam.vertex.portal;

/** Safe registration-grant lifecycle states returned by iam-portal. */
public enum RegistrationGrantStatus {
    ACTIVE,
    PAUSED,
    REDEEMED,
    EXPIRED,
    REVOKED
}
