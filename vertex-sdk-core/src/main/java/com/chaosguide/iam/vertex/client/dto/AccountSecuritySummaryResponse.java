package com.chaosguide.iam.vertex.client.dto;

/**
 * Secret-free current-user security summary for account-center UI.
 */
public record AccountSecuritySummaryResponse(
        boolean emailVerified,
        boolean passwordCredentialPresent,
        boolean mfaEnrolled,
        boolean totpEnrolled,
        boolean webAuthnEnrolled,
        int activeSessionCount) {
}
