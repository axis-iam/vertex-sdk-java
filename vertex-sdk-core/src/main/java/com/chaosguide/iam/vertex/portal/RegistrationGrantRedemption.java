package com.chaosguide.iam.vertex.portal;

/** Safe, masked registration-grant redemption history entry. */
public record RegistrationGrantRedemption(
        String id,
        String result,
        String email,
        String authMethod,
        String idpId,
        String clientId,
        String redeemedAt,
        String failureReason) {}
