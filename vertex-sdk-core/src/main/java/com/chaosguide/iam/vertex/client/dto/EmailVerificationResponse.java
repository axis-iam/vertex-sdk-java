package com.chaosguide.iam.vertex.client.dto;

/**
 * Public email verification send/verify response.
 */
public record EmailVerificationResponse(String message, Integer retryAfterSeconds) {
}
