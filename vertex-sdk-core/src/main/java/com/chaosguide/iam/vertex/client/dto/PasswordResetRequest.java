package com.chaosguide.iam.vertex.client.dto;

/**
 * Public password-reset completion request.
 */
public record PasswordResetRequest(String token, String newPassword) {
}
