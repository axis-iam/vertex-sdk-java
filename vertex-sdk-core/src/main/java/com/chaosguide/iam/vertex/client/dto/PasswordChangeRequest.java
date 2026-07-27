package com.chaosguide.iam.vertex.client.dto;

/**
 * Authenticated password-change request.
 */
public record PasswordChangeRequest(String currentPassword, String newPassword) {
}
