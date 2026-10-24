package com.chaosguide.iam.vertex.client.dto;

/**
 * Safe scalar profile update request for {@code PATCH /api/v1/auth/me/profile}.
 */
public record AccountUpdateProfileRequest(
        String displayName,
        String avatarUrl) {
}
