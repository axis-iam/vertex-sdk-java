package com.chaosguide.iam.vertex.client.dto;

/**
 * Response shape returned by {@code GET /api/v1/auth/me/profile}.
 *
 * <p>Authorization roles and permissions belong to {@link AccountPermissionSummaryResponse},
 * not the profile. Nullable profile values are preserved as returned by IAM.
 *
 * @param email nullable primary EMAIL projection; users without email are valid
 * @param username nullable primary USERNAME projection
 */
public record UserProfileResponse(
        String userId,
        String applicationId,
        String globalIdentityId,
        String email,
        boolean emailVerified,
        String username,
        String displayName,
        String avatarUrl,
        String status,
        String createdAt,
        String updatedAt,
        AccountOrganizationResponse currentOrganization) {}
