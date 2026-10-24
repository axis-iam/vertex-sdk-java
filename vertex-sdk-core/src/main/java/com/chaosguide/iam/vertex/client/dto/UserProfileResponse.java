package com.chaosguide.iam.vertex.client.dto;

import com.fasterxml.jackson.annotation.JsonAlias;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Response shape returned by {@code GET /api/v1/auth/me/profile}.
 *
 * <p>{@code metadata} is profile metadata for display/profile reads. It is not App User
 * authorization attributes and must not be used as an authorization source. New account-center
 * integrations should prefer the account-center fields such as {@link #userId()}, {@link
 * #applicationId()}, and {@link #currentOrganization()}.
 *
 * @param email nullable primary EMAIL projection; users without email are valid
 * @param username nullable primary USERNAME projection
 * @param metadata legacy profile metadata, when returned by older IAM servers
 */
public record UserProfileResponse(
        @JsonAlias("id") String userId,
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
        AccountOrganizationResponse currentOrganization,
        Set<String> roles,
        Map<String, Object> metadata) {

    public UserProfileResponse {
        roles = roles == null ? Set.of() : Collections.unmodifiableSet(new LinkedHashSet<>(roles));
        metadata =
                metadata == null
                        ? Map.of()
                        : Collections.unmodifiableMap(new LinkedHashMap<>(metadata));
    }

    /**
     * Legacy alias for callers compiled against the earlier {@code /api/v1/auth/me} profile shape.
     */
    public String id() {
        return userId;
    }
}
