package com.chaosguide.iam.vertex.context;

import com.chaosguide.iam.vertex.authz.PermissionKey;
import com.chaosguide.iam.vertex.authz.PermissionMatcher;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Request-local authenticated user derived from the verified JWT and resolved
 * Spring Security authorities.
 */
public record IamCurrentUser(
        String subject,
        String applicationId,
        String email,
        boolean emailVerified,
        String username,
        String organizationId,
        String organizationSlug,
        String organizationRole,
        String workspaceId,
        String sessionId,
        Set<String> roles,
        Set<String> permissions,
        List<String> authenticationMethods,
        String authenticationContextClass,
        IamActor actor,
        Map<String, Object> claims) {

    public IamCurrentUser {
        roles = immutableSet(roles);
        permissions = immutableSet(permissions);
        authenticationMethods = immutableList(authenticationMethods);
        claims = immutableMap(claims);
    }

    /** Alias for applications that call the actor id {@code userId}. */
    public String userId() {
        return subject;
    }

    public boolean isImpersonating() {
        return actor != null && actor.subject() != null && !actor.subject().isBlank();
    }

    public boolean hasMfa() {
        return authenticationMethods.stream()
                .anyMatch(v -> "mfa".equals(v) || "totp".equals(v) || "webauthn".equals(v) || "pwd+mfa".equals(v));
    }

    public boolean hasPermission(PermissionKey permission) {
        if (permission == null) {
            return false;
        }
        return permissions.stream().anyMatch(granted -> PermissionMatcher.matches(permission, granted));
    }

    public boolean hasPermission(String resource, String action) {
        return hasPermission(new PermissionKey(resource, action));
    }

    private static Set<String> immutableSet(Set<String> values) {
        if (values == null || values.isEmpty()) {
            return Set.of();
        }
        return Collections.unmodifiableSet(new LinkedHashSet<>(values));
    }

    private static List<String> immutableList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        return Collections.unmodifiableList(new ArrayList<>(values));
    }

    private static Map<String, Object> immutableMap(Map<String, Object> values) {
        if (values == null || values.isEmpty()) {
            return Map.of();
        }
        return Collections.unmodifiableMap(new LinkedHashMap<>(values));
    }
}
