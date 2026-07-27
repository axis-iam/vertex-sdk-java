package com.chaosguide.iam.vertex.context;

import com.chaosguide.iam.vertex.exception.IamSdkException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Convenience accessors for the current IAM-authenticated request. */
public final class IamContext {

    private final IamCurrentUser user;

    private IamContext(IamCurrentUser user) {
        this.user = user;
    }

    /** Returns the current IAM user or throws an SDK exception when the request is unauthenticated. */
    public static IamContext current() {
        return currentOptional()
                .orElseThrow(() -> new IamSdkException("current IAM user is not available"));
    }

    /** Returns the current IAM context if the Spring Security context contains a JWT authentication. */
    public static Optional<IamContext> currentOptional() {
        return currentUserOptional().map(IamContext::new);
    }

    /** Returns the immutable current-user value object, useful for injection and audit DTOs. */
    public static IamCurrentUser currentUser() {
        return currentUserOptional()
                .orElseThrow(() -> new IamSdkException("current IAM user is not available"));
    }

    /** Returns the current-user value object if the request is IAM authenticated. */
    public static Optional<IamCurrentUser> currentUserOptional() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return Optional.empty();
        }
        Jwt jwt = jwt(authentication);
        if (jwt == null) {
            return Optional.empty();
        }
        return Optional.of(from(authentication, jwt));
    }

    /** Alias for {@link #current()} for call sites that prefer explicit naming. */
    public static IamContext requireCurrent() {
        return current();
    }

    /** Alias for {@link #currentUser()} for call sites that prefer explicit naming. */
    public static IamCurrentUser requireCurrentUser() {
        return currentUser();
    }

    /** Returns the raw access token for explicit user-profile calls, if Spring exposes it. */
    public static Optional<String> currentAccessToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = authentication == null ? null : jwt(authentication);
        return jwt == null ? Optional.empty() : Optional.ofNullable(jwt.getTokenValue());
    }

    public IamCurrentUser user() {
        return user;
    }

    public String getUserId() {
        return user.subject();
    }

    public String getEmail() {
        return user.email();
    }

    public Set<String> getRoles() {
        return user.roles();
    }

    public Set<String> getPermissions() {
        return user.permissions();
    }

    public String getOrgId() {
        return user.organizationId();
    }

    public String getOrgRole() {
        return user.organizationRole();
    }

    public String getActorId() {
        return user.actor() == null ? null : user.actor().subject();
    }

    public boolean hasPermission(String resource, String action) {
        return user.hasPermission(resource, action);
    }

    public boolean isImpersonating() {
        return user.isImpersonating();
    }

    public boolean hasMfa() {
        return user.hasMfa();
    }

    private static IamCurrentUser from(Authentication authentication, Jwt jwt) {
        Set<String> permissions = new LinkedHashSet<>();
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            String value = authority.getAuthority();
            if (value != null && value.contains(":")) {
                permissions.add(value);
            }
        }
        return new IamCurrentUser(
                jwt.getSubject(),
                applicationId(jwt),
                stringClaim(jwt, "email"),
                Boolean.TRUE.equals(jwt.getClaim("email_verified")),
                stringClaim(jwt, "username"),
                stringClaim(jwt, "org_id"),
                stringClaim(jwt, "org_slug"),
                stringClaim(jwt, "org_role"),
                stringClaim(jwt, "workspace_id"),
                stringClaim(jwt, "sid"),
                stringSet(jwt.getClaim("roles")),
                permissions,
                stringList(jwt.getClaim("amr")),
                stringClaim(jwt, "acr"),
                actor(jwt.getClaim("act")),
                jwt.getClaims());
    }

    private static Jwt jwt(Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken token) {
            return token.getToken();
        }
        Object principal = authentication.getPrincipal();
        return principal instanceof Jwt jwt ? jwt : null;
    }

    private static String applicationId(Jwt jwt) {
        String appId = stringClaim(jwt, "app_id");
        if (appId != null) {
            return appId;
        }
        List<String> audience = jwt.getAudience();
        return audience == null || audience.isEmpty() ? null : audience.get(0);
    }

    private static String stringClaim(Jwt jwt, String name) {
        Object value = jwt.getClaim(name);
        if (value instanceof String s && !s.isBlank()) {
            return s;
        }
        return null;
    }

    private static Set<String> stringSet(Object value) {
        if (value == null) {
            return Set.of();
        }
        Set<String> out = new LinkedHashSet<>();
        if (value instanceof Collection<?> values) {
            for (Object item : values) {
                if (item instanceof String s && !s.isBlank()) {
                    out.add(s);
                }
            }
        } else if (value instanceof String s && !s.isBlank()) {
            out.add(s);
        }
        return out;
    }

    private static List<String> stringList(Object value) {
        return List.copyOf(stringSet(value));
    }

    private static IamActor actor(Object value) {
        if (value instanceof Map<?, ?> map) {
            Object subject = map.get("sub");
            if (subject instanceof String s && !s.isBlank()) {
                return new IamActor(s);
            }
        }
        return null;
    }
}
