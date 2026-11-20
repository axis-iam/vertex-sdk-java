package com.chaosguide.iam.vertex.web;

import java.net.URI;
import com.fasterxml.jackson.annotation.JsonIgnore;
import java.time.Duration;
import java.util.Set;

/** Explicit server_session configuration. Does not change existing oauth_tokens integration. */
public record WebBffConfig(URI issuer, String resourceAudience, String clientId, @JsonIgnore String clientSecret,
        URI callback, URI origin, String basePath, Set<String> returnPaths,
        String defaultReturnPath, Set<String> scopes, boolean developmentLoopback, int declaredProcesses) {
    public WebBffConfig {
        if (issuer == null || origin == null || callback == null || resourceAudience == null
                || resourceAudience.isBlank() || clientId == null || clientId.isBlank() || clientId.length() > 128
                || clientSecret == null || clientSecret.isBlank() || declaredProcesses < 1)
            throw new IllegalArgumentException("Explicit WEB configuration is required");
        validateOrigin(issuer, developmentLoopback); validateOrigin(origin, developmentLoopback);
        if ((origin.getPath() != null && !origin.getPath().isEmpty())
                || (issuer.getPath() != null && !issuer.getPath().isEmpty()))
            throw new IllegalArgumentException("Issuer and canonical origin have no path");
        if (basePath == null || !basePath.matches("/[A-Za-z0-9/_-]+") || basePath.endsWith("/"))
            throw new IllegalArgumentException("Invalid BFF base path");
        if (!callback.equals(origin.resolve(basePath + "/callback")))
            throw new IllegalArgumentException("Callback must match canonical BFF callback");
        returnPaths = Set.copyOf(returnPaths);
        for (String p : returnPaths)
            if (!p.startsWith("/") || p.startsWith("//") || p.contains("\\") || p.contains("?") || p.contains("#")
                    || p.contains("%") || !URI.create(p).normalize().getPath().equals(p))
                throw new IllegalArgumentException("Return destinations must be exact local paths");
        if (!returnPaths.contains(defaultReturnPath)) throw new IllegalArgumentException("Return path is not allowed");
        scopes = Set.copyOf(scopes);
        if (!scopes.contains("openid") || scopes.stream().anyMatch(s -> !s.matches("[a-zA-Z0-9_:.-]+")))
            throw new IllegalArgumentException("Explicit OpenID scope required");
    }
    static void validateOrigin(URI uri, boolean development) {
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
                || (!"https".equals(uri.getScheme()) && !(development && "http".equals(uri.getScheme())
                && Set.of("localhost", "127.0.0.1", "[::1]").contains(uri.getHost()))))
            throw new IllegalArgumentException("HTTPS or explicit loopback development required");
    }
    public Duration upstreamTimeout() { return Duration.ofSeconds(5); }
    public Duration authBudget() { return Duration.ofSeconds(10); }
    @Override public String toString() { return "WebBffConfig[server_session, credentials redacted]"; }
}
