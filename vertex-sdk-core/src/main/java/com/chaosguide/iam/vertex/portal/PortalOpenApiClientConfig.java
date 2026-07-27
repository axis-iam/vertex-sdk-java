package com.chaosguide.iam.vertex.portal;

import java.time.Duration;

/**
 * Configuration for {@link PortalOpenApiClient}.
 *
 * <p>This is a server-side M2M configuration. {@code clientSecret} must only be
 * used in trusted backend, CLI, or background-job runtimes.
 */
public final class PortalOpenApiClientConfig {

    static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);
    static final Duration DEFAULT_TOKEN_SKEW = Duration.ofSeconds(30);

    private final String issuer;
    private final String portalEndpoint;
    private final String clientId;
    private final String clientSecret;
    private final Duration timeout;
    private final Duration tokenSkew;

    private PortalOpenApiClientConfig(Builder builder) {
        this.issuer = stripTrailingSlash(requireText(builder.issuer, "issuer"));
        this.portalEndpoint = stripTrailingSlash(requireText(builder.portalEndpoint, "portalEndpoint"));
        this.clientId = requireText(builder.clientId, "clientId");
        this.clientSecret = requireText(builder.clientSecret, "clientSecret");
        this.timeout = builder.timeout == null ? DEFAULT_TIMEOUT : builder.timeout;
        this.tokenSkew = builder.tokenSkew == null ? DEFAULT_TOKEN_SKEW : builder.tokenSkew;
        if (this.timeout.isZero() || this.timeout.isNegative()) {
            throw new PortalOpenApiConfigException("timeout must be positive");
        }
        if (this.tokenSkew.isNegative()) {
            throw new PortalOpenApiConfigException("tokenSkew must be non-negative");
        }
    }

    public String getIssuer() {
        return issuer;
    }

    public String getPortalEndpoint() {
        return portalEndpoint;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public Duration getTimeout() {
        return timeout;
    }

    public Duration getTokenSkew() {
        return tokenSkew;
    }

    public static Builder builder() {
        return new Builder();
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new PortalOpenApiConfigException("PortalOpenApiClient " + field + " is required");
        }
        return value.strip();
    }

    private static String stripTrailingSlash(String value) {
        return value.replaceAll("/+$", "");
    }

    public static final class Builder {

        private String issuer;
        private String portalEndpoint;
        private String clientId;
        private String clientSecret;
        private Duration timeout;
        private Duration tokenSkew;

        private Builder() {
        }

        /** IAM issuer/auth server base URL. Tokens are requested from {@code {issuer}/oauth2/token}. */
        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        /** iam-portal base URL used for {@code /open/v1/**} resource requests. */
        public Builder portalEndpoint(String portalEndpoint) {
            this.portalEndpoint = portalEndpoint;
            return this;
        }

        /** M2M confidential {@code ApplicationClient.clientId}. */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /** M2M confidential client secret. Never expose this to browser or native code. */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        /** HTTP connect/read/write timeout. Defaults to 5 seconds. */
        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        /** Duration subtracted from {@code expires_in} before caching. Defaults to 30 seconds. */
        public Builder tokenSkew(Duration tokenSkew) {
            this.tokenSkew = tokenSkew;
            return this;
        }

        public PortalOpenApiClientConfig build() {
            return new PortalOpenApiClientConfig(this);
        }
    }
}
