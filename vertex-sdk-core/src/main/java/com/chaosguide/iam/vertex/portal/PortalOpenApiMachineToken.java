package com.chaosguide.iam.vertex.portal;

import java.time.Instant;

/** Cached M2M token for one explicit Portal Open API scope. */
public record PortalOpenApiMachineToken(String accessToken, String scope, Instant expiresAt) {
}
