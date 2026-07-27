package com.chaosguide.iam.vertex.client.dto;

/**
 * Current-user session/device view.
 */
public record SessionView(
        String sessionId,
        String ipAddress,
        String userAgent,
        String deviceId,
        String createdAt,
        String lastSeenAt,
        boolean current) {
}
