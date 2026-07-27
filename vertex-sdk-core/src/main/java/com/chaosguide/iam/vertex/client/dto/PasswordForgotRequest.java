package com.chaosguide.iam.vertex.client.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Public forgot-password request. Field names are OAuth-style snake_case on the wire.
 */
public record PasswordForgotRequest(
        String email,
        @JsonProperty("client_id") String clientId,
        @JsonProperty("redirect_uri") String redirectUri) {
}
