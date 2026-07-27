package com.chaosguide.iam.vertex.client.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Public email-verification send request. IAM also accepts clientId, but SDK sends canonical client_id.
 */
public record SendEmailVerificationRequest(
        @JsonProperty("client_id") String clientId,
        String email) {
}
