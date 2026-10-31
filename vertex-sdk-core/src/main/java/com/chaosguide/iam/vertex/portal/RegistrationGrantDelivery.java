package com.chaosguide.iam.vertex.portal;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;

/** Safe durable-delivery status. It never contains invitation credentials. */
public record RegistrationGrantDelivery(
        String id, String grantId, String recipient, RegistrationGrantDeliveryRequest.Variant variant,
        Status status, String failureCode,
        @JsonProperty(value = "attemptCount", required = true) @JsonSetter(nulls = Nulls.FAIL) int attemptCount, Integer maxAttempts,
        String nextAttemptAt, @JsonProperty(value = "retryable", required = true) @JsonSetter(nulls = Nulls.FAIL) boolean retryable,
        String expiresAt, String createdAt) {
    public RegistrationGrantDelivery {
        if (id == null || id.isBlank() || grantId == null || grantId.isBlank()
                || recipient == null || recipient.isBlank() || variant == null || status == null
                || attemptCount < 0 || (maxAttempts != null && maxAttempts < 1)
                || expiresAt == null || expiresAt.isBlank() || createdAt == null || createdAt.isBlank()) {
            throw new IllegalArgumentException("Invalid registration grant delivery response");
        }
    }
    public enum Status { QUEUED, SENDING, DELIVERED, FAILED, UNKNOWN }
}
