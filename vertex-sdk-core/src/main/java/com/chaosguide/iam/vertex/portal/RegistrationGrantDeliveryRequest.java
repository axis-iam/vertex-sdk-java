package com.chaosguide.iam.vertex.portal;

/** Explicit delivery; the recipient is never inferred from another operation. */
public record RegistrationGrantDeliveryRequest(String recipient, String locale, Variant variant) {
    public enum Variant { LINK, CODE }

    public RegistrationGrantDeliveryRequest {
        if (recipient == null || recipient.isBlank() || variant == null) {
            throw new IllegalArgumentException("Recipient and delivery variant are required");
        }
    }
}
