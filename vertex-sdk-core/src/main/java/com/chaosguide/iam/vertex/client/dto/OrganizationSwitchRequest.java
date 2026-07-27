package com.chaosguide.iam.vertex.client.dto;

/**
 * Current Organization switch request. The server validates membership and returns a continuation;
 * SDKs must not mutate JWT claims locally.
 */
public record OrganizationSwitchRequest(String organizationId) {
}
