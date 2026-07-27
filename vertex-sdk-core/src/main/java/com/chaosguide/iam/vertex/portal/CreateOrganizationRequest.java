package com.chaosguide.iam.vertex.portal;

/** Strict create payload for an Organization. */
public record CreateOrganizationRequest(String name, String slug) {}
