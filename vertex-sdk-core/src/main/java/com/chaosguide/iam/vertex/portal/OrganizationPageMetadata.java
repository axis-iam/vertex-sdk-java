package com.chaosguide.iam.vertex.portal;

/** Nested Spring PagedModel metadata used by Organization management lists. */
public record OrganizationPageMetadata(int size, int number, long totalElements, int totalPages) {}
