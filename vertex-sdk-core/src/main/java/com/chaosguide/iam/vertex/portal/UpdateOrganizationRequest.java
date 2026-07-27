package com.chaosguide.iam.vertex.portal;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Strict PATCH payload. At least one non-null field must be supplied by the caller. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record UpdateOrganizationRequest(String name, String slug) {}
