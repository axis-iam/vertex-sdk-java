package com.chaosguide.iam.vertex.portal;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Strict Organization invitation create payload. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CreateOrganizationInvitationRequest(
        String email, OrganizationMemberRole role, Boolean sendEmail) {}
