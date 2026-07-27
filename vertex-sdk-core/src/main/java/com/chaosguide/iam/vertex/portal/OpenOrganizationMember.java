package com.chaosguide.iam.vertex.portal;

/** Application-bound Organization membership detail, including optimistic-lock version. */
public record OpenOrganizationMember(
        String membershipId,
        String userId,
        String email,
        String displayName,
        OrganizationMemberRole role,
        String joinedAt,
        String updatedAt,
        Long version) {}
