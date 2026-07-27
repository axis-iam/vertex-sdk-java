package com.chaosguide.iam.vertex.portal;

import java.util.List;

/** Page of Organization members. */
public record OpenOrganizationMemberPage(List<OpenOrganizationMember> content, OrganizationPageMetadata page) {}
