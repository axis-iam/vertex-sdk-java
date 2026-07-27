package com.chaosguide.iam.vertex.portal;

import java.util.List;

/** Page of Application-bound Organizations. */
public record OpenOrganizationPage(List<OpenOrganization> content, OrganizationPageMetadata page) {}
