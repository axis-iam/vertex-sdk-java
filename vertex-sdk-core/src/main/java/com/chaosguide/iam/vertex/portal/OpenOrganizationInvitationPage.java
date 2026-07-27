package com.chaosguide.iam.vertex.portal;

import java.util.List;

/** Page of Organization invitations and their delivery state. */
public record OpenOrganizationInvitationPage(
        List<OpenOrganizationInvitation> content, OrganizationPageMetadata page) {}
