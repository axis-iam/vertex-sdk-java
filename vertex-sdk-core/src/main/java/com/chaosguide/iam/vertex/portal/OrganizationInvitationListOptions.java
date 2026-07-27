package com.chaosguide.iam.vertex.portal;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Optional terminal-state filter and paging for Organization invitations. */
public record OrganizationInvitationListOptions(
        OrganizationInvitationStatus status, Integer page, Integer size) {
    public static OrganizationInvitationListOptions empty() {
        return new OrganizationInvitationListOptions(null, null, null);
    }

    String toQueryString() {
        List<String> parameters = new ArrayList<>();
        add(parameters, "status", status == null ? null : status.name());
        add(parameters, "page", page == null ? null : page.toString());
        add(parameters, "size", size == null ? null : size.toString());
        return parameters.isEmpty() ? "" : "?" + String.join("&", parameters);
    }

    private static void add(List<String> parameters, String name, String value) {
        if (value != null) {
            parameters.add(URLEncoder.encode(name, StandardCharsets.UTF_8) + "="
                    + URLEncoder.encode(value, StandardCharsets.UTF_8));
        }
    }
}
