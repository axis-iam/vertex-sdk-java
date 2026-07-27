package com.chaosguide.iam.vertex.portal;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Optional search and paging parameters for Organization member lists. */
public record OrganizationMemberListOptions(String search, Integer page, Integer size) {
    public static OrganizationMemberListOptions empty() {
        return new OrganizationMemberListOptions(null, null, null);
    }

    String toQueryString() {
        List<String> parameters = new ArrayList<>();
        add(parameters, "search", search);
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
