package com.chaosguide.iam.vertex.portal;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Optional search, paging, and sorting parameters for Organization lists. */
public record OrganizationListOptions(
        String search,
        Integer page,
        Integer size,
        List<String> sort,
        List<OrganizationSortDirection> direction) {
    public static OrganizationListOptions empty() {
        return new OrganizationListOptions(null, null, null, null, null);
    }

    String toQueryString() {
        List<String> parameters = new ArrayList<>();
        add(parameters, "search", search);
        add(parameters, "page", page == null ? null : page.toString());
        add(parameters, "size", size == null ? null : size.toString());
        if (sort != null) {
            for (String value : sort) {
                add(parameters, "sort", value);
            }
        }
        if (direction != null) {
            for (OrganizationSortDirection value : direction) {
                add(parameters, "direction", value == null ? null : value.name());
            }
        }
        return parameters.isEmpty() ? "" : "?" + String.join("&", parameters);
    }

    private static void add(List<String> parameters, String name, String value) {
        if (value != null) {
            parameters.add(URLEncoder.encode(name, StandardCharsets.UTF_8) + "="
                    + URLEncoder.encode(value, StandardCharsets.UTF_8));
        }
    }
}
