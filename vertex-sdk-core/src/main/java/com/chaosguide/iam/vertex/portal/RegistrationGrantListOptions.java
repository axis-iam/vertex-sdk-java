package com.chaosguide.iam.vertex.portal;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Optional server-side filters for registration-grant listing. */
public record RegistrationGrantListOptions(
        RegistrationGrantType type, RegistrationGrantStatus status, String search, Integer page, Integer size) {
    public static RegistrationGrantListOptions empty() {
        return new RegistrationGrantListOptions(null, null, null, null, null);
    }

    String toQueryString() {
        List<String> parameters = new ArrayList<>();
        add(parameters, "type", type == null ? null : type.name());
        add(parameters, "status", status == null ? null : status.name());
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
