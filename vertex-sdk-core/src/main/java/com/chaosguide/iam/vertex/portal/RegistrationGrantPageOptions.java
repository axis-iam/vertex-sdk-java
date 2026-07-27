package com.chaosguide.iam.vertex.portal;

/** Pagination options for a registration grant's redemption history. */
public record RegistrationGrantPageOptions(Integer page, Integer size) {
    public static RegistrationGrantPageOptions empty() {
        return new RegistrationGrantPageOptions(null, null);
    }

    String toQueryString() {
        if (page == null && size == null) {
            return "";
        }
        if (page == null) {
            return "?size=" + size;
        }
        if (size == null) {
            return "?page=" + page;
        }
        return "?page=" + page + "&size=" + size;
    }
}
