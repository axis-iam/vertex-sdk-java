package com.chaosguide.iam.vertex.authz;

import java.util.regex.Pattern;

/** Frozen permission grant matcher: exact, {@code resource:*}, or {@code *:*} only. */
public final class PermissionMatcher {
    private static final Pattern SEGMENT = Pattern.compile("[a-z0-9_-]{1,128}");

    private PermissionMatcher() {}

    public static boolean matches(PermissionKey target, String granted) {
        if (target == null || !concrete(target.resource()) || !concrete(target.action()) || granted == null) {
            return false;
        }
        int separator = granted.indexOf(':');
        if (separator <= 0 || separator != granted.lastIndexOf(':') || separator == granted.length() - 1) {
            return false;
        }
        String resource = granted.substring(0, separator);
        String action = granted.substring(separator + 1);
        if ("*".equals(resource)) {
            return "*".equals(action);
        }
        if (!concrete(resource)) {
            return false;
        }
        if ("*".equals(action)) {
            return resource.equals(target.resource());
        }
        return concrete(action)
                && resource.equals(target.resource())
                && action.equals(target.action());
    }

    private static boolean concrete(String value) {
        return value != null && SEGMENT.matcher(value).matches();
    }
}
