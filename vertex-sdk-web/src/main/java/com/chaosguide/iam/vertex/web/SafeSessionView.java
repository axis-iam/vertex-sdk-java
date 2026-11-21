package com.chaosguide.iam.vertex.web;

import com.chaosguide.iam.vertex.client.dto.CurrentUserResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Set;

/**
 * Strict browser contract validator, also usable by artifact consumers with the frozen C0 vectors.
 */
public final class SafeSessionView {
    private SafeSessionView() {}

    public static void validate(JsonNode view) {
        WebWire.fields(
                view,
                Set.of("state", "expiresAt", "csrfToken"),
                Set.of(
                        "owner",
                        "version",
                        "profile",
                        "permissions",
                        "nextAction",
                        "challengeExpiresAt",
                        "cooldownSeconds",
                        "authorizationUrl"));
        WebWire.time(view, "expiresAt");
        random(view, "csrfToken");
        String state = WebWire.text(view, "state");
        if (!Set.of(
                        "PRELOGIN",
                        "AUTHENTICATING",
                        "AWAITING_PROVIDER",
                        "MFA_REQUIRED",
                        "AUTHENTICATED",
                        "COMPLETED",
                        "CANCELLED",
                        "EXPIRED",
                        "REJECTED")
                .contains(state)) throw WebSessionException.protocol();
        if (view.has("profile")) {
            if (!state.equals("AUTHENTICATED") || view.has("nextAction"))
                throw WebSessionException.protocol();
            random(view, "owner");
            if (!view.path("version").isIntegralNumber()
                    || view.path("version").longValue() < 0
                    || view.path("version").longValue() > 9007199254740991L)
                throw WebSessionException.protocol();
            try {
                CurrentUserResponse.fromJson(view.get("profile"));
            } catch (IllegalArgumentException e) {
                throw WebSessionException.protocol();
            }
            permissions(view.get("profile"), view.get("permissions"));
        } else {
            if (view.has("owner") || view.has("version") || view.has("permissions"))
                throw WebSessionException.protocol();
            String expected =
                    switch (state) {
                        case "PRELOGIN" -> null;
                        case "AUTHENTICATING" -> "authenticate";
                        case "AWAITING_PROVIDER" -> "authorize";
                        case "MFA_REQUIRED" -> "mfa";
                        case "AUTHENTICATED" -> "complete";
                        default -> "none";
                    };
            if (expected != null && !expected.equals(WebWire.text(view, "nextAction")))
                throw WebSessionException.protocol();
        }
        if (view.has("challengeExpiresAt")) WebWire.time(view, "challengeExpiresAt");
        if (view.has("cooldownSeconds")
                && (!view.path("cooldownSeconds").isIntegralNumber()
                        || !view.path("cooldownSeconds").canConvertToInt()
                        || view.path("cooldownSeconds").intValue() < 0))
            throw WebSessionException.protocol();
        if (view.has("authorizationUrl")) WebWire.text(view, "authorizationUrl");
    }

    private static void random(JsonNode n, String key) {
        if (!WebWire.text(n, key).matches("[A-Za-z0-9_-]{43}"))
            throw WebSessionException.protocol();
    }

    static void permissions(JsonNode profile, JsonNode p) {
        if (p == null || !p.isObject()) throw WebSessionException.protocol();
        WebWire.strings(p.get("roles"));
        WebWire.strings(p.get("permissions"));
        if (p.has("applicationId") || p.has("organizationId")) {
            JsonNode c = profile.path("authenticationContext");
            if (!c.path("applicationId").equals(p.path("applicationId"))
                    || !c.path("organizationId").equals(p.path("organizationId")))
                throw WebSessionException.protocol();
        }
    }

    static ObjectNode profileProjection(ObjectNode profile) {
        ObjectNode out =
                select(
                        profile,
                        Set.of("id", "email", "username", "status", "emailVerified", "metadata"));
        ObjectNode context =
                select(
                        profile.path("authenticationContext"),
                        Set.of(
                                "subjectType",
                                "applicationId",
                                "clientId",
                                "sessionId",
                                "workspaceId",
                                "workspaceSelectionRequired",
                                "organizationId",
                                "organizationSlug",
                                "organizationRole",
                                "authTime",
                                "authenticationMethods",
                                "assuranceLevel",
                                "impersonation"));
        if (!context.path("impersonation").isNull())
            context.set(
                    "impersonation",
                    select(context.get("impersonation"), Set.of("actorId", "impersonationId")));
        out.set("authenticationContext", context);
        return out;
    }

    static ObjectNode permissionProjection(ObjectNode permissions) {
        ObjectNode out = select(permissions, Set.of("roles", "permissions"));
        if (permissions.has("applicationId"))
            out.set("applicationId", permissions.get("applicationId"));
        if (permissions.has("organizationId"))
            out.set("organizationId", permissions.get("organizationId"));
        return out;
    }

    private static ObjectNode select(JsonNode input, Set<String> keys) {
        ObjectNode out = WebWire.object();
        for (String key : keys) {
            if (!input.has(key)) throw WebSessionException.protocol();
            out.set(key, input.get(key));
        }
        return out;
    }
}
