package com.chaosguide.iam.vertex.client.dto;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Safe GET /api/v1/auth/me view. Metadata is display data, never authorization. */
public record CurrentUserResponse(
        String id, String email, String username, String status, boolean emailVerified,
        AuthenticationContext authenticationContext, Map<String, JsonNode> metadata) {
    public CurrentUserResponse { metadata = Map.copyOf(metadata); }

    public record Impersonation(String actorId, String impersonationId) {}
    public record AuthenticationContext(
            String subjectType, String applicationId, String clientId, String sessionId,
            String workspaceId, boolean workspaceSelectionRequired,
            String organizationId, String organizationSlug, String organizationRole,
            Instant authTime, List<String> authenticationMethods, String assuranceLevel,
            Impersonation impersonation) {
        public AuthenticationContext { authenticationMethods = List.copyOf(authenticationMethods); }
    }

    /** Reject incomplete views rather than constructing an anonymous or default context. */
    public static CurrentUserResponse fromJson(JsonNode root) {
        requireObject(root);
        JsonNode c = root.get("authenticationContext");
        requireObject(c);
        if (!"USER".equals(text(c, "subjectType"))) throw invalid();
        String workspace = nullable(c, "workspaceId");
        boolean selection = flag(c, "workspaceSelectionRequired");
        String organization = nullable(c, "organizationId");
        String slug = nullable(c, "organizationSlug");
        String role = nullable(c, "organizationRole");
        if ((selection && workspace != null) || (organization == null && (slug != null || role != null))) throw invalid();
        String time = nullable(c, "authTime");
        Instant authTime;
        try { authTime = time == null ? null : Instant.parse(time); }
        catch (DateTimeParseException ex) { throw invalid(); }
        JsonNode methods = required(c, "authenticationMethods");
        if (!methods.isArray()) throw invalid();
        List<String> values = new ArrayList<>();
        for (JsonNode method : methods) values.add(value(method));
        JsonNode i = required(c, "impersonation");
        Impersonation impersonation = null;
        if (!i.isNull()) { requireObject(i); impersonation = new Impersonation(text(i, "actorId"), text(i, "impersonationId")); }
        JsonNode metadata = root.get("metadata");
        requireObject(metadata);
        Map<String, JsonNode> entries = new LinkedHashMap<>();
        metadata.fields().forEachRemaining(entry -> entries.put(entry.getKey(), entry.getValue().deepCopy()));
        return new CurrentUserResponse(text(root, "id"), nullable(root, "email"), nullable(root, "username"),
                text(root, "status"), flag(root, "emailVerified"),
                new AuthenticationContext("USER", text(c, "applicationId"), text(c, "clientId"), text(c, "sessionId"),
                        workspace, selection, organization, slug, role, authTime, values,
                        nullable(c, "assuranceLevel"), impersonation), entries);
    }
    private static JsonNode required(JsonNode n, String field) {
        JsonNode result = n.get(field); if (result == null) throw invalid(); return result;
    }
    private static String text(JsonNode n, String field) { return value(required(n, field)); }
    private static String value(JsonNode n) { if (!n.isTextual() || n.textValue().isBlank()) throw invalid(); return n.textValue(); }
    private static String nullable(JsonNode n, String field) { JsonNode v = required(n, field); return v.isNull() ? null : value(v); }
    private static boolean flag(JsonNode n, String field) { JsonNode v = required(n, field); if (!v.isBoolean()) throw invalid(); return v.booleanValue(); }
    private static void requireObject(JsonNode n) { if (n == null || !n.isObject()) throw invalid(); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid current-user view"); }
}
