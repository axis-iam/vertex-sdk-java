package com.chaosguide.iam.vertex.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Projects only frozen public DTO fields, including nested capability/policy fields. */
final class CapabilityView {
    private static final Map<String, JsonNode> RECORDS = load();

    private CapabilityView() {}

    private static Map<String, JsonNode> load() {
        try (InputStream stream = CapabilityView.class.getResourceAsStream("wire-records.json")) {
            if (stream == null)
                throw new IllegalStateException("Missing frozen capability descriptors");
            JsonNode snapshot = WebWire.JSON.readTree(stream);
            Map<String, JsonNode> schemas = new HashMap<>();
            for (JsonNode record : snapshot.path("records"))
                schemas.put(record.path("record").asText(), record);
            return Map.copyOf(schemas);
        } catch (IOException e) {
            throw new IllegalStateException("Invalid frozen capability descriptors");
        }
    }

    static ObjectNode project(String resource, ObjectNode response, String clientId) {
        ObjectNode out =
                (ObjectNode)
                        value(
                                resource.equals("auth-methods")
                                        ? "AuthMethodsPublicResponse"
                                        : "AuthPolicyPublicResponse",
                                response);
        if (resource.equals("auth-methods") && !clientId.equals(WebWire.text(out, "clientId")))
            throw WebSessionException.protocol();
        return out;
    }

    private static JsonNode value(String type, JsonNode input) {
        if (input == null || input.isNull()) throw WebSessionException.protocol();
        if (type.startsWith("List<") && type.endsWith(">")) {
            if (!input.isArray()) throw WebSessionException.protocol();
            var result = WebWire.JSON.createArrayNode();
            for (JsonNode item : input)
                result.add(value(type.substring(5, type.length() - 1), item));
            return result;
        }
        switch (type) {
            case "String", "AuthMethodType", "UserIdentifierKind" -> {
                if (!input.isTextual()) throw WebSessionException.protocol();
                return input;
            }
            case "UUID" -> {
                ObjectNode wrapped = WebWire.object();
                wrapped.set("id", input);
                WebWire.uuid(wrapped, "id");
                return input;
            }
            case "boolean" -> {
                if (!input.isBoolean()) throw WebSessionException.protocol();
                return input;
            }
            case "int" -> {
                if (!input.isIntegralNumber() || !input.canConvertToInt() || input.intValue() < 0)
                    throw WebSessionException.protocol();
                return input;
            }
            default -> {
                String name = type.substring(type.lastIndexOf('.') + 1);
                JsonNode schema = RECORDS.get(name);
                if (schema == null || !input.isObject()) throw WebSessionException.protocol();
                Set<String> nullable = new HashSet<>();
                schema.path("nullable").forEach(v -> nullable.add(v.asText()));
                ObjectNode out = WebWire.object();
                for (JsonNode component : schema.path("components")) {
                    String[] parts = component.asText().split(" ", 2);
                    JsonNode field = input.get(parts[1]);
                    if (field == null) throw WebSessionException.protocol();
                    if (field.isNull() && nullable.contains(parts[1])) out.putNull(parts[1]);
                    else out.set(parts[1], value(parts[0], field));
                }
                return out;
            }
        }
    }
}
