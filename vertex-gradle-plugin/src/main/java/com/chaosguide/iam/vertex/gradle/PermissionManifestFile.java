package com.chaosguide.iam.vertex.gradle;

import com.chaosguide.iam.vertex.manifest.PermissionManifestClient;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

final class PermissionManifestFile {
    private static final Set<String> MANIFEST_FIELDS = Set.of("manifestId", "revision", "permissions");
    private static final Set<String> DECLARATION_FIELDS = Set.of("resource", "action", "name", "description");
    private static final ObjectMapper MAPPER = new ObjectMapper(
            JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private PermissionManifestFile() {}

    static PermissionManifestClient.Manifest read(File file) throws IOException {
        JsonNode root = MAPPER.readTree(file);
        requireExactObject(root, MANIFEST_FIELDS, "manifest");
        JsonNode permissions = root.get("permissions");
        if (permissions == null || !permissions.isArray()) {
            throw new IllegalArgumentException("permission manifest permissions must be an array");
        }
        var declarations = new ArrayList<PermissionManifestClient.Declaration>();
        for (JsonNode item : permissions) {
            requireExactObject(item, DECLARATION_FIELDS, "permission declaration");
            JsonNode description = item.get("description");
            if (description == null || (!description.isNull() && !description.isTextual())) {
                throw new IllegalArgumentException("permission declaration description must be string or null");
            }
            declarations.add(new PermissionManifestClient.Declaration(
                    requiredText(item, "resource"), requiredText(item, "action"),
                    requiredText(item, "name"), description.isNull() ? null : description.textValue()));
        }
        return new PermissionManifestClient.Manifest(
                requiredText(root, "manifestId"), requiredText(root, "revision"), declarations);
    }

    private static void requireExactObject(JsonNode value, Set<String> fields, String name) {
        if (value == null || !value.isObject()) throw new IllegalArgumentException(name + " must be an object");
        Set<String> actual = new HashSet<>();
        value.fieldNames().forEachRemaining(actual::add);
        if (!actual.equals(fields)) throw new IllegalArgumentException(name + " fields must be exactly " + fields);
    }

    private static String requiredText(JsonNode value, String field) {
        JsonNode child = value.get(field);
        if (child == null || !child.isTextual() || child.textValue().isEmpty()) {
            throw new IllegalArgumentException("permission manifest " + field + " must be a non-empty string");
        }
        return child.textValue();
    }
}
