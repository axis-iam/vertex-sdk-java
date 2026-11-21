package com.chaosguide.iam.vertex.web;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

final class WebWire {
    static final ObjectMapper JSON =
            new ObjectMapper()
                    .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                    .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private WebWire() {}

    static ObjectNode object() {
        return JSON.createObjectNode();
    }

    static ObjectNode parse(byte[] bytes) {
        try {
            JsonNode n = JSON.readTree(bytes);
            if (n == null || !n.isObject()) throw WebSessionException.protocol();
            return (ObjectNode) n;
        } catch (IOException e) {
            throw WebSessionException.protocol();
        }
    }

    static String text(JsonNode n, String key) {
        JsonNode v = n.get(key);
        if (v == null || !v.isTextual() || v.textValue().isBlank())
            throw WebSessionException.protocol();
        return v.textValue();
    }

    static Instant time(JsonNode n, String key) {
        try {
            return Instant.parse(text(n, key));
        } catch (DateTimeParseException e) {
            throw WebSessionException.protocol();
        }
    }

    static String uuid(JsonNode n, String key) {
        String s = text(n, key);
        try {
            if (!UUID.fromString(s).toString().equals(s)) throw WebSessionException.protocol();
        } catch (IllegalArgumentException e) {
            throw WebSessionException.protocol();
        }
        return s;
    }

    static void fields(JsonNode n, Set<String> required, Set<String> optional) {
        if (n == null || !n.isObject()) throw WebSessionException.invalid();
        Set<String> actual = new HashSet<>();
        n.fieldNames().forEachRemaining(actual::add);
        Set<String> allowed = new HashSet<>(required);
        allowed.addAll(optional);
        if (!actual.containsAll(required) || !allowed.containsAll(actual))
            throw WebSessionException.invalid();
    }

    static void strings(JsonNode list) {
        if (list == null || !list.isArray()) throw WebSessionException.protocol();
        for (JsonNode v : list)
            if (!v.isTextual() || v.textValue().isBlank()) throw WebSessionException.protocol();
    }

    static void navigation(String url, boolean development) {
        try {
            URI target = new URI(url);
            if (target.getUserInfo() != null
                    || target.getFragment() != null
                    || target.getHost() == null) throw WebSessionException.protocol();
            WebBffConfig.validateOrigin(
                    new URI(
                            target.getScheme(),
                            null,
                            target.getHost(),
                            target.getPort(),
                            null,
                            null,
                            null),
                    development);
        } catch (URISyntaxException | IllegalArgumentException e) {
            throw WebSessionException.protocol();
        }
    }

    static void boundedText(JsonNode n, String key, int max) {
        JsonNode value = n.get(key);
        if (value == null
                || !value.isTextual()
                || value.textValue().isBlank()
                || value.textValue().length() > max) throw WebSessionException.invalid();
    }

    static String canonical(JsonNode node) {
        return canonicalNode(node).toString();
    }

    private static JsonNode canonicalNode(JsonNode node) {
        if (node.isObject()) {
            ObjectNode out = object();
            List<String> keys = new ArrayList<>();
            node.fieldNames().forEachRemaining(keys::add);
            keys.sort(String::compareTo);
            for (String key : keys) out.set(key, canonicalNode(node.get(key)));
            return out;
        }
        if (node.isArray()) {
            var out = JSON.createArrayNode();
            node.forEach(v -> out.add(canonicalNode(v)));
            return out;
        }
        return node;
    }

    static Instant min(Instant... values) {
        Instant result = values[0];
        for (Instant v : values) if (v.isBefore(result)) result = v;
        return result;
    }
}
