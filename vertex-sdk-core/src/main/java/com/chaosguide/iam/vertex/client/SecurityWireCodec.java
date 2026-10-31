package com.chaosguide.iam.vertex.client;

import com.chaosguide.iam.vertex.client.dto.AccountSecurityOperations.*;
import com.chaosguide.iam.vertex.exception.*;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.*;
import java.lang.reflect.*;
import java.util.*;

/** Strict, bounded operation wire boundary; never uses raw payloads as public diagnostics. */
final class SecurityWireCodec {
    private SecurityWireCodec() {}
    static String token(String value) {
        if (value == null)
            throw new IllegalArgumentException("An explicit current-user bearer is required");
        String token = value.startsWith("Bearer ") ? value.substring(7) : value;
        if (token.isEmpty() || !token.matches("[!-~]+"))
            throw new IllegalArgumentException("An explicit current-user bearer is required");
        return token;
    }
    static String key(String value) {
        if (value == null || value.isBlank() || value.length() > 256 || !value.matches("[ -~]+"))
            throw new IllegalArgumentException("A caller-retained Idempotency-Key is required");
        return value;
    }
    static String text(String value) {
        if (value == null || value.isBlank())
            throw new IllegalArgumentException("A nonblank security field is required");
        return value;
    }
    static String code(String value) {
        if (value == null || !value.matches("[0-9]{6}"))
            throw new IllegalArgumentException("A six-digit ASCII code is required");
        return value;
    }
    static String id(UUID value) {
        return Objects.requireNonNull(value, "Operation UUID is required").toString();
    }
    private static void uuid(String value) {
        if (value == null
            || !value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
            throw new IllegalArgumentException("A canonical UUID is required");
    }
    static Object encode(Object value) {
        Objects.requireNonNull(value, "A typed security request is required");
        if (value instanceof Enum<?> v)
            return v.name();
        if (value instanceof String || value instanceof Long || value instanceof Boolean)
            return value;
        if (value instanceof List<?> items)
            return items.stream().map(SecurityWireCodec::encode).toList();
        if (!value.getClass().isRecord()
            || value.getClass().getEnclosingClass()
                != com.chaosguide.iam.vertex.client.dto.AccountSecurityOperations.class)
            throw new IllegalArgumentException("A typed security request is required");
        Map<String, Object> out = new LinkedHashMap<>();
        for (RecordComponent c : value.getClass().getRecordComponents()) {
            Object field;
            try {
                field = c.getAccessor().invoke(value);
            } catch (ReflectiveOperationException ex) {
                throw new IllegalArgumentException("Invalid typed security request");
            }
            if (field == null) {
                if (!c.isAnnotationPresent(NullableWire.class))
                    throw new IllegalArgumentException("Missing required security request field");
                continue;
            }
            if (field instanceof String s) {
                text(s);
                if (c.getName().endsWith("Id")
                    && !Set.of("methodId", "requestId").contains(c.getName())
                    && (!c.getName().equals("challengeId")
                        || value instanceof EmailOtpReauthentication))
                    uuid(s);
                if (c.getName().equals("code"))
                    code(s);
            }
            out.put(c.getName(), encode(field));
        }
        if (value instanceof IdentityOperationCreate v) {
            if (v.expectedLoginMethodVersion() < 0)
                throw new IllegalArgumentException("Nonnegative version required");
            String type;
            if (v.payload() instanceof AddIdentity)
                type = "ADD";
            else if (v.payload() instanceof VerifyIdentity)
                type = "VERIFY";
            else if (v.payload() instanceof SetPrimaryIdentity)
                type = "SET_PRIMARY";
            else if (v.payload() instanceof RemoveIdentity)
                type = "REMOVE";
            else if (v.payload() instanceof ReplaceIdentity)
                type = "REPLACE";
            else if (v.payload() instanceof LinkIdentity)
                type = "LINK";
            else if (v.payload() instanceof UnlinkIdentity)
                type = "UNLINK";
            else if (v.payload() instanceof TransferIdentity)
                type = "TRANSFER";
            else
                throw new IllegalArgumentException("Unsupported identity payload");
            out.put("type", type);
        }
        if (value instanceof MfaOperationCreate v && v.expectedLoginMethodVersion() < 0)
            throw new IllegalArgumentException("Nonnegative version required");
        if (value instanceof PasswordReauthentication v) {
            if (v.password().length() > 128)
                throw new IllegalArgumentException("Password exceeds protocol limit");
            out.put("method", "PASSWORD");
        }
        if (value instanceof EmailOtpReauthentication)
            out.put("method", "EMAIL_OTP");
        if (value instanceof IdentityTargetProof)
            out.put("purpose", "TARGET_OWNERSHIP");
        if (value instanceof IdentityOperationComplete v && v.proofs().size() > 1)
            throw new IllegalArgumentException("Zero or one target proof required");
        if (value instanceof ProviderExchange v
            && !v.codeVerifier().matches("[A-Za-z0-9._~-]{43,128}"))
            throw new IllegalArgumentException("Invalid PKCE verifier");
        if (value instanceof MfaProviderAuthorize v)
            pkce(v.codeChallenge(), v.codeChallengeMethod());
        if (value instanceof IdentityProviderAuthorize v)
            pkce(v.codeChallenge(), v.codeChallengeMethod());
        return out;
    }
    private static void pkce(String challenge, String method) {
        if (!"S256".equals(method) || !challenge.matches("[A-Za-z0-9_-]{43}"))
            throw new IllegalArgumentException("An S256 PKCE challenge is required");
    }
    private static JsonNode tree(ObjectMapper mapper, byte[] raw) {
        try {
            return mapper.reader()
                .with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .readTree(raw);
        } catch (java.io.IOException ex) {
            throw new AccountSecurityProtocolException();
        }
    }
    static <T> T decode(ObjectMapper mapper, byte[] raw, TypeReference<T> type) {
        JsonNode root = tree(mapper, raw);
        validate(type.getType(), root);
        try {
            return mapper.readerFor(type)
                .without(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .readValue(root);
        } catch (java.io.IOException | IllegalArgumentException ex) {
            throw new AccountSecurityProtocolException();
        }
    }
    private static void validate(Type type, JsonNode node) {
        if (node == null || node.isNull())
            throw new AccountSecurityProtocolException();
        if (type instanceof ParameterizedType p) {
            if (p.getRawType() == List.class) {
                if (!node.isArray())
                    throw new AccountSecurityProtocolException();
                node.forEach(v -> validate(p.getActualTypeArguments()[0], v));
                return;
            }
            if (p.getRawType() == Map.class) {
                if (!node.isObject())
                    throw new AccountSecurityProtocolException();
                node.fieldNames().forEachRemaining(k
                    -> validate(p.getActualTypeArguments()[0],
                        com.fasterxml.jackson.databind.node.TextNode.valueOf(k)));
                node.forEach(v -> validate(p.getActualTypeArguments()[1], v));
                return;
            }
        }
        if (!(type instanceof Class<?> c))
            throw new AccountSecurityProtocolException();
        if (c == String.class) {
            if (!node.isTextual())
                throw new AccountSecurityProtocolException();
            return;
        }
        if (c == Long.class) {
            if (!node.isIntegralNumber() || !node.canConvertToLong())
                throw new AccountSecurityProtocolException();
            return;
        }
        if (c == Boolean.class) {
            if (!node.isBoolean())
                throw new AccountSecurityProtocolException();
            return;
        }
        if (c.isEnum()) {
            if (!node.isTextual()
                || Arrays.stream(c.getEnumConstants())
                    .noneMatch(v -> ((Enum<?>) v).name().equals(node.textValue())))
                throw new AccountSecurityProtocolException();
            return;
        }
        if (!c.isRecord() || !node.isObject())
            throw new AccountSecurityProtocolException();
        for (RecordComponent f : c.getRecordComponents()) {
            JsonNode v = node.get(f.getName());
            if ((v == null || v.isNull()) && f.isAnnotationPresent(NullableWire.class))
                continue;
            validate(f.getGenericType(), v);
        }
        semantic(c, node);
    }
    private static boolean wireUuid(String value) {
        try {
            return UUID.fromString(value).toString().equals(value);
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }
    private static void semantic(Class<?> type, JsonNode n) {
        if (type == RecoveryCodesRemaining.class
            && (n.path("remaining").asLong() < 0 || n.hasNonNull("codes")
                || n.hasNonNull("recoveryCodes") || n.hasNonNull("material")))
            throw new AccountSecurityProtocolException();
        if (type == MfaOperation.class
            && (n.hasNonNull("material") || n.hasNonNull("recoveryCodes")))
            throw new AccountSecurityProtocolException();
        if (type == ProviderTarget.class
            && (!wireUuid(n.path("providerId").asText())
                || !n.path("reference").asText().matches("[0-9a-f]{64}")))
            throw new AccountSecurityProtocolException();
        if (type == IdentityOperation.class && n.hasNonNull("providerTarget")
            && (!n.path("type").asText().equals("LINK")
                || Set.of("CANCELLED", "EXPIRED", "REJECTED").contains(n.path("state").asText())))
            throw new AccountSecurityProtocolException();
        if (type == IdentifierCapability.class) {
            if (n.path("allowed").asBoolean() != n.path("unavailableReasons").isEmpty())
                throw new AccountSecurityProtocolException();
            n.path("replacementPrimaryIds").forEach(id -> {
                if (!wireUuid(id.asText()))
                    throw new AccountSecurityProtocolException();
            });
        }
        if (type == MfaOperation.class
            && (n.path("state").asText().equals("COMMITTED") != n.path("result").isObject()))
            throw new AccountSecurityProtocolException();
        if (type == MfaAction.class && n.path("allowed").asBoolean()
            && !n.path("proofRequirement").asText().equals("SESSION")
            && n.path("proofOptions").isEmpty())
            throw new AccountSecurityProtocolException();
        if (type == TotpBeginResult.class
            && (n.path("delivery").asText().equals("AVAILABLE") != n.path("material").isObject()
                || n.path("delivery").asText().equals("NOT_APPLICABLE")))
            throw new AccountSecurityProtocolException();
        if (type == MfaCompletionResult.class
            && (n.path("delivery").asText().equals("AVAILABLE")
                != n.path("recoveryCodes").isObject()))
            throw new AccountSecurityProtocolException();
        if (type == RecoveryCodes.class && n.path("count").asLong() != n.path("codes").size())
            throw new AccountSecurityProtocolException();
        if (type == OperationProofOption.class) {
            String method = n.path("method").asText();
            Set<String> expected = switch (method) {
                case "PASSWORD" -> Set.of();
                case "EMAIL_OTP" -> Set.of("identifierId", "maskedIdentifier");
                case "PROVIDER" -> Set.of("methodId", "displayName");
                case "STEP_UP_PROOF" -> Set.of("availableMethods");
                default -> throw new AccountSecurityProtocolException();
            };
            for (String key : Set.of("identifierId", "maskedIdentifier", "methodId", "displayName",
                     "availableMethods")) {
                if (expected.contains(key) != (n.hasNonNull(key)))
                    throw new AccountSecurityProtocolException();
            }
            if (method.equals("STEP_UP_PROOF"))
                n.path("availableMethods").forEach(v -> {
                    if (!Set.of("TOTP", "WEBAUTHN").contains(v.asText()))
                        throw new AccountSecurityProtocolException();
                });
            if (method.equals("EMAIL_OTP")
                && (!n.path("identifierId").isTextual() || !n.path("maskedIdentifier").isTextual()))
                throw new AccountSecurityProtocolException();
            if (method.equals("PROVIDER")
                && (!n.path("methodId").isTextual() || !n.path("displayName").isTextual()))
                throw new AccountSecurityProtocolException();
            if (method.equals("STEP_UP_PROOF")
                && (!n.path("availableMethods").isArray() || n.path("availableMethods").isEmpty()))
                throw new AccountSecurityProtocolException();
        }
    }
    static AccountSecurityException error(
        ObjectMapper mapper, int status, byte[] raw, String retry) {
        JsonNode node = tree(mapper, raw);
        if (node == null || !node.isObject() || !node.path("status").isIntegralNumber()
            || node.path("status").asInt() != status || !node.path("error").isTextual()
            || !node.path("error").asText().matches("[A-Z][A-Z0-9_]{0,127}"))
            throw new AccountSecurityProtocolException();
        Integer delay = null;
        if (retry != null && retry.matches("[0-9]{1,10}")) {
            long parsed = Long.parseLong(retry);
            if (parsed <= Integer.MAX_VALUE)
                delay = (int) parsed;
        }
        return new AccountSecurityException(status, node.path("error").asText(), delay);
    }
}
