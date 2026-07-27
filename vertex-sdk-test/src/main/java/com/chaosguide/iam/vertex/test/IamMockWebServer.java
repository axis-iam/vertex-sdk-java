package com.chaosguide.iam.vertex.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;

import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 面向 SDK 集成测试的 IAM Mock Server。
 *
 * <p>它同时扮演 JWT issuer、JWKS endpoint、权限解析 endpoint 和权限快照/upsert endpoint，便于接入应用在不启动真实
 * IAM Server 的情况下验证完整安全链路。
 *
 * <pre>
 * &#64;ExtendWith(IamMockWebServer.class)
 * class MyIntegrationTest {
 *   &#64;Test void t(IamMockWebServer iam) {
 *       iam.givenRole("admin").hasPermissions("posts:read");
 *       String token = iam.issueToken("alice", Set.of("admin"));
 *       // ...
 *   }
 * }
 * </pre>
 */
public class IamMockWebServer implements BeforeEachCallback, AfterEachCallback, ParameterResolver {

    private MockWebServer server;
    private RSAKey signingKey;
    private final Map<String, Set<String>> rolePermissions = new LinkedHashMap<>();
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        server = new MockWebServer();
        // 每个测试用例独立生成签名密钥，避免测试之间共享 JWT 状态。
        signingKey = new RSAKeyGenerator(2048).keyID("test-kid-1").generate();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return IamMockWebServer.this.dispatch(request);
            }
        });
        server.start();
        ExtensionContext.Store store = context.getStore(ExtensionContext.Namespace.create(IamMockWebServer.class));
        store.put("self", this);
    }

    @Override
    public void afterEach(ExtensionContext context) throws IOException {
        rolePermissions.clear();
        if (server != null) {
            server.shutdown();
        }
    }

    @Override
    public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext)
            throws ParameterResolutionException {
        return parameterContext.getParameter().getType() == IamMockWebServer.class;
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext)
            throws ParameterResolutionException {
        return this;
    }

    public String baseUrl() {
        return server.url("/").toString().replaceAll("/+$", "");
    }

    public MockWebServer raw() {
        return server;
    }

    public RoleBinding givenRole(String role) {
        return new RoleBinding(role);
    }

    public String issueToken(String subject, Set<String> roles) {
        return issueToken(subject, roles, "test-client", 3600);
    }

    public String issueToken(String subject, Set<String> roles, String audience, long ttlSeconds) {
        try {
            // 测试 token 和真实 IAM token 保持相同的核心契约：sub/aud/issuer/roles，不包含 permissions。
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(signingKey.getKeyID())
                    .type(JOSEObjectType.JWT)
                    .build();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .audience(audience)
                    .issuer(baseUrl())
                    .claim("roles", List.copyOf(roles))
                    .issueTime(Date.from(Instant.now()))
                    .expirationTime(Date.from(Instant.now().plusSeconds(ttlSeconds)))
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new RSASSASigner(signingKey.toPrivateKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to issue test token", e);
        }
    }

    private MockResponse dispatch(RecordedRequest req) {
        String path = req.getPath() == null ? "" : req.getPath();
        if (path.endsWith("/oauth2/jwks")) {
            // Resource Server 通过这个 JWKS 验证 issueToken() 签出的测试 JWT。
            JWKSet set = new JWKSet(signingKey.toPublicJWK());
            return new MockResponse()
                    .setHeader("Content-Type", "application/json")
                    .setBody(set.toString());
        }
        if (path.endsWith("/open/v1/permissions:resolve") && "POST".equalsIgnoreCase(req.getMethod())) {
            // 模拟运行时权限解析：请求里的 roles 合并成最终 permissions。
            return resolveResponse(req);
        }
        if (path.contains("/open/v1/apps/") && path.endsWith("/permissions")
                && "GET".equalsIgnoreCase(req.getMethod())) {
            // 模拟 server 当前快照形态：按角色返回 permissions，而不是直接返回 flat permissions。
            return listResponse();
        }
        return new MockResponse().setResponseCode(404);
    }

    private MockResponse resolveResponse(RecordedRequest req) {
        try {
            var node = mapper.readTree(req.getBody().readUtf8());
            Set<String> roles = new LinkedHashSet<>();
            node.path("roles").forEach(n -> roles.add(n.asText()));
            Set<String> perms = new LinkedHashSet<>();
            for (String r : roles) {
                // 一个用户可能有多个角色，最终权限是所有角色权限的并集。
                perms.addAll(rolePermissions.getOrDefault(r, Set.of()));
            }
            ObjectNode body = mapper.createObjectNode();
            ArrayNode arr = body.putArray("permissions");
            perms.forEach(arr::add);
            return new MockResponse()
                    .setHeader("Content-Type", "application/json")
                    .setBody(mapper.writeValueAsString(body));
        } catch (IOException e) {
            return new MockResponse().setResponseCode(400).setBody(e.getMessage());
        }
    }

    private MockResponse listResponse() {
        ObjectNode body = mapper.createObjectNode();
        body.put("applicationId", "test-application");
        body.put("clientId", "test-client");
        ArrayNode roles = body.putArray("roles");
        for (Map.Entry<String, Set<String>> entry : rolePermissions.entrySet()) {
            // 与真实 IAM Server 对齐：每个角色节点带 key/name/permissions。
            ObjectNode role = roles.addObject();
            role.put("key", entry.getKey());
            role.put("name", entry.getKey());
            ArrayNode permissions = role.putArray("permissions");
            entry.getValue().forEach(permissions::add);
        }
        Set<String> deduped = new LinkedHashSet<>();
        rolePermissions.values().forEach(deduped::addAll);
        try {
            // ETag 只需要稳定表达当前权限集合变化，测试里用 hash 即可。
            return new MockResponse()
                    .setHeader("Content-Type", "application/json")
                    .setHeader("ETag", "\"" + Integer.toHexString(deduped.hashCode()) + "\"")
                    .setBody(mapper.writeValueAsString(body));
        } catch (IOException e) {
            return new MockResponse().setResponseCode(500);
        }
    }

    public final class RoleBinding {
        private final String role;
        private RoleBinding(String role) { this.role = role; }

        /** 给指定角色绑定权限，供 resolve 和 snapshot endpoint 使用。 */
        public IamMockWebServer hasPermissions(String... perms) {
            rolePermissions.computeIfAbsent(role, k -> new LinkedHashSet<>()).addAll(Set.of(perms));
            return IamMockWebServer.this;
        }
    }
}
