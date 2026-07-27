package com.chaosguide.iam.vertex.test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.text.ParseException;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(IamMockWebServer.class)
class IamMockWebServerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final OkHttpClient http = new OkHttpClient();

    @Test
    void resolverInjectsAsParameter(IamMockWebServer iam) {
        assertThat(iam).isNotNull();
        assertThat(iam.baseUrl()).startsWith("http://");
        assertThat(iam.raw()).isNotNull();
    }

    @Test
    void issuedTokenContainsSubjectRolesAndIssuer(IamMockWebServer iam) throws ParseException {
        String token = iam.issueToken("alice", Set.of("admin", "editor"));

        SignedJWT jwt = SignedJWT.parse(token);
        var claims = jwt.getJWTClaimsSet();

        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.getAudience()).containsExactly("test-client");
        assertThat(claims.getIssuer()).isEqualTo(iam.baseUrl());
        assertThat(claims.getStringListClaim("roles"))
                .containsExactlyInAnyOrder("admin", "editor");
        assertThat(jwt.getHeader().getKeyID()).isEqualTo("test-kid-1");
    }

    @Test
    void jwksEndpointReturnsPublicKey(IamMockWebServer iam) throws Exception {
        Response resp = http.newCall(new Request.Builder()
                .url(iam.baseUrl() + "/oauth2/jwks")
                .get().build()).execute();

        try (ResponseBody body = resp.body()) {
            assertThat(resp.code()).isEqualTo(200);
            JWKSet set = JWKSet.parse(body.string());
            assertThat(set.getKeys()).hasSize(1);
            assertThat(set.getKeys().get(0).getKeyID()).isEqualTo("test-kid-1");
            assertThat(set.getKeys().get(0).isPrivate()).isFalse();
        }
    }

    @Test
    void resolveEndpointReturnsBoundPermissions(IamMockWebServer iam) throws Exception {
        iam.givenRole("admin").hasPermissions("posts:read", "posts:write");
        iam.givenRole("viewer").hasPermissions("posts:read");

        String body = mapper.writeValueAsString(java.util.Map.of(
                "appId", "app-1", "roles", List.of("admin")));
        Response resp = http.newCall(new Request.Builder()
                .url(iam.baseUrl() + "/open/v1/permissions:resolve")
                .post(RequestBody.create(body, MediaType.get("application/json")))
                .build()).execute();

        try (ResponseBody rb = resp.body()) {
            assertThat(resp.code()).isEqualTo(200);
            JsonNode tree = mapper.readTree(rb.string());
            List<String> perms = new java.util.ArrayList<>();
            tree.path("permissions").forEach(n -> perms.add(n.asText()));
            assertThat(perms).containsExactlyInAnyOrder("posts:read", "posts:write");
        }
    }

    @Test
    void listEndpointReturnsAggregatedPermissionsWithEtag(IamMockWebServer iam) throws Exception {
        iam.givenRole("admin").hasPermissions("posts:read", "posts:write");

        Response resp = http.newCall(new Request.Builder()
                .url(iam.baseUrl() + "/open/v1/apps/app-1/permissions")
                .get().build()).execute();

        try (ResponseBody rb = resp.body()) {
            assertThat(resp.code()).isEqualTo(200);
            assertThat(resp.header("ETag")).isNotBlank();
            JsonNode tree = mapper.readTree(rb.string());
            assertThat(tree.path("roles").isArray()).isTrue();
            assertThat(tree.path("roles").get(0).path("permissions").isArray()).isTrue();
            assertThat(tree.path("roles").get(0).path("permissions").size()).isEqualTo(2);
            assertThat(tree.path("roles").get(0).path("permissions").get(0).asText())
                    .startsWith("posts:");
        }
    }

    @Test
    void unknownPathReturns404(IamMockWebServer iam) throws Exception {
        Response resp = http.newCall(new Request.Builder()
                .url(iam.baseUrl() + "/nope")
                .get().build()).execute();

        assertThat(resp.code()).isEqualTo(404);
        if (resp.body() != null) resp.body().close();
    }
}
