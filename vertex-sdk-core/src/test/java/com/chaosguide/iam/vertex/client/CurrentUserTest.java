package com.chaosguide.iam.vertex.client;

import com.chaosguide.iam.vertex.client.dto.CurrentUserResponse;
import com.chaosguide.iam.vertex.exception.CurrentUserException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import static org.assertj.core.api.Assertions.*;

class CurrentUserTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private JsonNode fixture() throws Exception {
        try (var in = getClass().getResourceAsStream("/current-user.json")) { return mapper.readTree(in); }
    }
    @Test void nullableAndStrictContext() throws Exception {
        var data = fixture();
        var view = CurrentUserResponse.fromJson(data);
        assertThat(view.email()).isNull();
        assertThat(view.authenticationContext().workspaceSelectionRequired()).isTrue();
        assertThat(view.authenticationContext().authTime().toString()).isEqualTo("2026-10-20T01:02:03Z");
        for (var key : new String[]{"applicationId","clientId","sessionId","subjectType","workspaceId","authTime","impersonation","authenticationMethods"}) {
            ObjectNode bad = data.deepCopy();
            ((ObjectNode) bad.get("authenticationContext")).remove(key);
            assertThatThrownBy(() -> CurrentUserResponse.fromJson(bad)).isInstanceOf(IllegalArgumentException.class);
        }
        for (var patch : new String[]{"{\"authTime\":\"yesterday\"}","{\"impersonation\":{\"actorId\":\"actor\"}}","{\"workspaceId\":\"ws\"}","{\"organizationSlug\":\"unbound\"}","{\"subjectType\":\"MACHINE\"}"}) {
            ObjectNode bad = data.deepCopy();
            ((ObjectNode) bad.get("authenticationContext")).setAll((ObjectNode) mapper.readTree(patch));
            assertThatThrownBy(() -> CurrentUserResponse.fromJson(bad)).isInstanceOf(IllegalArgumentException.class);
        }
    }
    @Test void realHttpBearerAndFailure() throws Exception {
        try (var server = new MockWebServer()) {
            server.start();
            var client = new IamClient(server.url("/").toString(), "test-client", "fixture", Duration.ofSeconds(5), mapper);
            server.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setBody(fixture().toString()));
            assertThat(client.getCurrentUser("contract-fixture").email()).isNull();
            var req = server.takeRequest();
            assertThat(req.getPath()).isEqualTo("/api/v1/auth/me");
            assertThat(req.getHeader("Authorization")).isEqualTo("Bearer contract-fixture");
            assertThat(req.getHeader("X-IAM-Client-Id")).isNull();
            for (int status : new int[]{401,403,503}) {
                server.enqueue(new MockResponse().setResponseCode(status).setBody("private"));
                assertThatThrownBy(() -> client.getCurrentUser("contract-fixture"))
                    .isInstanceOfSatisfying(CurrentUserException.class, ex -> assertThat(ex.status()).isEqualTo(status))
                    .hasMessageNotContaining("private");
            }
        }
    }
}
