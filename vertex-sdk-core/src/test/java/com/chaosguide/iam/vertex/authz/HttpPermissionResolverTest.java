package com.chaosguide.iam.vertex.authz;

import com.chaosguide.iam.vertex.IamSecurityProperties;
import com.chaosguide.iam.vertex.client.IamClient;
import com.chaosguide.iam.vertex.exception.IamSdkException;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HttpPermissionResolverTest {

    private MockWebServer server;
    private IamSecurityProperties props;
    private IamClient client;

    @BeforeEach
    void start() throws Exception {
        server = new MockWebServer();
        server.start();
        props = new IamSecurityProperties();
        props.setEndpoint(server.url("/").toString().replaceAll("/+$", ""));
        props.setClientId("test-app");
        props.setClientSecret("secret");
        props.setPermissionCacheTtl(Duration.ofMinutes(5));
        props.setPermissionCacheMaxSize(100);
        client = new IamClient(props.getEndpoint(), props.getClientId(), props.getClientSecret(),
                Duration.ofSeconds(5), new ObjectMapper());
    }

    @AfterEach
    void stop() throws Exception {
        server.shutdown();
    }

    @Test
    void cachesResultsByRoleSet() throws Exception {
        server.enqueue(jsonResponse("{\"permissions\":[\"posts:read\",\"posts:write\"]}"));
        HttpPermissionResolver resolver = new HttpPermissionResolver(client, props);

        Set<String> first = resolver.resolve("test-app", Set.of("admin"));
        Set<String> second = resolver.resolve("test-app", Set.of("admin"));

        assertThat(first).containsExactlyInAnyOrder("posts:read", "posts:write");
        assertThat(second).isSameAs(first);
        assertThat(server.getRequestCount()).isEqualTo(1);
    }

    @Test
    void cacheKeyIsOrderIndependent() throws Exception {
        server.enqueue(jsonResponse("{\"permissions\":[\"posts:read\"]}"));
        HttpPermissionResolver resolver = new HttpPermissionResolver(client, props);

        resolver.resolve("test-app", Set.of("a", "b"));
        resolver.resolve("test-app", Set.of("b", "a"));

        assertThat(server.getRequestCount()).isEqualTo(1);
    }

    @Test
    void usesConfiguredApplicationClientIdInsteadOfJwtApplicationId() throws Exception {
        server.enqueue(jsonResponse("{\"permissions\":[\"posts:read\"]}"));
        HttpPermissionResolver resolver = new HttpPermissionResolver(client, props);

        Set<String> a = resolver.resolve("app-a", Set.of("admin"));
        Set<String> b = resolver.resolve("app-b", Set.of("admin"));

        assertThat(a).containsExactly("posts:read");
        assertThat(b).isSameAs(a);
        assertThat(server.getRequestCount()).isEqualTo(1);
        RecordedRequest req = server.takeRequest();
        assertThat(req.getBody().readUtf8()).contains("\"clientId\":\"test-app\"");
    }

    @Test
    void emptyRolesShortCircuits() {
        HttpPermissionResolver resolver = new HttpPermissionResolver(client, props);
        assertThat(resolver.resolve("test-app", Set.of())).isEmpty();
        assertThat(server.getRequestCount()).isZero();
    }

    @Test
    void failModeCloseThrows() {
        server.enqueue(new MockResponse().setResponseCode(500));
        props.setFailMode(FailMode.CLOSE);
        HttpPermissionResolver resolver = new HttpPermissionResolver(client, props);

        assertThatThrownBy(() -> resolver.resolve("test-app", Set.of("admin")))
                .isInstanceOf(IamSdkException.class);
    }

    @Test
    void failModeOpenReturnsEmpty() {
        server.enqueue(new MockResponse().setResponseCode(500));
        props.setFailMode(FailMode.OPEN);
        HttpPermissionResolver resolver = new HttpPermissionResolver(client, props);

        assertThat(resolver.resolve("test-app", Set.of("admin"))).isEmpty();
    }

    @Test
    void sendsClientIdAndRolesInRequestBody() throws Exception {
        server.enqueue(jsonResponse("{\"permissions\":[]}"));
        HttpPermissionResolver resolver = new HttpPermissionResolver(client, props);

        resolver.resolve("test-app", Set.of("alpha", "beta"));

        RecordedRequest req = server.takeRequest();
        assertThat(req.getPath()).isEqualTo("/open/v1/permissions:resolve");
        String body = req.getBody().readUtf8();
        assertThat(body).contains("\"clientId\":\"test-app\"");
        assertThat(body).contains("alpha").contains("beta");
    }

    @Test
    void invalidateAllClearsCache() throws Exception {
        server.enqueue(jsonResponse("{\"permissions\":[\"posts:read\"]}"));
        server.enqueue(jsonResponse("{\"permissions\":[\"posts:read\"]}"));
        HttpPermissionResolver resolver = new HttpPermissionResolver(client, props);
        resolver.resolve("test-app", Set.of("admin"));
        resolver.invalidateAll();
        resolver.resolve("test-app", Set.of("admin"));

        assertThat(server.getRequestCount()).isEqualTo(2);
        assertThat(resolver.estimatedSize()).isGreaterThanOrEqualTo(1);
    }

    private MockResponse jsonResponse(String body) {
        return new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }
}
