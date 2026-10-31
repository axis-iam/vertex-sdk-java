package com.chaosguide.iam.vertex.client;

import static org.assertj.core.api.Assertions.*;

import com.chaosguide.iam.vertex.client.dto.AccountSecurityOperations.*;
import com.chaosguide.iam.vertex.exception.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import okhttp3.mockwebserver.*;
import org.junit.jupiter.api.Test;

class AccountSecurityRemediationTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String ROOT = "/api/v1/auth/mfa";
    private static final UUID ID = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private IamClient client(MockWebServer server) {
        return new IamClient(
            server.url("/").toString(), "client", "fixture-secret", Duration.ofSeconds(2), JSON);
    }
    private static String operation(boolean committed) {
        return "{\"id\":\"" + ID + "\",\"type\":\"RECOVERY_CODES_GENERATE\",\"state\":\""
            + (committed ? "COMMITTED" : "READY")
            + ("\",\"createdAt\":\"2026-10-31T00:00:00Z\",\"expiresAt\":\"2026-10-31T00:10:00Z\","
               + "\"expectedLoginMethodVersion\":4,\"proofRequirement\":\"SESSION\","
               + "\"proofOptions\":[],\"proofSatisfied\":true,\"result\":")
            + (committed ? "{\"completedAt\":\"2026-10-31T00:00:00Z\",\"finalLoginMethodVersion\":"
                           + "5,\"sessionImpact\":\"CURRENT_SESSION_RETAINED\",\"recoveryCount\":5}"
                         : "null")
            + "}";
    }
    @Test
    void liveRemainingIsOwnerBoundAndNotGenerationTimeCount() throws Exception {
        var remaining = new AtomicLong(0);
        var calls = new ArrayList<String>();
        try (var server = new MockWebServer()) {
            server.setDispatcher(new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest request) {
                    calls.add(request.getMethod() + " " + request.getPath());
                    String owner = request.getHeader("Authorization");
                    if (!Set.of("Bearer owner-a", "Bearer owner-b").contains(owner))
                        return new MockResponse().setResponseCode(401).setBody(
                            "{\"status\":401,\"error\":\"UNAUTHORIZED\",\"message\":\"private-"
                            + "diagnostic\"}");
                    String path = request.getPath();
                    if ((ROOT + "/recovery-codes/remaining").equals(path)) {
                        if (!"GET".equals(request.getMethod()) || request.getBodySize() != 0)
                            return new MockResponse().setResponseCode(400);
                        long count = "Bearer owner-b".equals(owner) ? 2 : remaining.get();
                        return new MockResponse().setBody(
                            "{\"remaining\":" + count + ",\"future\":true}");
                    }
                    if ((ROOT + "/operations").equals(path)) {
                        if (!"retained-key".equals(request.getHeader("Idempotency-Key")))
                            return new MockResponse().setResponseCode(400);
                        return new MockResponse().setResponseCode(201).setBody(operation(false));
                    }
                    if (path.endsWith("/complete")) {
                        remaining.set(5);
                        return new MockResponse().setBody("{\"operation\":" + operation(true)
                            + (",\"delivery\":\"AVAILABLE\",\"recoveryCodes\":{\"codes\":["
                               + "\"fixture-0\",\"fixture-1\",\"fixture-2\",\"fixture-3\","
                               + "\"fixture-4\"],\"count\":5}}"));
                    }
                    if ((ROOT + "/recovery-codes/verify").equals(path)) {
                        remaining.decrementAndGet();
                        return new MockResponse().setBody("{\"verified\":true}");
                    }
                    return new MockResponse().setResponseCode(404);
                }
            });
            server.start();
            var client = client(server);
            assertThat(client.getRecoveryCodesRemaining("owner-a").remaining()).isZero();
            var created = client.createMfaOperation("owner-a",
                new MfaOperationCreate(MfaOperationType.RECOVERY_CODES_GENERATE, 4L),
                "retained-key");
            var generated =
                client.completeMfaOperation("owner-a", UUID.fromString(created.id()), null);
            assertThat(generated.operation().result().recoveryCount()).isEqualTo(5L);
            assertThat(client.getRecoveryCodesRemaining("owner-a").remaining()).isEqualTo(5L);
            var verification =
                HttpRequest
                    .newBuilder(URI.create(server.url(ROOT + "/recovery-codes/verify").toString()))
                    .header("Authorization", "Bearer owner-a")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"code\":\"fixture-0\"}"))
                    .build();
            assertThat(HttpClient.newHttpClient()
                           .send(verification, HttpResponse.BodyHandlers.ofString())
                           .statusCode())
                .isEqualTo(200);
            assertThat(client.getRecoveryCodesRemaining("owner-a").remaining())
                .isEqualTo(4L)
                .isNotEqualTo(generated.operation().result().recoveryCount());
            assertThat(client.getRecoveryCodesRemaining("owner-b").remaining()).isEqualTo(2L);
            assertThat(RecoveryCodesRemaining.class.getRecordComponents())
                .extracting("name")
                .containsExactly("remaining");
            assertThatThrownBy(() -> client.getRecoveryCodesRemaining("bad-owner"))
                .isInstanceOfSatisfying(AccountSecurityException.class, e -> {
                    assertThat(e.status()).isEqualTo(401);
                    assertThat(e.code()).isEqualTo("UNAUTHORIZED");
                    assertThat(e.getMessage()).doesNotContain("private-diagnostic");
                });
            assertThat(calls.stream().filter(s -> s.endsWith("/complete")).count()).isEqualTo(1);
            assertThat(calls.stream().filter(s -> s.endsWith("/verify")).count()).isEqualTo(1);
        }
    }
    @Test
    void remainingDtoErrorsAndExplicitBearerAreStrict() throws Exception {
        try (var server = new MockWebServer()) {
            server.start();
            var client = client(server);
            assertThatThrownBy(() -> client.getRecoveryCodesRemaining(""))
                .isInstanceOf(IllegalArgumentException.class);
            assertThat(server.getRequestCount()).isZero();
            for (String body : List.of("{}", "{\"remaining\":null}", "{\"remaining\":true}",
                     "{\"remaining\":-1}", "{\"remaining\":1.5}",
                     "{\"remaining\":9223372036854775808}", "{\"remaining\":1,\"remaining\":2}",
                     "{\"remaining\":1,\"codes\":[\"not-a-live-code\"]}")) {
                server.enqueue(new MockResponse().setBody(body));
                assertThatThrownBy(() -> client.getRecoveryCodesRemaining("owner-a"))
                    .isInstanceOf(AccountSecurityProtocolException.class);
            }
            server.enqueue(new MockResponse()
                    .setResponseCode(429)
                    .setHeader("Retry-After", "2")
                    .setBody("{\"status\":429,\"error\":\"OPERATION_PROOF_RATE_LIMITED\"}"));
            assertThatThrownBy(() -> client.getRecoveryCodesRemaining("owner-a"))
                .isInstanceOfSatisfying(AccountSecurityException.class,
                    e -> assertThat(e.retryAfterSeconds()).isEqualTo(2));
        }
    }
}
