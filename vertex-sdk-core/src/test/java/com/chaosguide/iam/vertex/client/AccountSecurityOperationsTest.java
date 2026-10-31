package com.chaosguide.iam.vertex.client;

import static org.assertj.core.api.Assertions.*;

import com.chaosguide.iam.vertex.client.dto.AccountSecurityOperations.*;
import com.chaosguide.iam.vertex.exception.*;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Duration;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.IntStream;
import okhttp3.mockwebserver.*;
import org.junit.jupiter.api.Test;

class AccountSecurityOperationsTest {
    private static final UUID ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private JsonNode fixture() throws Exception {
        try (var in = getClass().getResourceAsStream("/account-security-contract.json")) {
            return MAPPER.readTree(in);
        }
    }
    private IamClient client(MockWebServer server) {
        return new IamClient(server.url("/").toString(), "configured-client", "configured-secret",
            Duration.ofSeconds(2), MAPPER);
    }
    private MockResponse json(JsonNode body) {
        return new MockResponse()
            .setHeader("Content-Type", "application/json")
            .setBody(body.toString());
    }

    @Test
    void publicOperationMatrix() throws Exception {
        var cases = fixture().path("cases");
        List<Consumer<IamClient>> calls = List.of(c
            -> assertThat(c.listAccountIdentifiers("Bearer current-user")).isNotNull(),
            c
            -> assertThat(c.listAccountLoginMethods("Bearer current-user")).isNotNull(),
            c
            -> assertThat(c.listLinkableIdentityProviders("Bearer current-user")).isNotNull(),
            c
            -> assertThat(c.createIdentityOperation("Bearer current-user",
                              new IdentityOperationCreate(4L,
                                  new AddIdentity(new LoginIdentifier(
                                      IdentifierKind.EMAIL, "new@example.test", null))),
                              "retained-key"))
                .isNotNull(),
            c
            -> assertThat(c.getIdentityOperation("Bearer current-user", ID)).isNotNull(),
            c
            -> assertThat(c.listIdentityTransfers("Bearer current-user")).isNotNull(),
            c
            -> assertThat(c.reauthenticateIdentityOperation("Bearer current-user", ID,
                              new PasswordReauthentication("fixture-password")))
                .isNotNull(),
            c
            -> assertThat(c.challengeIdentityOperation(
                              "Bearer current-user", ID, TargetProofMethod.EMAIL_OTP))
                .isNotNull(),
            c
            -> assertThat(c.challengeIdentityCurrentAccount("Bearer current-user", ID, ID))
                .isNotNull(),
            c
            -> assertThat(c.completeIdentityOperation(
                              "Bearer current-user", ID, new IdentityOperationComplete(List.of())))
                .isNotNull(),
            c
            -> assertThat(c.cancelIdentityOperation("Bearer current-user", ID)).isNotNull(),
            c
            -> assertThat(
                c.confirmIdentityTransfer("Bearer current-user", ID, TransferDecision.ACCEPT))
                .isNotNull(),
            c
            -> assertThat(c.authorizeIdentityOperation("Bearer current-user", ID,
                              new IdentityProviderAuthorize(AuthorizationPurpose.CURRENT_ACCOUNT,
                                  "https://app.example.test/callback", "c".repeat(43), "S256",
                                  "identity:linked")))
                .isNotNull(),
            c
            -> assertThat(c.completeIdentityProviderAuthorization("Bearer current-user", ID,
                              new ProviderExchange(ID.toString(), "v".repeat(43))))
                .isNotNull(),
            c
            -> assertThat(c.getMfaCapabilities("Bearer current-user")).isNotNull(),
            c
            -> assertThat(
                c.createMfaOperation("Bearer current-user",
                    new MfaOperationCreate(MfaOperationType.TOTP_ENROLL, 4L), "retained-key"))
                .isNotNull(),
            c
            -> assertThat(c.getMfaOperation("Bearer current-user", ID)).isNotNull(),
            c
            -> assertThat(c.reauthenticateMfaOperation("Bearer current-user", ID,
                              new PasswordReauthentication("fixture-password")))
                .isNotNull(),
            c
            -> assertThat(c.challengeMfaOperation("Bearer current-user", ID, ID)).isNotNull(),
            c
            -> assertThat(c.authorizeMfaOperation("Bearer current-user", ID,
                              new MfaProviderAuthorize("identity:linked",
                                  "https://app.example.test/callback", "c".repeat(43), "S256")))
                .isNotNull(),
            c
            -> assertThat(c.completeMfaProviderAuthorization("Bearer current-user", ID,
                              new ProviderExchange(ID.toString(), "v".repeat(43))))
                .isNotNull(),
            c
            -> assertThat(c.beginTotpEnrollmentOperation("Bearer current-user", ID)).isNotNull(),
            c
            -> assertThat(c.completeMfaOperation("Bearer current-user", ID, null)).isNotNull(),
            c
            -> assertThat(c.cancelMfaOperation("Bearer current-user", ID)).isNotNull(),
            c
            -> assertThat(c.startIdentityOperationStepUp("Bearer current-user", ID)).isNotNull(),
            c
            -> assertThat(c.verifyIdentityOperationStepUp("Bearer current-user", ID,
                              new OperationStepUpVerify("scoped-challenge", "123456")))
                .isNotNull(),
            c
            -> assertThat(
                c.startIdentityOperationWebAuthn("Bearer current-user", ID, "scoped-challenge"))
                .isNotNull(),
            c
            -> assertThat(c.verifyIdentityOperationWebAuthn("Bearer current-user", ID,
                              new OperationWebAuthnVerify(
                                  "scoped-challenge", "scoped-request", "fixture-credential")))
                .isNotNull(),
            c
            -> assertThat(c.startMfaOperationStepUp("Bearer current-user", ID)).isNotNull(),
            c
            -> assertThat(c.verifyMfaOperationStepUp("Bearer current-user", ID,
                              new OperationStepUpVerify("scoped-challenge", "123456")))
                .isNotNull(),
            c
            -> assertThat(
                c.startMfaOperationWebAuthn("Bearer current-user", ID, "scoped-challenge"))
                .isNotNull(),
            c
            -> assertThat(c.verifyMfaOperationWebAuthn("Bearer current-user", ID,
                              new OperationWebAuthnVerify(
                                  "scoped-challenge", "scoped-request", "fixture-credential")))
                .isNotNull());
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            var c = client(server);
            for (int i = 0; i < calls.size(); i++) {
                var expected = cases.get(i);
                server.enqueue(json(expected.path("response")));
                calls.get(i).accept(c);
                var request = server.takeRequest();
                assertThat(request.getPath()).isEqualTo(expected.path("path").asText());
                assertThat(request.getMethod()).isEqualTo(expected.path("method").asText());
                assertThat(request.getHeader("Authorization")).isEqualTo("Bearer current-user");
                assertThat(request.getHeaders().toString()).doesNotContain("configured-secret");
                if (!expected.path("body").isNull())
                    assertThat(MAPPER.readTree(request.getBody().readUtf8()))
                        .isEqualTo(expected.path("body"));
                else
                    assertThat(request.getBody().size()).isZero();
                if (expected.path("name").asText().startsWith("create_"))
                    assertThat(request.getHeader("Idempotency-Key")).isEqualTo("retained-key");
            }
            assertThat(server.getRequestCount()).isEqualTo(32);
        }
    }

    @Test
    void firstAndRepeatedSensitiveDeliveryAndRecovery() throws Exception {
        var samples = fixture().path("samples");
        var pending = samples.path("MfaOperation");
        var committed = pending.deepCopy();
        ((ObjectNode) committed)
            .put("type", "RECOVERY_CODES_GENERATE")
            .put("state", "COMMITTED")
            .set("result", samples.path("MfaOperationResult"));
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            var c = client(server);
            server.enqueue(json(samples.path("TotpBeginResult")));
            var once = c.beginTotpEnrollmentOperation("current-user", ID);
            assertThat(once.material().secret()).isEqualTo("fixture-material");
            assertThat(once.toString()).doesNotContain("fixture-material");
        }
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            var c = client(server);
            var repeated = MAPPER.createObjectNode().put("delivery", "ALREADY_DELIVERED");
            repeated.set("operation", pending);
            repeated.putNull("material");
            server.enqueue(json(repeated));
            assertThat(c.beginTotpEnrollmentOperation("current-user", ID).material()).isNull();
            var first = MAPPER.createObjectNode().put("delivery", "AVAILABLE");
            first.set("operation", committed);
            first.set("recoveryCodes", samples.path("RecoveryCodes"));
            server.enqueue(json(first));
            var completion = c.completeMfaOperation("current-user", ID, null);
            assertThat(completion.recoveryCodes().codes()).containsExactly("fixture-code");
            assertThat(completion.toString()).doesNotContain("fixture-code");
            var replay = MAPPER.createObjectNode().put("delivery", "ALREADY_DELIVERED");
            replay.set("operation", committed);
            replay.putNull("recoveryCodes");
            server.enqueue(json(replay));
            assertThat(c.completeMfaOperation("current-user", ID, null).recoveryCodes()).isNull();
            server.enqueue(json(committed));
            assertThat(c.getMfaOperation("new-session-same-owner", ID).result().sessionImpact())
                .isEqualTo(SessionImpact.CURRENT_SESSION_RETAINED);
            var cancelled = pending.deepCopy();
            ((ObjectNode) cancelled).put("state", "CANCELLED");
            server.enqueue(json(cancelled));
            assertThat(c.cancelMfaOperation("current-user", ID).state())
                .isEqualTo(MfaOperationState.CANCELLED);
        }
    }

    @Test
    void typedErrorsRetryDelayAndNoSensitiveDiagnostics() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            var c = client(server);
            for (String delay : List.of("60", "-1", "1.2", "99999999999999")) {
                server.enqueue(new MockResponse()
                        .setResponseCode(429)
                        .setHeader("Retry-After", delay)
                        .setBody("{\"status\":429,\"error\":\"OPERATION_PROOF_RATE_"
                            + "LIMITED\",\"message\":\"provider-secret\"}"));
                var ex =
                    catchThrowableOfType(()
                                             -> c.completeMfaOperation("current-user", ID, null),
                        AccountSecurityException.class);
                assertThat(ex.code()).isEqualTo("OPERATION_PROOF_RATE_LIMITED");
                assertThat(ex.status()).isEqualTo(429);
                assertThat(ex.retryAfterSeconds()).isEqualTo(delay.equals("60") ? 60 : null);
                assertThat(ex).hasMessageNotContaining("provider-secret");
            }
            assertThat(server.getRequestCount()).isEqualTo(4);
        }
    }

    @Test
    void strictMissingDuplicateNullAndCompatibleExtensions() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            var c = client(server);
            for (String body : List.of("{}", "null", "{} {}", "{\"id\":1,\"id\":2}")) {
                server.enqueue(new MockResponse().setBody(body));
                assertThatThrownBy(() -> c.getMfaCapabilities("current-user"))
                    .isInstanceOf(AccountSecurityProtocolException.class);
            }
            var broken = fixture().path("samples").path("MfaCapabilities").deepCopy();
            ((ObjectNode) broken).put("unknown", true);
            server.enqueue(json(broken));
            assertThat(c.getMfaCapabilities("current-user").loginMethodVersion()).isEqualTo(4L);
        }
    }

    @Test
    void strictRequestsAndCurrentUserContext() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            var c = client(server);
            assertThatThrownBy(() -> c.getMfaCapabilities(""))
                .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> c.getMfaOperation("current-user", null))
                .isInstanceOf(NullPointerException.class);
            assertThatThrownBy(
                ()
                    -> c.createMfaOperation("current-user",
                        new MfaOperationCreate(MfaOperationType.TOTP_ENROLL, -1L), "key"))
                .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(
                ()
                    -> c.createMfaOperation("current-user",
                        new MfaOperationCreate(MfaOperationType.TOTP_ENROLL, 4L), ""))
                .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> c.completeMfaOperation("current-user", ID, ""))
                .isInstanceOf(IllegalArgumentException.class);
            assertThat(server.getRequestCount()).isZero();
            server.enqueue(new MockResponse().setResponseCode(403).setBody(
                "{\"status\":403,\"error\":\"FORBIDDEN\",\"message\":\"no current user\"}"));
            assertThatThrownBy(()
                                   -> c.reauthenticateMfaOperation("machine-token", ID,
                                       new EmailOtpReauthentication(ID.toString(), "123456")))
                .isInstanceOf(AccountSecurityException.class);
            var req = server.takeRequest();
            assertThat(req.getHeader("Authorization")).isEqualTo("Bearer machine-token");
            assertThat(MAPPER.readTree(req.getBody().readUtf8()))
                .isEqualTo(MAPPER.readTree("{\"method\":\"EMAIL_OTP\",\"challengeId\":\"" + ID
                    + "\",\"code\":\"123456\"}"));
        }
    }

    @Test
    void lostMutationResponseAndInterruptionDoNotReplay() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            var c = client(server);
            server.enqueue(
                new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST));
            assertThatThrownBy(() -> c.completeMfaOperation("current-user", ID, null))
                .isInstanceOfSatisfying(AccountSecurityTransportException.class,
                    e -> assertThat(e.outcomeUnknown()).isTrue());
            server.enqueue(json(fixture().path("samples").path("MfaOperation")));
            assertThat(c.getMfaOperation("new-session-same-owner", ID).id())
                .isEqualTo(ID.toString());
            assertThat(server.getRequestCount()).isEqualTo(2);
            Thread.currentThread().interrupt();
            try {
                assertThatThrownBy(() -> c.getMfaCapabilities("current-user"))
                    .isInstanceOf(AccountSecurityTransportException.class);
                assertThat(Thread.currentThread().isInterrupted()).isTrue();
            } finally {
                Thread.interrupted();
            }
            assertThat(server.getRequestCount()).isEqualTo(2);
        }
    }
    @Test
    void serviceUnavailableZeroRetryAfterCannotReplayOneShotMutation() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            var c = client(server);
            server.enqueue(new MockResponse()
                    .setResponseCode(503)
                    .setHeader("Retry-After", "0")
                    .setBody("{\"status\":503,\"error\":\"OPERATION_DEPENDENCY_"
                        + "UNAVAILABLE\",\"message\":\"unavailable\"}"));
            assertThatThrownBy(() -> c.completeMfaOperation("current-user", ID, null))
                .isInstanceOf(AccountSecurityException.class);
            assertThat(server.getRequestCount()).isEqualTo(1);
        }
    }
    @Test
    void identityPayloadVariantsAndCounterpartRedaction() throws Exception {
        var payloads = List.of(
            new AddIdentity(new LoginIdentifier(IdentifierKind.EMAIL, "new@example.test", null)),
            new VerifyIdentity(ID.toString()), new SetPrimaryIdentity(ID.toString()),
            new RemoveIdentity(ID.toString(), null),
            new ReplaceIdentity(ID.toString(),
                new LoginIdentifier(IdentifierKind.USERNAME, "new-name", null), false, null),
            new LinkIdentity(ID.toString()), new UnlinkIdentity("identity:linked"),
            new TransferIdentity(ID.toString(), ID.toString(), null));
        var kinds = List.of(
            "ADD", "VERIFY", "SET_PRIMARY", "REMOVE", "REPLACE", "LINK", "UNLINK", "TRANSFER");
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            var c = client(server);
            for (int i = 0; i < payloads.size(); i++) {
                for (int retry = 0; retry < 2; retry++) {
                    server.enqueue(json(fixture().path("samples").path("IdentityOperation")));
                    assertThat(
                        c.createIdentityOperation("current-user",
                             new IdentityOperationCreate(4L, (IdentityPayload) payloads.get(i)),
                             "retained-key")
                            .id())
                        .isEqualTo(ID.toString());
                    var req = server.takeRequest();
                    var body = MAPPER.readTree(req.getBody().readUtf8());
                    assertThat(body.path("type").asText()).isEqualTo(kinds.get(i));
                    assertThat(body.size()).isEqualTo(3);
                    assertThat(body.path("payload").isObject()).isTrue();
                    assertThat(req.getHeader("Idempotency-Key")).isEqualTo("retained-key");
                }
            }
            var counterpart = fixture().path("samples").path("IdentityOperation").deepCopy();
            ((ObjectNode) counterpart)
                .put("type", "TRANSFER")
                .put("state", "COMMITTED")
                .putNull("result")
                .putNull("completion");
            server.enqueue(json(counterpart));
            assertThat(c.getIdentityOperation("counterpart-user", ID).completion()).isNull();
        }
    }
    @Test
    void springBeanUsesTheSamePublicOperations() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            server.start();
            server.enqueue(json(fixture().path("samples").path("MfaCapabilities")));
            new org.springframework.boot.test.context.runner.ApplicationContextRunner()
                .withConfiguration(org.springframework.boot.autoconfigure.AutoConfigurations.of(
                    com.chaosguide.iam.vertex.config.IamSecurityAutoConfiguration.class))
                .withPropertyValues("iam.sdk.endpoint=" + server.url("/"),
                    "iam.sdk.client-id=client", "iam.sdk.client-secret=secret")
                .run(context
                    -> assertThat(context.getBean(IamClient.class)
                                      .getMfaCapabilities("current-user")
                                      .loginMethodVersion())
                        .isEqualTo(4L));
            assertThat(server.getRequestCount()).isEqualTo(1);
        }
    }
}
