package com.chaosguide.iam.vertex.client;

import static org.assertj.core.api.Assertions.*;

import com.chaosguide.iam.vertex.client.dto.AccountSecurityOperations.*;
import com.chaosguide.iam.vertex.exception.AccountSecurityProtocolException;
import com.fasterxml.jackson.databind.*;
import java.time.Duration;
import java.util.*;
import okhttp3.mockwebserver.*;
import org.junit.jupiter.api.Test;

class AccountSecurityManagementTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final UUID ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private JsonNode data() throws Exception {
        try (var in = getClass().getResourceAsStream("/account-security-management.json")) {
            return MAPPER.readTree(in);
        }
    }
    private IamClient client(MockWebServer server) {
        return new IamClient(
            server.url("/").toString(), "client", "fixture-secret", Duration.ofSeconds(2), MAPPER);
    }
    private MockResponse response(JsonNode node) {
        return new MockResponse().setBody(node.toString());
    }
    @Test
    void providerTargetNullableAndCompatibleFields() throws Exception {
        try (var server = new MockWebServer()) {
            server.start();
            var client = client(server);
            for (var wire : data().path("validOperations")) {
                server.enqueue(response(wire));
                var operation = client.getIdentityOperation("current-user", ID);
                var expected = wire.get("providerTarget");
                if (expected == null || expected.isNull())
                    assertThat(operation.providerTarget()).isNull();
                else {
                    var target = operation.providerTarget();
                    assertThat(target.providerId()).isEqualTo(expected.path("providerId").asText());
                    assertThat(target.reference()).isEqualTo(expected.path("reference").asText());
                    assertThat(target.maskedDisplayName())
                        .isEqualTo(expected.path("maskedDisplayName").asText(null));
                    assertThat(target.maskedEmail())
                        .isEqualTo(expected.path("maskedEmail").asText(null));
                }
                assertThat(server.takeRequest().getHeader("Authorization"))
                    .isEqualTo("Bearer current-user");
            }
        }
    }
    @Test
    void providerTargetRejectsMalformedKnownFields() throws Exception {
        try (var server = new MockWebServer()) {
            server.start();
            var client = client(server);
            for (var wire : data().path("invalidOperations")) {
                server.enqueue(response(wire));
                assertThatThrownBy(() -> client.getIdentityOperation("current-user", ID))
                    .isInstanceOf(AccountSecurityProtocolException.class);
            }
        }
    }
    @Test
    void authenticatedManagementSnapshot() throws Exception {
        try (var server = new MockWebServer()) {
            server.start();
            var client = client(server);
            for (var wire : data().path("validSnapshots")) {
                server.enqueue(response(wire));
                var snapshot = client.listAccountIdentifiers("current-user");
                if (!wire.hasNonNull("management")) {
                    assertThat(snapshot.management()).isNull();
                    assertThat(snapshot.items()).allMatch(i -> i.capabilities() == null);
                } else {
                    assertThat(snapshot.management().add())
                        .containsOnlyKeys(IdentifierKind.values());
                    assertThat(snapshot.management().proofOptions()).hasSize(4);
                    assertThat(snapshot.management().add().get(IdentifierKind.EMAIL).allowed())
                        .isTrue();
                    var capabilities = snapshot.items().get(0).capabilities();
                    assertThat(capabilities).containsOnlyKeys(IdentifierAction.values());
                    assertThat(capabilities.get(IdentifierAction.REMOVE).replacementPrimaryIds())
                        .containsExactly("00000000-0000-0000-0000-000000000002");
                    assertThat(capabilities.get(IdentifierAction.REMOVE).allowed()).isTrue();
                    assertThat(capabilities.get(IdentifierAction.TRANSFER).unavailableReasons())
                        .containsExactly(IdentifierDenial.IDENTIFIER_RANGE_REJECTED);
                }
                assertThat(server.takeRequest().getPath()).isEqualTo("/api/v1/auth/me/identifiers");
            }
        }
    }
    @Test
    void managementRejectsMalformedKnownFields() throws Exception {
        try (var server = new MockWebServer()) {
            server.start();
            var client = client(server);
            for (var wire : data().path("invalidSnapshots")) {
                server.enqueue(response(wire));
                assertThatThrownBy(() -> client.listAccountIdentifiers("current-user"))
                    .isInstanceOf(AccountSecurityProtocolException.class);
            }
        }
    }
    @Test
    void actualAdapterTargetSurvivesCallbackReplayAndCommittedRead() throws Exception {
        try (var server = new MockWebServer()) {
            server.start();
            var client = client(server);
            var cases = data().path("validOperations");
            server.enqueue(response(cases.get(0)));
            server.enqueue(response(cases.get(0)));
            server.enqueue(response(cases.get(1)));
            var first = client.completeIdentityProviderAuthorization(
                "current-user", ID, new ProviderExchange(ID.toString(), "v".repeat(43)));
            var replay = client.getIdentityOperation("current-user", ID);
            var committed = client.getIdentityOperation("current-user", ID);
            assertThat(first.providerTarget())
                .isEqualTo(replay.providerTarget())
                .isEqualTo(committed.providerTarget());
            assertThat(server.getRequestCount()).isEqualTo(3);
            var request = server.takeRequest();
            assertThat(request.getPath()).endsWith("/provider-callback");
            assertThat(MAPPER.readTree(request.getBody().readUtf8()).path("codeVerifier").asText())
                .isEqualTo("v".repeat(43));
        }
    }
    @Test
    void futureMfaFieldsDoNotPermitSensitiveStatusRedelivery() throws Exception {
        try (var server = new MockWebServer()) {
            server.start();
            var client = client(server);
            for (var wire : data().path("invalidMfaStatus")) {
                server.enqueue(response(wire));
                assertThatThrownBy(() -> client.getMfaOperation("current-user", ID))
                    .isInstanceOf(AccountSecurityProtocolException.class);
            }
            server.enqueue(response(data().path("validExtendedMfa").get(0)));
            assertThat(client.getMfaCapabilities("current-user").loginMethodVersion())
                .isEqualTo(4L);
        }
    }
}
