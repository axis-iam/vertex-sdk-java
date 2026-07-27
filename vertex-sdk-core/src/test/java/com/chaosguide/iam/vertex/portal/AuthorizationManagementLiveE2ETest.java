package com.chaosguide.iam.vertex.portal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.junit.jupiter.api.Test;

class AuthorizationManagementLiveE2ETest {

    @Test
    void permissionLifecycleAgainstSupportedPortalFixture() {
        String clientId = System.getenv("IAM_E2E_CLIENT_ID");
        String clientSecret = System.getenv("IAM_E2E_CLIENT_SECRET");
        assumeTrue(clientId != null && clientSecret != null, "IAM_E2E fixture is not configured");
        var client = new PortalOpenApiClient(PortalOpenApiClientConfig.builder()
                .issuer(required("IAM_E2E_ISSUER"))
                .portalEndpoint(required("IAM_E2E_PORTAL_ENDPOINT"))
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build());
        OpenPermission created = client.createPermission(
                new CreateOpenPermissionRequest("a4_java", "read", "A4 Java", null), "a4-java-create");
        assertThat(created.etag()).matches("\"[0-9]+\"");
        OpenPermission updated = client.updatePermission(created.id(),
                new UpdateOpenPermissionRequest("A4 Java Updated", null), created.etag());
        assertThat(updated.name()).isEqualTo("A4 Java Updated");
        client.deletePermission(updated.id(), updated.etag());
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalStateException(name + " is required");
        return value;
    }
}
