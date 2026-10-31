package com.chaosguide.iam.vertex.user;

import com.chaosguide.iam.vertex.IamSecurityProperties;
import com.chaosguide.iam.vertex.client.IamClient;
import com.chaosguide.iam.vertex.context.IamContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class IamUserProfileServiceTest {

    private MockWebServer server;
    private IamUserProfileService service;

    @BeforeEach
    void start() throws Exception {
        server = new MockWebServer();
        server.start();
        IamSecurityProperties props = new IamSecurityProperties();
        props.setUserProfileCacheTtl(Duration.ofMinutes(5));
        IamClient client =
                new IamClient(
                        server.url("/").toString().replaceAll("/+$", ""),
                        "demo-app",
                        "secret",
                        Duration.ofSeconds(5),
                        new ObjectMapper());
        service = new IamUserProfileService(client, props);

        Jwt jwt =
                Jwt.withTokenValue("access-token")
                        .header("alg", "none")
                        .subject("user-1")
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(300))
                        .claim("app_id", "app-1")
                        .claim("roles", List.of("admin"))
                        .build();
        SecurityContextHolder.getContext()
                .setAuthentication(
                        new JwtAuthenticationToken(
                                jwt, List.of(new SimpleGrantedAuthority("ROLE_admin"))));
    }

    @AfterEach
    void stop() throws Exception {
        SecurityContextHolder.clearContext();
        server.shutdown();
    }

    @Test
    void getCurrentProfileCachesAndSupportsBypass() {
        server.enqueue(profile("alice"));
        server.enqueue(profile("alice-fresh"));

        var first = service.getCurrentProfile();
        var second = service.getCurrentProfile();
        var fresh = service.getCurrentProfile(CachePolicy.BYPASS);

        assertThat(first.username()).isEqualTo("alice");
        assertThat(second.username()).isEqualTo("alice");
        assertThat(fresh.username()).isEqualTo("alice-fresh");
        assertThat(server.getRequestCount()).isEqualTo(2);
        assertThat(service.estimatedSize()).isEqualTo(1);
        assertThat(IamContext.currentAccessToken()).contains("access-token");
    }

    private static MockResponse profile(String username) {
        return new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody(
                        """
                        {
                          "userId":"user-1",
                          "applicationId":"app-1",
                          "email":"user@example.com",
                          "username":"%s",
                          "status":"ACTIVE",
                          "emailVerified":true
                        }
                        """
                                .formatted(username));
    }
}
