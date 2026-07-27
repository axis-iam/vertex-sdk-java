package com.chaosguide.iam.vertex.config;

import com.chaosguide.iam.vertex.authz.PermissionResolver;
import com.chaosguide.iam.vertex.authz.HighRiskGuardAspect;
import com.chaosguide.iam.vertex.authz.RequirePermAspect;
import com.chaosguide.iam.vertex.client.IamClient;
import com.chaosguide.iam.vertex.IamSecurityProperties;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class IamSecurityAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IamSecurityAutoConfiguration.class));

    @Test
    void doesNotCreateNetworkBackedBeansWhenEndpointMissing() {
        contextRunner.run(context -> {
            assertThat(context).doesNotHaveBean(IamClient.class);
            assertThat(context).doesNotHaveBean(JwtDecoder.class);
            assertThat(context).doesNotHaveBean(PermissionResolver.class);
            assertThat(context).hasSingleBean(RequirePermAspect.class);
            assertThat(context).hasSingleBean(HighRiskGuardAspect.class);
        });
    }

    @Test
    void createsSecurityBeansWhenEndpointConfigured() {
        contextRunner
                .withPropertyValues(
                        "iam.sdk.endpoint=http://localhost:30001",
                        "iam.sdk.client-id=demo-app",
                        "iam.sdk.client-secret=secret")
                .run(context -> {
                    assertThat(context).hasSingleBean(IamClient.class);
                    assertThat(context).hasSingleBean(JwtDecoder.class);
                    assertThat(context).hasSingleBean(PermissionResolver.class);
                    assertThat(context.getBean(IamSecurityProperties.class).getJwksUrl())
                            .isEqualTo("http://localhost:30001/oauth2/jwks");
                });
    }

    @Test
    void jwtDecoderAcceptsIamEs256TokensFromJwks() throws Exception {
        MockWebServer server = new MockWebServer();
        server.start();
        try {
            ECKey key = new ECKeyGenerator(Curve.P_256)
                    .keyID("iam-es256-test")
                    .algorithm(JWSAlgorithm.ES256)
                    .generate();
            server.enqueue(new MockResponse()
                    .setHeader("Content-Type", "application/json")
                    .setBody(new JWKSet(key.toPublicJWK()).toString()));

            String endpoint = server.url("/").toString().replaceAll("/+$", "");
            String token = signEs256(key, endpoint);

            contextRunner
                    .withPropertyValues(
                            "iam.sdk.endpoint=" + endpoint,
                            "iam.sdk.client-id=demo-client",
                            "iam.sdk.client-secret=secret")
                    .run(context -> {
                        JwtDecoder decoder = context.getBean(JwtDecoder.class);
                        assertThat(decoder.decode(token).getSubject()).isEqualTo("user-1");
                    });
        } finally {
            server.shutdown();
        }
    }

    private static String signEs256(ECKey key, String issuer) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(key.getKeyID())
                .type(JOSEObjectType.JWT)
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("user-1")
                .issuer(issuer)
                .audience("app-1")
                .claim("roles", List.of("reader"))
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }
}
