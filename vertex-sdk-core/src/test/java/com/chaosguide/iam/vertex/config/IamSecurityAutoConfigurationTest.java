package com.chaosguide.iam.vertex.config;

import com.chaosguide.iam.vertex.EnableIamSecurity;
import com.chaosguide.iam.vertex.IamSecurityProperties;
import com.chaosguide.iam.vertex.authz.HighRiskGuardAspect;
import com.chaosguide.iam.vertex.authz.PermissionResolver;
import com.chaosguide.iam.vertex.authz.RequirePermAspect;
import com.chaosguide.iam.vertex.client.IamClient;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IamSecurityAutoConfigurationTest {

    private static final String AUDIENCE = "api://business-resource";
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
        configuredRunner("http://localhost:30001/")
                .withPropertyValues("iam.sdk.resource-audience=" + AUDIENCE)
                .run(context -> {
                    assertThat(context).hasSingleBean(IamClient.class);
                    assertThat(context).hasSingleBean(JwtDecoder.class);
                    assertThat(context).hasSingleBean(PermissionResolver.class);
                    IamSecurityProperties props = context.getBean(IamSecurityProperties.class);
                    assertThat(props.getJwksUrl()).isEqualTo("http://localhost:30001/oauth2/jwks");
                    assertThat(props.getIssuerUri()).isEqualTo("http://localhost:30001");
                    assertThat(props.getResourceAudience()).isEqualTo(AUDIENCE);
                });
    }

    @Test
    void requiresExplicitNonblankAudienceOnlyForSdkDecoder() {
        for (String value : List.of("", "   ")) {
            configuredRunner("http://localhost:30001")
                    .withPropertyValues("iam.sdk.resource-audience=" + value)
                    .run(context -> assertThat(context).hasFailed()
                            .getFailure().hasRootCauseInstanceOf(IllegalArgumentException.class)
                            .hasStackTraceContaining("iam.sdk.resource-audience"));
        }
        configuredRunner("http://localhost:30001")
                .run(context -> assertThat(context).hasFailed()
                        .getFailure().hasStackTraceContaining("iam.sdk.resource-audience"));
    }

    @Test
    void customDecoderAndResolverOverrideSdkBeansWithoutResourceAudience() {
        JwtDecoder decoder = token -> { throw new UnsupportedOperationException("test decoder"); };
        PermissionResolver resolver = (appId, roles) -> Set.of("posts:read");
        configuredRunner("http://localhost:30001")
                .withBean(JwtDecoder.class, () -> decoder)
                .withBean(PermissionResolver.class, () -> resolver)
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(JwtDecoder.class)
                            .hasSingleBean(PermissionResolver.class);
                    assertThat(context.getBean(JwtDecoder.class)).isSameAs(decoder);
                    assertThat(context.getBean(PermissionResolver.class)).isSameAs(resolver);
                });
    }

    @Test
    void signedTokensRequireIssuerAudienceLifetimeSignatureAndAllowedAlgorithm() throws Exception {
        ECKey ec = new ECKeyGenerator(Curve.P_256).keyID("ec").generate();
        RSAKey rsa = new RSAKeyGenerator(2048).keyID("rsa").generate();
        RSAKey foreignKey = new RSAKeyGenerator(2048).keyID("rsa").generate();
        try (MockWebServer server = new MockWebServer()) {
            server.setDispatcher(new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest request) {
                    return new MockResponse().setHeader("Content-Type", "application/json")
                            .setBody(new JWKSet(List.of(ec.toPublicJWK(), rsa.toPublicJWK())).toString());
                }
            });
            server.start();
            String issuer = server.url("/").toString().replaceAll("/+$", "");
            Instant now = Instant.now();
            String validEc = sign(new ECDSASigner(ec), JWSAlgorithm.ES256, "ec", issuer,
                    List.of("other-resource", AUDIENCE), now.minusSeconds(5), now.plusSeconds(600));
            String validRsa = sign(new RSASSASigner(rsa), JWSAlgorithm.RS256, "rsa", issuer,
                    List.of(AUDIENCE), now.minusSeconds(5), now.plusSeconds(600));
            List<String> invalid = List.of(
                    sign(new ECDSASigner(ec), JWSAlgorithm.ES256, "ec", "https://wrong-issuer.invalid",
                            List.of(AUDIENCE), now.minusSeconds(5), now.plusSeconds(600)),
                    sign(new ECDSASigner(ec), JWSAlgorithm.ES256, "ec", null,
                            List.of(AUDIENCE), now.minusSeconds(5), now.plusSeconds(600)),
                    sign(new ECDSASigner(ec), JWSAlgorithm.ES256, "ec", issuer,
                            List.of("demo-client"), now.minusSeconds(5), now.plusSeconds(600)),
                    sign(new ECDSASigner(ec), JWSAlgorithm.ES256, "ec", issuer,
                            null, now.minusSeconds(5), now.plusSeconds(600)),
                    sign(new ECDSASigner(ec), JWSAlgorithm.ES256, "ec", issuer,
                            List.of(), now.minusSeconds(5), now.plusSeconds(600)),
                    sign(new ECDSASigner(ec), JWSAlgorithm.ES256, "ec", issuer,
                            List.of(AUDIENCE), now.minusSeconds(600), now.minusSeconds(120)),
                    sign(new ECDSASigner(ec), JWSAlgorithm.ES256, "ec", issuer,
                            List.of(AUDIENCE), now.plusSeconds(120), now.plusSeconds(600)),
                    sign(new RSASSASigner(rsa), JWSAlgorithm.RS512, "rsa", issuer,
                            List.of(AUDIENCE), now.minusSeconds(5), now.plusSeconds(600)),
                    sign(new RSASSASigner(foreignKey), JWSAlgorithm.RS256, "rsa", issuer,
                            List.of(AUDIENCE), now.minusSeconds(5), now.plusSeconds(600)));
            configuredRunner(issuer + "/")
                    .withPropertyValues("iam.sdk.resource-audience=" + AUDIENCE)
                    .run(context -> {
                        JwtDecoder decoder = context.getBean(JwtDecoder.class);
                        assertThat(decoder.decode(validEc).getSubject()).isEqualTo("user-1");
                        assertThat(decoder.decode(validRsa).getSubject()).isEqualTo("user-1");
                        for (String token : invalid) {
                            assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
                        }
                    });
        }
    }

    private ApplicationContextRunner configuredRunner(String endpoint) {
        return contextRunner.withPropertyValues("iam.sdk.endpoint=" + endpoint,
                "iam.sdk.client-id=demo-client", "iam.sdk.client-secret=secret");
    }

    @Test
    void enabledEntryPointHonorsUserDecoderAndResolverWithoutAudience() {
        new ApplicationContextRunner().withUserConfiguration(EnabledCustomBeans.class)
                .withPropertyValues("iam.sdk.endpoint=http://localhost:30001",
                        "iam.sdk.client-id=demo-client", "iam.sdk.client-secret=secret")
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(JwtDecoder.class)
                            .hasSingleBean(PermissionResolver.class);
                    assertThat(context.getBean(JwtDecoder.class)).isSameAs(context.getBean("customDecoder"));
                    assertThat(context.getBean(PermissionResolver.class)).isSameAs(context.getBean("customResolver"));
                });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableIamSecurity
    static class EnabledCustomBeans {
        @Bean JwtDecoder customDecoder() {
            return token -> { throw new UnsupportedOperationException("test decoder"); };
        }

        @Bean PermissionResolver customResolver() {
            return (appId, roles) -> Set.of("posts:read");
        }
    }

    private static String sign(JWSSigner signer, JWSAlgorithm algorithm, String kid, String issuer,
                               List<String> audience, Instant notBefore, Instant expires) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(algorithm).keyID(kid).type(JOSEObjectType.JWT).build(),
                new JWTClaimsSet.Builder().subject("user-1").issuer(issuer).audience(audience)
                        .claim("app_id", "11111111-1111-4111-8111-111111111111")
                        .claim("roles", List.of("reader")).issueTime(Date.from(Instant.now()))
                        .notBeforeTime(Date.from(notBefore)).expirationTime(Date.from(expires)).build());
        jwt.sign(signer);
        return jwt.serialize();
    }
}
