package com.chaosguide.iam.vertex.jwt;

import com.chaosguide.iam.vertex.IamSecurityProperties;
import com.chaosguide.iam.vertex.exception.IamSdkException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IamJwksProviderTest {

    private MockWebServer server;

    @BeforeEach
    void start() throws Exception {
        server = new MockWebServer();
        server.start();
    }

    @AfterEach
    void stop() throws Exception {
        server.shutdown();
    }

    @Test
    void fetchesAndCachesJwks() throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("kid-1").generate();
        JWKSet set = new JWKSet(key.toPublicJWK());
        server.enqueue(jwksResponse(set.toString()));

        IamJwksProvider provider = provider(Duration.ofMinutes(1));

        JWKSet first = provider.get();
        JWKSet second = provider.get();

        assertThat(first.getKeys()).hasSize(1);
        assertThat(second).isSameAs(first);
        assertThat(server.getRequestCount()).isEqualTo(1);
    }

    @Test
    void refreshesAfterTtl() throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("kid-1").generate();
        JWKSet set = new JWKSet(key.toPublicJWK());
        server.enqueue(jwksResponse(set.toString()));
        server.enqueue(jwksResponse(set.toString()));

        IamJwksProvider provider = provider(Duration.ofMillis(1));
        provider.get();
        Thread.sleep(10);
        provider.get();

        assertThat(server.getRequestCount()).isEqualTo(2);
    }

    @Test
    void throwsOnHttpFailure() {
        server.enqueue(new MockResponse().setResponseCode(500));

        IamJwksProvider provider = provider(Duration.ofMinutes(1));
        assertThatThrownBy(provider::get).isInstanceOf(IamSdkException.class);
    }

    @Test
    void throwsOnMalformedResponse() {
        server.enqueue(new MockResponse().setBody("not json"));

        IamJwksProvider provider = provider(Duration.ofMinutes(1));
        assertThatThrownBy(provider::get).isInstanceOf(IamSdkException.class);
    }

    @Test
    void manualRefreshBypassesCache() throws Exception {
        RSAKey k = new RSAKeyGenerator(2048).keyID("kid-1").generate();
        server.enqueue(jwksResponse(new JWKSet(k.toPublicJWK()).toString()));
        server.enqueue(jwksResponse(new JWKSet(k.toPublicJWK()).toString()));

        IamJwksProvider provider = provider(Duration.ofMinutes(10));
        provider.get();
        provider.refresh();

        assertThat(server.getRequestCount()).isEqualTo(2);
    }

    @Test
    void constructorFromPropertiesUsesJwksUrl() {
        IamSecurityProperties props = new IamSecurityProperties();
        props.setEndpoint(server.url("/").toString().replaceAll("/+$", ""));
        assertThat(props.getJwksUrl()).endsWith("/oauth2/jwks");
        // must not throw / fetch
        new IamJwksProvider(props);
    }

    private IamJwksProvider provider(Duration refresh) {
        OkHttpClient http = new OkHttpClient.Builder()
                .connectTimeout(2, TimeUnit.SECONDS)
                .readTimeout(2, TimeUnit.SECONDS).build();
        return new IamJwksProvider(http, server.url("/oauth2/jwks").toString(), refresh);
    }

    private MockResponse jwksResponse(String body) {
        return new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody(body);
    }
}
