package com.chaosguide.iam.vertex.jwt;

import com.chaosguide.iam.vertex.IamSecurityProperties;
import com.chaosguide.iam.vertex.exception.IamSdkException;
import com.nimbusds.jose.jwk.JWKSet;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 轻量 JWKS 拉取工具。
 *
 * <p>默认 Spring Security 集成已经使用 {@code NimbusJwtDecoder.withJwkSetUri(...)} 完成 JWT 验签；这个类主要给测试
 * 或需要直接读取 JWKS 的接入场景使用。
 */
public class IamJwksProvider {

    private final OkHttpClient http;
    private final String jwksUrl;
    private final Duration refresh;
    private final AtomicReference<CachedJwks> cache = new AtomicReference<>();

    public IamJwksProvider(IamSecurityProperties props) {
        this(defaultHttp(props), props.getJwksUrl(), props.getJwksRefresh());
    }

    IamJwksProvider(OkHttpClient http, String jwksUrl, Duration refresh) {
        this.http = http;
        this.jwksUrl = jwksUrl;
        this.refresh = refresh;
    }

    public JWKSet get() {
        CachedJwks c = cache.get();
        if (c != null && !c.isExpired(refresh)) {
            return c.jwks;
        }
        return refresh();
    }

    public JWKSet refresh() {
        // 强制刷新会绕过当前缓存，适合密钥轮换后主动拉取。
        Request req = new Request.Builder().url(jwksUrl).get().build();
        try (Response resp = http.newCall(req).execute()) {
            if (!resp.isSuccessful() || resp.body() == null) {
                throw new IamSdkException("Failed to fetch JWKS: HTTP " + resp.code());
            }
            JWKSet parsed = JWKSet.parse(resp.body().string());
            cache.set(new CachedJwks(parsed, Instant.now()));
            return parsed;
        } catch (IOException | java.text.ParseException e) {
            throw new IamSdkException("JWKS fetch/parse failed: " + e.getMessage(), e);
        }
    }

    private static OkHttpClient defaultHttp(IamSecurityProperties props) {
        long ms = Math.max(1000L, props.getHttpTimeout().toMillis());
        return new OkHttpClient.Builder()
                .connectTimeout(ms, TimeUnit.MILLISECONDS)
                .readTimeout(ms, TimeUnit.MILLISECONDS)
                .build();
    }

    private record CachedJwks(JWKSet jwks, Instant fetchedAt) {
        boolean isExpired(Duration ttl) {
            return Instant.now().isAfter(fetchedAt.plus(ttl));
        }
    }
}
