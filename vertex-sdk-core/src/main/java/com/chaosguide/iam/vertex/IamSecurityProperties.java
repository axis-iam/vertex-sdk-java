package com.chaosguide.iam.vertex;

import com.chaosguide.iam.vertex.authz.FailMode;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/** SDK 运行时配置，对应接入应用里的 {@code iam.sdk.*} 配置项。 */
@ConfigurationProperties(prefix = "iam.sdk")
public class IamSecurityProperties {

    /** IAM Server 根地址，例如 {@code https://iam.example.com}。未配置时不会创建网络访问相关 bean。 */
    private String endpoint;

    /** 当前服务端接入使用的 {@code ApplicationClient.clientId}，应来自 WEB/M2M confidential client。 */
    private String clientId;

    /** WEB/M2M confidential ApplicationClient 的 secret；权限同步和内部管理调用必须配置。 */
    private String clientSecret;

    /** JWKS 工具类的本地刷新间隔；默认的 NimbusJwtDecoder 也会自行处理 JWKS 缓存。 */
    private Duration jwksRefresh = Duration.ofHours(1);

    /** 权限解析缓存 TTL，缓存维度是「应用 + 排序后的角色集合」。 */
    private Duration permissionCacheTtl = Duration.ofMinutes(5);

    /** 权限解析缓存最大条数，避免角色组合过多时无限占用内存。 */
    private int permissionCacheMaxSize = 10_000;

    /** 显式用户资料查询缓存是否启用；不会影响认证和授权链路。 */
    private boolean userProfileCacheEnabled = true;

    /** 显式用户资料查询缓存 TTL，默认短缓存，避免资料更新长期不可见。 */
    private Duration userProfileCacheTtl = Duration.ofMinutes(1);

    /** 用户资料缓存最大条数。 */
    private int userProfileCacheMaxSize = 10_000;

    /** 运行时权限解析失败时的处理方式；生产默认 fail-close。 */
    private FailMode failMode = FailMode.CLOSE;

    /** SDK 调 IAM Server 的连接、读取和写入超时时间。 */
    private Duration httpTimeout = Duration.ofSeconds(10);

    public String getEndpoint() { return endpoint; }
    public void setEndpoint(String endpoint) { this.endpoint = endpoint; }

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

    public Duration getJwksRefresh() { return jwksRefresh; }
    public void setJwksRefresh(Duration jwksRefresh) { this.jwksRefresh = jwksRefresh; }

    public Duration getPermissionCacheTtl() { return permissionCacheTtl; }
    public void setPermissionCacheTtl(Duration permissionCacheTtl) { this.permissionCacheTtl = permissionCacheTtl; }

    public int getPermissionCacheMaxSize() { return permissionCacheMaxSize; }
    public void setPermissionCacheMaxSize(int permissionCacheMaxSize) { this.permissionCacheMaxSize = permissionCacheMaxSize; }

    public boolean isUserProfileCacheEnabled() { return userProfileCacheEnabled; }
    public void setUserProfileCacheEnabled(boolean userProfileCacheEnabled) { this.userProfileCacheEnabled = userProfileCacheEnabled; }

    public Duration getUserProfileCacheTtl() { return userProfileCacheTtl; }
    public void setUserProfileCacheTtl(Duration userProfileCacheTtl) { this.userProfileCacheTtl = userProfileCacheTtl; }

    public int getUserProfileCacheMaxSize() { return userProfileCacheMaxSize; }
    public void setUserProfileCacheMaxSize(int userProfileCacheMaxSize) { this.userProfileCacheMaxSize = userProfileCacheMaxSize; }

    public FailMode getFailMode() { return failMode; }
    public void setFailMode(FailMode failMode) { this.failMode = failMode; }

    public Duration getHttpTimeout() { return httpTimeout; }
    public void setHttpTimeout(Duration httpTimeout) { this.httpTimeout = httpTimeout; }

    /** 根据 endpoint 推导出的 JWKS 地址。IAM Server 固定暴露在 {@code /oauth2/jwks}。 */
    public String getJwksUrl() {
        return stripTrailingSlash(endpoint) + "/oauth2/jwks";
    }

    /** JWT issuer 也使用标准化后的 IAM Server 根地址。 */
    public String getIssuerUri() {
        return stripTrailingSlash(endpoint);
    }

    private static String stripTrailingSlash(String url) {
        if (url == null) {
            return "";
        }
        return url.replaceAll("/+$", "");
    }
}
