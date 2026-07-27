package com.chaosguide.iam.vertex.authz;

import com.chaosguide.iam.vertex.IamSecurityProperties;
import com.chaosguide.iam.vertex.client.IamClient;
import com.chaosguide.iam.vertex.client.dto.ResolveRequest;
import com.chaosguide.iam.vertex.client.dto.ResolveResponse;
import com.chaosguide.iam.vertex.exception.IamSdkException;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.TreeSet;

/**
 * 基于 Caffeine 本地缓存和 IAM HTTP 接口的权限解析器。
 *
 * <p>JWT 不再携带最终 permissions，SDK 在第一次遇到某个「ApplicationClient + 角色集合」时调用
 * {@code POST /open/v1/permissions:resolve}，后续相同组合直接走本地缓存。
 *
 * <p>HTTP 调用失败时：
 * <ul>
 *   <li>{@link FailMode#CLOSE}：抛出异常，默认拒绝请求。</li>
 *   <li>{@link FailMode#OPEN}：返回空权限集合，请求可认证但权限校验通常会失败。</li>
 * </ul>
 */
public class HttpPermissionResolver implements PermissionResolver {

    private static final Logger log = LoggerFactory.getLogger(HttpPermissionResolver.class);

    private final IamClient client;
    private final IamSecurityProperties props;
    private final Cache<CacheKey, Set<String>> cache;

    public HttpPermissionResolver(IamClient client, IamSecurityProperties props) {
        this.client = client;
        this.props = props;
        this.cache = Caffeine.newBuilder()
                .maximumSize(Math.max(1, props.getPermissionCacheMaxSize()))
                .expireAfterWrite(props.getPermissionCacheTtl())
                .build();
    }

    @Override
    public Set<String> resolve(String appId, Set<String> roles) {
        if (roles == null || roles.isEmpty()) {
            return Set.of();
        }
        String applicationClientId = props.getClientId();
        if (applicationClientId == null || applicationClientId.isBlank()) {
            throw new IamSdkException("iam.sdk.client-id is required and must be ApplicationClient.clientId");
        }

        // 角色集合排序后再作为 cache key，避免 ["admin","viewer"] 和 ["viewer","admin"] 重复缓存。
        Set<String> normalizedRoles = new TreeSet<>(roles);
        CacheKey key = new CacheKey(applicationClientId, Set.copyOf(normalizedRoles));
        Set<String> cached = cache.getIfPresent(key);
        if (cached != null) {
            return cached;
        }
        // Caffeine 的 get(key, loader) 会对同一个 key 的并发加载做合并，避免瞬时打爆 IAM。
        return cache.get(key, this::load);
    }

    private Set<String> load(CacheKey key) {
        try {
            ResolveResponse resp = client.resolvePermissions(new ResolveRequest(key.applicationClientId, key.roles));
            return resp.permissions();
        } catch (RuntimeException e) {
            if (props.getFailMode() == FailMode.OPEN) {
                log.warn("IAM resolve failed (fail-open): {}", e.getMessage());
                return Set.of();
            }
            log.warn("IAM resolve failed (fail-close): {}", e.getMessage());
            throw e;
        }
    }

    /** 清空本地权限缓存；主要用于测试，也可以作为手动失效入口。 */
    public void invalidateAll() {
        cache.invalidateAll();
    }

    /** 暴露缓存估算大小，方便单元测试断言缓存行为。 */
    public long estimatedSize() {
        return cache.estimatedSize();
    }

    /** 缓存 key 使用 ApplicationClient.clientId + 已排序角色集合，保证同一语义组合只缓存一份。 */
    record CacheKey(String applicationClientId, Set<String> roles) {
    }
}
