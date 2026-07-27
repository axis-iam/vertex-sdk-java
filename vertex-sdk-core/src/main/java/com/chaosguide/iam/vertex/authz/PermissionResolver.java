package com.chaosguide.iam.vertex.authz;

import java.util.Set;

/**
 * 根据接入上下文和角色集合解析最终权限。
 *
 * <p>JWT 只携带 roles，不携带 permissions；具体权限由实现类向 IAM 查询并在本地缓存。
 */
public interface PermissionResolver {

    /**
     * @param appId JWT 中的业务 Application 上下文。HTTP 实现向 IAM 请求时使用配置的
     *              {@code ApplicationClient.clientId}，不会把业务 Application UUID 当作 client id。
     * @param roles JWT {@code roles} claim 中的角色 key 集合
     * @return 摊平后的权限集合，格式为 {@code resource:action}
     */
    Set<String> resolve(String appId, Set<String> roles);
}
