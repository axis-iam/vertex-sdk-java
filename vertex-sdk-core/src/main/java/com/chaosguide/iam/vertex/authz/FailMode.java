package com.chaosguide.iam.vertex.authz;

/** IAM 权限解析失败时的策略。 */
public enum FailMode {
    /** 默认策略：解析失败就抛异常，避免在 IAM 不可用时误放行。 */
    CLOSE,

    /** 返回空权限集合；请求可以完成认证，但受权限保护的接口通常仍会被拒绝。 */
    OPEN
}
