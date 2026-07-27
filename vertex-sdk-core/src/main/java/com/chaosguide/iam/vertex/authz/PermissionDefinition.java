package com.chaosguide.iam.vertex.authz;

/**
 * 应用侧权限枚举需要实现的接口。
 *
 * <p>每个 enum 常量通常会配合 {@link DefinesPermission} 注解声明 resource/action，{@link #key()}
 * 返回标准化后的 {@link PermissionKey}。
 */
public interface PermissionDefinition {

    PermissionKey key();

    default String authority() {
        // Spring Security 最终比对的是字符串 authority，这里提供一个直接可用的快捷方法。
        return key().toAuthority();
    }
}
