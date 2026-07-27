package com.chaosguide.iam.vertex.authz;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 控制器或服务方法上的类型安全权限声明。
 *
 * <pre>
 * &#64;RequirePerm(value = MyAppPermissions.class, name = "POSTS_READ")
 * public List&lt;Post&gt; list() { ... }
 * </pre>
 *
 * <p>{@code value} 指向应用自己的权限 enum，{@code name} 是 enum 常量名。运行时由
 * {@link RequirePermAspect} 解析成 {@code resource:action}，再检查当前 {@code Authentication}
 * 是否拥有同名 authority。
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface RequirePerm {

    /** 实现 {@link PermissionDefinition} 的权限枚举类型。 */
    Class<? extends PermissionDefinition> value();

    /** 权限枚举常量名，例如 {@code "POSTS_READ"}。 */
    String name();
}
