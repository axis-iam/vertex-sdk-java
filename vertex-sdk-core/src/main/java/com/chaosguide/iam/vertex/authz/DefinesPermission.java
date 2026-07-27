package com.chaosguide.iam.vertex.authz;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 标在权限 enum 常量上，用来声明代码侧拥有的权限元数据，并在启动时同步到 IAM。 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface DefinesPermission {

    /** 资源名，例如 {@code posts}、{@code users}、{@code signing-keys}。 */
    String resource();

    /** 动作名，例如 {@code read}、{@code create}、{@code delete}。 */
    String action();

    /** 给 IAM 管理端展示的人类可读说明，可为空。 */
    String description() default "";
}
