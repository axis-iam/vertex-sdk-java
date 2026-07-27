package com.chaosguide.iam.vertex.test;

import org.springframework.test.context.TestExecutionListeners;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 测试注解：在测试方法执行前往 Spring SecurityContext 注入一个已认证身份。
 *
 * <p>适合 controller/aspect 单元测试。它直接注入 roles/permissions authority，不会真实调用 IAM 权限解析接口。
 *
 * <pre>
 * &#64;Test
 * &#64;IamTestSecurity(permissions = {"posts:read"})
 * void shouldAllowListing() { ... }
 * </pre>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@TestExecutionListeners(
        listeners = IamTestSecurityListener.class,
        mergeMode = TestExecutionListeners.MergeMode.MERGE_WITH_DEFAULTS)
public @interface IamTestSecurity {

    String username() default "test-user";

    /** 注入为 {@code ROLE_<role>} 的角色 authority。 */
    String[] roles() default {};

    /** 注入为 {@code resource:action} 的权限 authority。 */
    String[] permissions() default {};
}
