package com.chaosguide.iam.vertex;

import com.chaosguide.iam.vertex.config.IamSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 开启 IAM SDK 安全集成。
 *
 * <p>该注解会导入自动配置，包含 JWT 解码、角色到权限解析、{@code @RequirePerm} /
 * {@code @RequireStepUp} / {@code @RequireNoImpersonation} AOP 检查。用户自定义 bean 优先于 SDK 默认值。
 *
 * <pre>
 * &#64;SpringBootApplication
 * &#64;EnableIamSecurity
 * public class MyApp { ... }
 * </pre>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@ImportAutoConfiguration(IamSecurityAutoConfiguration.class)
public @interface EnableIamSecurity {
}
