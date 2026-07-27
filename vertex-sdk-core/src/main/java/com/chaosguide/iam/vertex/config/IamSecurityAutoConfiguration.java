package com.chaosguide.iam.vertex.config;

import com.chaosguide.iam.vertex.IamSecurityProperties;
import com.chaosguide.iam.vertex.authz.HighRiskGuardAspect;
import com.chaosguide.iam.vertex.authz.HttpPermissionResolver;
import com.chaosguide.iam.vertex.authz.PermissionResolver;
import com.chaosguide.iam.vertex.authz.RequirePermAspect;
import com.chaosguide.iam.vertex.client.IamClient;
import com.chaosguide.iam.vertex.context.CurrentIamUserArgumentResolver;
import com.chaosguide.iam.vertex.jwt.IamJwtAuthenticationConverter;
import com.chaosguide.iam.vertex.user.IamUserProfileService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

/**
 * IAM SDK 的 Spring Boot 自动配置入口。
 *
 * <p>这里刻意把网络访问相关 bean 都绑定到 {@code iam.sdk.endpoint} 上：接入方只引入依赖但还没配置 IAM
 * 时，应用不应该因为 SDK 抢先创建 {@link IamClient} 或 {@link JwtDecoder} 而启动失败。
 */
@AutoConfiguration
@EnableConfigurationProperties(IamSecurityProperties.class)
public class IamSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(name = "iamObjectMapper")
    public ObjectMapper iamObjectMapper() {
        // 给 SDK 内部 HTTP client 使用独立 ObjectMapper，避免接入应用全局 ObjectMapper 定制影响协议解析。
        return new ObjectMapper();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "iam.sdk", name = "endpoint")
    public IamClient iamClient(IamSecurityProperties props, ObjectMapper iamObjectMapper) {
        return new IamClient(
                props.getEndpoint(),
                props.getClientId(),
                props.getClientSecret(),
                props.getHttpTimeout(),
                iamObjectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "iam.sdk", name = "endpoint")
    public JwtDecoder iamJwtDecoder(IamSecurityProperties props) {
        // Spring Security 的 NimbusJwtDecoder 已内置 JWKS 拉取与缓存；SDK 不再重复实现 JwtVerifier。
        return NimbusJwtDecoder.withJwkSetUri(props.getJwksUrl())
                .jwsAlgorithms(algorithms -> {
                    algorithms.add(SignatureAlgorithm.ES256);
                    algorithms.add(SignatureAlgorithm.RS256);
                })
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(IamClient.class)
    public PermissionResolver iamPermissionResolver(IamClient client, IamSecurityProperties props) {
        return new HttpPermissionResolver(client, props);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PermissionResolver.class)
    public IamJwtAuthenticationConverter iamJwtAuthenticationConverter(
            PermissionResolver resolver, IamSecurityProperties props) {
        return new IamJwtAuthenticationConverter(resolver, props);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(IamClient.class)
    public IamUserProfileService iamUserProfileService(IamClient client, IamSecurityProperties props) {
        return new IamUserProfileService(client, props);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    public CurrentIamUserArgumentResolver iamCurrentUserArgumentResolver() {
        return new CurrentIamUserArgumentResolver();
    }

    @Bean
    @ConditionalOnClass(WebMvcConfigurer.class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    public WebMvcConfigurer iamCurrentUserWebMvcConfigurer(CurrentIamUserArgumentResolver resolver) {
        return new WebMvcConfigurer() {
            @Override
            public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
                resolvers.add(resolver);
            }
        };
    }

    @Bean
    @ConditionalOnMissingBean
    public RequirePermAspect iamRequirePermAspect() {
        // AOP 检查只依赖 SecurityContext，本身不需要 IAM endpoint，因此可以始终注册。
        return new RequirePermAspect();
    }

    @Bean
    @ConditionalOnMissingBean
    public HighRiskGuardAspect iamHighRiskGuardAspect() {
        // High-risk guards only read request-local IAM context from the verified JWT.
        return new HighRiskGuardAspect();
    }
}
