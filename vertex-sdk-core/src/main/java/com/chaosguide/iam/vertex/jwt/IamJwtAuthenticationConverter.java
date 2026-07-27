package com.chaosguide.iam.vertex.jwt;

import com.chaosguide.iam.vertex.IamSecurityProperties;
import com.chaosguide.iam.vertex.authz.PermissionResolver;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 把 IAM 签发的 {@link Jwt} 转成 Spring Security 使用的 {@link JwtAuthenticationToken}。
 *
 * <p>最终 authorities 来自两部分：
 * <ul>
 *   <li>JWT 的 {@code roles} claim 转成 {@code ROLE_<role>}。</li>
 *   <li>通过 {@link PermissionResolver#resolve(String, Set)} 解析出的 {@code resource:action} 权限。</li>
 * </ul>
 *
 * <p>注意：这里不会读取、信任或合并 JWT 里的 {@code permissions} claim。权限必须运行时解析，避免 token
 * 过大以及权限撤销延迟。
 */
public class IamJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final PermissionResolver resolver;
    private final IamSecurityProperties props;

    public IamJwtAuthenticationConverter(PermissionResolver resolver, IamSecurityProperties props) {
        this.resolver = resolver;
        this.props = props;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Set<String> roles = readStringSet(jwt, "roles");
        String appId = resolveAppId(jwt);

        Collection<GrantedAuthority> authorities = new ArrayList<>();
        for (String role : roles) {
            // 保留 Spring Security hasRole/ROLE_ 生态习惯；权限本身则保持 resource:action。
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
        }

        Set<String> permissions = new LinkedHashSet<>();
        if (!roles.isEmpty()) {
            try {
                permissions.addAll(resolver.resolve(appId, roles));
            } catch (RuntimeException e) {
                // fail-close：解析失败时不静默降级为空权限，交给 Spring Security/调用方决定响应。
                throw e;
            }
        }
        for (String perm : permissions) {
            authorities.add(new SimpleGrantedAuthority(perm));
        }

        String principalName = jwt.getSubject() != null ? jwt.getSubject() : "anonymous";
        return new JwtAuthenticationToken(jwt, authorities, principalName);
    }

    private String resolveAppId(Jwt jwt) {
        // 优先保留 JWT 里的业务 Application 上下文；缺失时才兜底到配置的 ApplicationClient.clientId。
        List<String> aud = jwt.getAudience();
        if (aud != null && !aud.isEmpty()) {
            return aud.get(0);
        }
        Object appId = jwt.getClaim("app_id");
        if (appId instanceof String s && !s.isBlank()) {
            return s;
        }
        return props.getClientId();
    }

    private Set<String> readStringSet(Jwt jwt, String claim) {
        Object value = jwt.getClaim(claim);
        if (value == null) {
            return Collections.emptySet();
        }
        if (value instanceof Collection<?> c) {
            Set<String> out = new LinkedHashSet<>();
            for (Object item : c) {
                if (item instanceof String s && !s.isBlank()) {
                    out.add(s);
                }
            }
            return out;
        }
        if (value instanceof String s && !s.isBlank()) {
            return Set.of(s);
        }
        return Collections.emptySet();
    }
}
