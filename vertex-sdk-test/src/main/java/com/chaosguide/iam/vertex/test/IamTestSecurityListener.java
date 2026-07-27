package com.chaosguide.iam.vertex.test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.support.AbstractTestExecutionListener;

import java.lang.reflect.AnnotatedElement;
import java.util.ArrayList;
import java.util.List;

/** 处理 {@link IamTestSecurity} 的 Spring 测试监听器，负责注入和清理 SecurityContext。 */
public class IamTestSecurityListener extends AbstractTestExecutionListener {

    @Override
    public void beforeTestMethod(TestContext testContext) {
        IamTestSecurity ann = find(testContext.getTestMethod())
                .or(() -> find(testContext.getTestClass()))
                .orElse(null);
        if (ann == null) {
            return;
        }
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (String role : ann.roles()) {
            // 与运行时 converter 保持一致：角色使用 ROLE_ 前缀。
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
        }
        for (String perm : ann.permissions()) {
            // 权限 authority 直接使用 resource:action，便于测试 @RequirePerm。
            authorities.add(new SimpleGrantedAuthority(perm));
        }
        TestingAuthenticationToken auth = new TestingAuthenticationToken(
                ann.username(), "N/A", authorities);
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    @Override
    public void afterTestMethod(TestContext testContext) {
        // SecurityContextHolder 是线程本地状态，测试后必须清理，避免污染后续用例。
        SecurityContextHolder.clearContext();
    }

    private static java.util.Optional<IamTestSecurity> find(AnnotatedElement el) {
        return el == null
                ? java.util.Optional.empty()
                : java.util.Optional.ofNullable(el.getAnnotation(IamTestSecurity.class));
    }
}
