package com.chaosguide.iam.vertex.web;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** No auto-configuration import or SecurityFilterChain bean: a dependency alone opens no routes. */
@Configuration(proxyBeanMethods = false)
public class WebBffSpringConfiguration {
    @Bean
    @ConditionalOnMissingBean
    public WebIamClient webIamClient(WebBffConfig config, WebSessionStore store) {
        store.validateTopology(config.declaredProcesses());
        return new WebIamClient(config);
    }

    @Bean
    @ConditionalOnMissingBean
    public WebSessionService webSessionService(
            WebBffConfig config, WebSessionStore store, WebIamClient iam) {
        return new WebSessionService(config, store, iam);
    }

    @Bean
    @ConditionalOnMissingBean
    public WebBff webBff(
            WebBffConfig config, WebSessionService service, WebSessionCarrier carrier) {
        return new WebBff(config, service, carrier);
    }
}
