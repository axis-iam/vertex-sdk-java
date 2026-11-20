package example;

import com.chaosguide.iam.vertex.authz.PermissionDefinition;
import com.chaosguide.iam.vertex.authz.PermissionKey;
import com.chaosguide.iam.vertex.authz.RequirePerm;
import com.chaosguide.iam.vertex.context.IamContext;
import com.chaosguide.iam.vertex.web.CookieWebSessionCarrier;
import com.chaosguide.iam.vertex.web.EnableWebBff;
import com.chaosguide.iam.vertex.web.HttpSessionWebSessionCarrier;
import com.chaosguide.iam.vertex.web.MemoryWebSessionStore;
import com.chaosguide.iam.vertex.web.WebBff;
import com.chaosguide.iam.vertex.web.WebBffConfig;
import com.chaosguide.iam.vertex.web.WebSessionCarrier;
import com.chaosguide.iam.vertex.web.WebSessionStore;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.net.URI;
import java.util.Map;
import java.util.Set;

/** Standalone app: depends only on Maven coordinates. See README for explicit memory and native Session modes. */
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
@EnableWebBff
@RestController
public class BffApplication {
    public static void main(String[] args) { SpringApplication.run(BffApplication.class,args); }
    @Bean WebBffConfig webConfig(Environment env) {
        URI origin=URI.create(env.getRequiredProperty("vertex.web.origin"));
        return new WebBffConfig(URI.create(env.getRequiredProperty("vertex.web.issuer")),
                env.getRequiredProperty("vertex.web.audience"),env.getRequiredProperty("vertex.web.client-id"),
                env.getRequiredProperty("vertex.web.client-secret"),origin.resolve("/auth/callback"),origin,"/auth",
                Set.of("/"),"/",Set.of("openid","offline_access"),env.getProperty("vertex.web.development-loopback",Boolean.class,false),1);
    }
    @Bean(destroyMethod="close") WebSessionStore webStore() { return new MemoryWebSessionStore(); }
    @Bean WebSessionCarrier webCarrier(WebBffConfig config, Environment env) {
        return env.getProperty("vertex.web.native-session",Boolean.class,false)
                ? new HttpSessionWebSessionCarrier(config,"JSESSIONID",true) : new CookieWebSessionCarrier(config);
    }
    @Bean SecurityFilterChain security(HttpSecurity http, WebBff web) throws Exception {
        web.configure(http,request -> request.getRequestURI().startsWith("/api/"));
        http.authorizeHttpRequests(a -> a.requestMatchers("/api/**").authenticated().anyRequest().permitAll())
                .requestCache(c -> c.disable()).formLogin(c -> c.disable()).httpBasic(c -> c.disable()).logout(c -> c.disable());
        return http.build();
    }
    public enum Permission implements PermissionDefinition {
        READ("read"), WRITE("write");
        private final PermissionKey key;
        Permission(String action) { key=new PermissionKey("documents",action); }
        @Override public PermissionKey key() { return key; }
    }
    @GetMapping("/api/documents") @RequirePerm(value=Permission.class,name="READ")
    public Map<String,Object> documents() { return Map.of("userId",IamContext.currentUser().subject(),"documents",Set.of("example")); }
    @GetMapping("/api/admin") @RequirePerm(value=Permission.class,name="WRITE")
    public Map<String,String> admin() { return Map.of("result","allowed"); }
}
