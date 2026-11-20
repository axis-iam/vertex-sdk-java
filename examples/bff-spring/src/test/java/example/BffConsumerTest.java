package example;

import com.chaosguide.iam.vertex.web.SafeSessionView;
import com.chaosguide.iam.vertex.web.TestIam;
import com.chaosguide.iam.vertex.web.WebBff;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.ServerSocket;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import static org.assertj.core.api.Assertions.*;

class BffConsumerTest {
    static final ObjectMapper JSON=new ObjectMapper();
    URI origin;
    HttpClient browser;
    static CountDownLatch entered, release;
    @RestController public static class HostProbe {
        @GetMapping("/probe/seed") public Map<String,String> seed(HttpServletRequest request) {
            request.getSession().setAttribute("unrelated","kept"); return Map.of("result","seeded");
        }
        @GetMapping("/probe/slow") public Map<String,String> slow(HttpServletRequest request) throws InterruptedException {
            var session=request.getSession(false); entered.countDown(); release.await(10,TimeUnit.SECONDS);
            return Map.of("unrelated",session.getAttribute("unrelated").toString());
        }
        @GetMapping("/probe/read") public Map<String,String> read(HttpServletRequest request) {
            return Map.of("unrelated",request.getSession(false).getAttribute("unrelated").toString());
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void actualJarHostedCustomPermissionsCsrfAndNativeSessionLifecycle(boolean nativeSession) throws Exception {
        assertThat(WebBff.class.getProtectionDomain().getCodeSource().getLocation().toString())
                .endsWith("/vertex-sdk-web-0.1.0.jar");
        int port; try (ServerSocket socket=new ServerSocket(0)) { port=socket.getLocalPort(); }
        origin=URI.create("http://127.0.0.1:"+port);
        browser=HttpClient.newBuilder().cookieHandler(new CookieManager(null,CookiePolicy.ACCEPT_ALL))
                .followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(5)).build();
        try (TestIam iam=new TestIam()) {
            SpringApplication app=new SpringApplication(BffApplication.class,HostProbe.class);
            app.setDefaultProperties(Map.ofEntries(Map.entry("server.port",Integer.toString(port)),Map.entry("server.address","127.0.0.1"),
                    Map.entry("vertex.web.origin",origin.toString()),Map.entry("vertex.web.issuer",iam.config().issuer().toString()),
                    Map.entry("vertex.web.audience","api"),Map.entry("vertex.web.client-id","web"),Map.entry("vertex.web.client-secret","fixture-secret"),
                    Map.entry("vertex.web.development-loopback","true"),Map.entry("vertex.web.native-session",Boolean.toString(nativeSession)),
                    Map.entry("server.servlet.session.cookie.secure","false"),Map.entry("server.servlet.session.cookie.http-only","true"),
                    Map.entry("server.servlet.session.cookie.same-site","lax"),Map.entry("logging.level.root","WARN")));
            try (ConfigurableApplicationContext context=app.run("--server.servlet.session.cookie.secure=false")) {
                assertThat(context.getBeansOfType(SecurityFilterChain.class)).hasSize(1);
                assertThat(get("/auth/login").statusCode()).isEqualTo(401);
                if (nativeSession) assertThat(get("/probe/seed").statusCode()).isEqualTo(200);
                JsonNode pre=json(get("/auth/session/bootstrap")); SafeSessionView.validate(pre);
                HttpResponse<String> start=get("/auth/login"); assertThat(start.statusCode()).isEqualTo(302);
                iam.capture(start.headers().firstValue("Location").orElseThrow());
                HttpResponse<String> callback=get("/auth/callback?code=fixture-code&state="+iam.state);
                assertThat(callback.statusCode()).isEqualTo(302); assertThat(callback.headers().firstValue("Location")).hasValue("/");
                assertThat(callback.headers().firstValue("Cache-Control")).hasValue("no-store");
                JsonNode current=json(get("/auth/session")); SafeSessionView.validate(current);
                String csrf=current.path("csrfToken").asText();
                assertThat(current.toString()).doesNotContain("fixture-access","fixture-refresh","fixture-control");
                assertThat(get("/api/documents").statusCode()).isEqualTo(200);
                assertThat(get("/api/admin").statusCode()).isEqualTo(403);
                assertThat(get("/auth/session").statusCode()).isEqualTo(200);
                var badBearer=browser.send(HttpRequest.newBuilder(origin.resolve("/api/documents")).header("Authorization","Bearer invalid").GET().build(),HttpResponse.BodyHandlers.ofString());
                assertThat(badBearer.statusCode()).isEqualTo(401);
                assertThat(post("/auth/session/logout","{}","wrong").statusCode()).isEqualTo(403);
                entered=new CountDownLatch(1); release=new CountDownLatch(1);
                var executor=Executors.newSingleThreadExecutor();
                try {
                    var late=nativeSession ? executor.submit(() -> get("/probe/slow")) : null;
                    if (nativeSession) assertThat(entered.await(5,TimeUnit.SECONDS)).isTrue();
                    HttpResponse<String> logout=post("/auth/session/logout","{}",csrf);
                    assertThat(logout.statusCode()).isEqualTo(200); assertThat(json(logout).path("remote").asText()).isEqualTo("SESSION_REVOKED");
                    assertThat(get("/api/documents").statusCode()).isEqualTo(401);
                    // Reuse unrelated native Session state using the previous cookie, as a host application may do.
                    if (nativeSession) get("/probe/seed");
                    iam.userId="019b0000-0000-7000-8000-000000000005";
                    JsonNode fresh=json(get("/auth/session/bootstrap")); String anonymousCsrf=fresh.path("csrfToken").asText();
                    assertThat(post("/auth/session/login","{}",anonymousCsrf).statusCode()).isEqualTo(200);
                    String password="{\"method\":\"PASSWORD\",\"identifier\":{\"kind\":\"EMAIL\",\"value\":\"reader@example.test\"},\"password\":\"fixture-password\"}";
                    assertThat(post("/auth/session/login/authenticate",password,anonymousCsrf).statusCode()).isEqualTo(200);
                    JsonNode custom=json(post("/auth/session/login/complete","{}",anonymousCsrf)); SafeSessionView.validate(custom);
                    assertThat(custom.has("profile")).isTrue();
                    assertThat(custom.path("profile").path("id").asText()).isEqualTo(iam.userId);
                    assertThat(custom.path("profile").path("id")).isNotEqualTo(current.path("profile").path("id"));
                    release.countDown();
                    if (nativeSession) {
                        HttpResponse<String> old=late.get(10,TimeUnit.SECONDS); assertThat(old.statusCode()).isEqualTo(200);
                        assertThat(old.headers().allValues("Set-Cookie")).isEmpty();
                        assertThat(json(get("/probe/read")).path("unrelated").asText()).isEqualTo("kept");
                    }
                    assertThat(get("/api/documents").statusCode()).isEqualTo(200);
                    assertThat(json(get("/auth/session")).path("profile").path("id").asText()).isEqualTo(iam.userId);
                    assertThat(iam.exchanges).hasValue(2);
                    if (!nativeSession) lostCallbackCookieCannotRestoreAnOldIdentity(iam);
                } finally { release.countDown(); executor.shutdownNow(); }
            }
        }
    }

    void lostCallbackCookieCannotRestoreAnOldIdentity(TestIam iam) throws Exception {
        HttpResponse<String> bootstrap=manualGet("/auth/session/bootstrap",null);
        String pre=cookie(bootstrap);
        HttpResponse<String> start=manualGet("/auth/login",pre); iam.capture(start.headers().firstValue("Location").orElseThrow());
        HttpResponse<String> callback=manualGet("/auth/callback?code=fixture-code&state="+iam.state,pre);
        assertThat(callback.statusCode()).isEqualTo(302); String lateCookie=cookie(callback);
        // Deliberately lose the callback Cookie and bootstrap using the consumed prelogin Cookie.
        String nextPre=cookie(manualGet("/auth/session/bootstrap",pre));
        iam.userId="019b0000-0000-7000-8000-000000000006";
        start=manualGet("/auth/login",nextPre); iam.capture(start.headers().firstValue("Location").orElseThrow());
        String currentCookie=cookie(manualGet("/auth/callback?code=fixture-code&state="+iam.state,nextPre));
        assertThat(manualGet("/api/documents",lateCookie).statusCode()).isEqualTo(401);
        assertThat(manualGet("/api/documents",currentCookie).statusCode()).isEqualTo(200);
        assertThat(json(manualGet("/auth/session",currentCookie)).path("profile").path("id").asText()).isEqualTo(iam.userId);
        assertThat(iam.exchanges).hasValue(4);
    }
    String cookie(HttpResponse<String> response) {
        return response.headers().firstValue("Set-Cookie").orElseThrow().split(";",2)[0];
    }
    HttpResponse<String> manualGet(String path, String cookie) throws Exception {
        var request=HttpRequest.newBuilder(origin.resolve(path)).timeout(Duration.ofSeconds(15)).GET();
        if (cookie!=null) request.header("Cookie",cookie);
        return HttpClient.newHttpClient().send(request.build(),HttpResponse.BodyHandlers.ofString());
    }
    HttpResponse<String> get(String path) throws Exception {
        return browser.send(HttpRequest.newBuilder(origin.resolve(path)).timeout(Duration.ofSeconds(15)).GET().build(),HttpResponse.BodyHandlers.ofString());
    }
    HttpResponse<String> post(String path, String body, String csrf) throws Exception {
        return browser.send(HttpRequest.newBuilder(origin.resolve(path)).timeout(Duration.ofSeconds(15)).header("Content-Type","application/json")
                .header("Origin",origin.toString()).header("X-CSRF-Token",csrf).POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
    }
    JsonNode json(HttpResponse<String> response) throws Exception {
        assertThat(response.statusCode()).isBetween(200,299); return JSON.readTree(response.body());
    }
}
