package com.chaosguide.iam.vertex.web;

import com.chaosguide.iam.vertex.client.dto.CurrentUserResponse;
import com.chaosguide.iam.vertex.context.IamActor;
import com.chaosguide.iam.vertex.context.IamCurrentUser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Explicit Spring chain attachment and finite host HTTP routes. Does not create or replace an
 * application chain.
 */
public final class WebBff {
    private final WebBffConfig config;
    private final WebSessionService service;
    private final WebSessionCarrier carrier;

    public WebBff(WebBffConfig config, WebSessionService service, WebSessionCarrier carrier) {
        this.config = config;
        this.service = service;
        this.carrier = carrier;
    }

    /**
     * App explicitly chooses protected business paths. Cookie POST protection is handled before
     * business code.
     */
    public void configure(HttpSecurity http, RequestMatcher protectedBusiness) throws Exception {
        RequestMatcher handled =
                request -> authRoute(request) || protectedBusiness.matches(request);
        http.csrf(csrf -> csrf.ignoringRequestMatchers(handled));
        http.securityContext(
                sc ->
                        sc.requireExplicitSave(true)
                                .securityContextRepository(
                                        new RequestAttributeSecurityContextRepository()));
        http.addFilterAfter(filter(protectedBusiness), BearerTokenAuthenticationFilter.class);
    }

    public OncePerRequestFilter filter(RequestMatcher protectedBusiness) {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(
                    HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                    throws ServletException, IOException {
                boolean route = authRoute(req), protect = protectedBusiness.matches(req);
                if (!route && !protect) {
                    chain.doFilter(req, res);
                    return;
                }
                SecurityContext previous = SecurityContextHolder.getContext();
                try {
                    Authentication supplied = previous.getAuthentication();
                    if (req.getHeader("Authorization") != null) {
                        if (!(supplied instanceof JwtAuthenticationToken)
                                || !supplied.isAuthenticated())
                            throw new WebSessionException(401, "INVALID_BEARER");
                        if (!route) {
                            chain.doFilter(req, res);
                            return;
                        }
                        throw WebSessionException.invalid();
                    }
                    String handle = carrier.read(req);
                    if (route) {
                        routes(req, res, handle);
                        return;
                    }
                    if (!Set.of("GET", "HEAD", "OPTIONS").contains(req.getMethod()))
                        csrf(req, handle);
                    WebSessionService.Result session = service.session(handle);
                    if (!session.view().has("profile")) throw WebSessionException.absent();
                    SecurityContext current = SecurityContextHolder.createEmptyContext();
                    current.setAuthentication(authentication(session.view()));
                    SecurityContextHolder.setContext(current);
                    chain.doFilter(req, res);
                } catch (WebSessionException e) {
                    error(res, e, null);
                } finally {
                    SecurityContextHolder.setContext(previous);
                }
            }
        };
    }

    private boolean authRoute(HttpServletRequest r) {
        return r.getRequestURI().startsWith(r.getContextPath() + config.basePath() + "/");
    }

    private void csrf(HttpServletRequest req, String handle) {
        if (req.getHeaders("Origin").asIterator().hasNext()) {
            List<String> origins = new ArrayList<>();
            req.getHeaders("Origin").asIterator().forEachRemaining(origins::add);
            if (origins.size() != 1) throw new WebSessionException(403, "SESSION_CSRF_INVALID");
        }
        List<String> csrf = new ArrayList<>();
        req.getHeaders("X-CSRF-Token").asIterator().forEachRemaining(csrf::add);
        if (csrf.size() != 1) throw new WebSessionException(403, "SESSION_CSRF_INVALID");
        service.csrf(handle, req.getHeader("Origin"), csrf.get(0));
    }

    private void routes(HttpServletRequest req, HttpServletResponse res, String handle)
            throws IOException {
        res.setHeader("Cache-Control", "no-store");
        res.setHeader("Referrer-Policy", "no-referrer");
        String path =
                req.getRequestURI()
                        .substring(req.getContextPath().length() + config.basePath().length());
        String method = req.getMethod();
        if (method.equals("POST")) {
            try {
                csrf(req, handle);
            } catch (WebSessionException e) {
                if (path.equals("/session/logout")
                        && e.status() == 503
                        && e.code().startsWith("SESSION_STORE_")) {
                    carrier.clear(req, res, handle);
                    error(
                            res,
                            e,
                            WebWire.object()
                                    .put("local", "UNCONFIRMED")
                                    .put("cookie", "CLEARED")
                                    .put("remote", "NOT_ATTEMPTED")
                                    .put("sso", "NOT_REQUESTED"));
                    return;
                }
                throw e;
            }
        }
        if (method.equals("GET") && path.equals("/session/bootstrap")) {
            WebSessionService.Result r = service.bootstrap(handle);
            if (!r.handle().equals(handle)) bind(req, res, handle, r.handle());
            json(res, 200, r.view());
            return;
        }
        if (method.equals("GET") && path.equals("/session")) {
            json(res, 200, service.session(handle).view());
            return;
        }
        if (method.equals("GET") && path.equals("/login")) {
            Map<String, String> query = query(req);
            if (!Set.of("returnTo").containsAll(query.keySet()))
                throw WebSessionException.invalid();
            redirect(
                    res,
                    service.hosted(
                            handle, query.getOrDefault("returnTo", config.defaultReturnPath())));
            return;
        }
        if (method.equals("GET") && path.equals("/callback")) {
            WebSessionService.Result result;
            try {
                result = service.callback(handle, query(req));
            } catch (WebSessionException e) {
                if (e.code().equals("AUTH_ACCESS_DENIED")) {
                    carrier.clear(req, res, handle);
                    redirect(res, config.defaultReturnPath());
                    return;
                }
                throw e;
            }
            if (!result.handle().equals(handle)) bind(req, res, handle, result.handle());
            redirect(res, service.returnPath(result.handle()));
            return;
        }
        if (method.equals("GET") && Set.of("/auth-methods", "/auth-policy").contains(path)) {
            json(res, 200, service.capabilities(path.substring(1)));
            return;
        }
        if (method.equals("GET") && path.matches("/registration/[A-Za-z0-9_-]{43}")) {
            json(
                    res,
                    200,
                    service.registration(
                            handle,
                            path.substring("/registration/".length()),
                            "get",
                            WebWire.object()));
            return;
        }
        if (!method.equals("POST")) {
            throw new WebSessionException(404, "NOT_FOUND");
        }
        ObjectNode body = body(req);
        if (path.equals("/session/logout")) {
            WebWire.fields(body, Set.of(), Set.of());
            WebSessionService.Logout logout;
            try {
                logout = service.logout(handle);
            } catch (WebSessionException e) {
                carrier.clear(req, res, handle);
                error(
                        res,
                        e,
                        WebWire.object()
                                .put("local", "UNCONFIRMED")
                                .put("cookie", "CLEARED")
                                .put("remote", "UNCONFIRMED")
                                .put("sso", "NOT_REQUESTED"));
                return;
            }
            carrier.clear(req, res, handle);
            if (logout.status() == 200) json(res, 200, logout.result());
            else error(res, new WebSessionException(503, "LOGOUT_UNCONFIRMED"), logout.result());
            return;
        }
        if (path.equals("/session/login")) {
            WebWire.fields(body, Set.of(), Set.of());
            json(res, 200, service.custom(handle).view());
            return;
        }
        if (path.startsWith("/session/login/")) {
            WebSessionService.Result result =
                    service.action(handle, path.substring("/session/login/".length()), body);
            if (!result.handle().equals(handle)) bind(req, res, handle, result.handle());
            if (path.endsWith("/cancel")) carrier.clear(req, res, handle);
            json(res, 200, result.view());
            return;
        }
        if (path.equals("/registration")) {
            ObjectNode safe = service.registration(handle, null, "create", body);
            json(
                    res,
                    "PENDING_VERIFICATION".equals(safe.path("status").asText()) ? 202 : 201,
                    safe);
            return;
        }
        if (path.matches("/registration/[A-Za-z0-9_-]{43}/(challenges|complete|cancel)")) {
            String[] parts = path.split("/");
            json(res, 200, service.registration(handle, parts[2], parts[3], body));
            return;
        }
        if (path.startsWith("/password-reset/")) {
            service.passwordReset(path.substring("/password-reset/".length()), body);
            res.setStatus(204);
            return;
        }
        throw new WebSessionException(404, "NOT_FOUND");
    }

    private void bind(HttpServletRequest req, HttpServletResponse res, String old, String next) {
        try {
            carrier.bind(req, res, old, next);
        } catch (RuntimeException e) {
            // New credentials must not survive a failed host Session commit.
            service.logout(next);
            throw new WebSessionException(401, "AUTH_EXCHANGE_UNCERTAIN");
        }
    }

    private static ObjectNode body(HttpServletRequest req) throws IOException {
        if (req.getContentType() == null
                || !req.getContentType().split(";")[0].trim().equals("application/json"))
            throw WebSessionException.invalid();
        byte[] bytes = req.getInputStream().readNBytes(65537);
        if (bytes.length > 65536) throw WebSessionException.invalid();
        try {
            return WebWire.parse(bytes);
        } catch (WebSessionException e) {
            throw WebSessionException.invalid();
        }
    }

    private static Map<String, String> query(HttpServletRequest req) {
        Map<String, String> out = new HashMap<>();
        req.getParameterMap()
                .forEach(
                        (k, v) -> {
                            if (v.length != 1 || v[0].isBlank() || v[0].length() > 4096)
                                throw WebSessionException.invalid();
                            out.put(k, v[0]);
                        });
        return out;
    }

    private static void redirect(HttpServletResponse res, String location) {
        res.setStatus(302);
        res.setHeader("Location", location);
    }

    private static void json(HttpServletResponse res, int status, ObjectNode value)
            throws IOException {
        res.setStatus(status);
        res.setContentType("application/json");
        res.setHeader("Cache-Control", "no-store");
        res.getOutputStream().write(WebWire.JSON.writeValueAsBytes(value));
    }

    private static void error(HttpServletResponse res, WebSessionException e, ObjectNode details)
            throws IOException {
        ObjectNode n =
                WebWire.object()
                        .put("status", e.status())
                        .put("error", e.code())
                        .put("message", "Authentication request could not be completed")
                        .put("timestamp", Instant.now().toString());
        if (details != null) n.set("details", details);
        if (e.retryAfter() != null) res.setHeader("Retry-After", e.retryAfter().toString());
        json(res, e.status(), n);
    }

    private static Authentication authentication(ObjectNode safe) {
        CurrentUserResponse p = CurrentUserResponse.fromJson(safe.get("profile"));
        CurrentUserResponse.AuthenticationContext c = p.authenticationContext();
        Set<String> roles = strings(safe.path("permissions").path("roles")),
                permissions = strings(safe.path("permissions").path("permissions"));
        IamCurrentUser user =
                new IamCurrentUser(
                        p.id(),
                        c.applicationId(),
                        p.email(),
                        p.emailVerified(),
                        p.username(),
                        c.organizationId(),
                        c.organizationSlug(),
                        c.organizationRole(),
                        c.workspaceId(),
                        c.sessionId(),
                        roles,
                        permissions,
                        c.authenticationMethods(),
                        c.assuranceLevel(),
                        c.impersonation() == null
                                ? null
                                : new IamActor(c.impersonation().actorId()),
                        Map.of());
        return UsernamePasswordAuthenticationToken.authenticated(
                user, null, permissions.stream().map(SimpleGrantedAuthority::new).toList());
    }

    private static Set<String> strings(JsonNode array) {
        Set<String> values = new LinkedHashSet<>();
        array.forEach(v -> values.add(v.textValue()));
        return values;
    }
}
