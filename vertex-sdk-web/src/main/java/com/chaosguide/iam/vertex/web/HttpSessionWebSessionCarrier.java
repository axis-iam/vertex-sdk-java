package com.chaosguide.iam.vertex.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import java.time.Duration;
import java.util.Objects;

/**
 * Single-JVM Servlet Session handle bridge. Tokens never enter Session attributes. Native Cookie
 * config must match name, Path=/, host-only, Secure, HttpOnly, SameSite=Lax. Spring
 * Session/distributed automatic-save semantics are not certified by this bridge.
 */
public final class HttpSessionWebSessionCarrier implements WebSessionCarrier {
    public static final String ATTRIBUTE = "com.chaosguide.iam.vertex.web.handle.v1";
    private final String cookieName;
    private final boolean secure;

    public HttpSessionWebSessionCarrier(
            WebBffConfig config, String cookieName, boolean nativeCookieConfigured) {
        if (config.declaredProcesses() != 1
                || !nativeCookieConfigured
                || cookieName == null
                || !cookieName.matches("[A-Za-z0-9_-]+"))
            throw new IllegalArgumentException(
                    "Native Session requires verified Cookie configuration and one JVM");
        this.cookieName = cookieName;
        this.secure = "https".equals(config.origin().getScheme());
        if (!secure && cookieName.startsWith("__Host-"))
            throw new IllegalArgumentException("Development Cookie cannot use __Host-");
    }

    @Override
    public String read(HttpServletRequest request) {
        HttpSession s = request.getSession(false);
        if (s == null) return null;
        Object value = s.getAttribute(ATTRIBUTE);
        if (value == null) return null;
        if (!(value instanceof String)) throw WebSessionException.protocol();
        return (String) value;
    }

    @Override
    public void bind(
            HttpServletRequest request,
            HttpServletResponse response,
            String expected,
            String handle) {
        HttpSession session = request.getSession(true);
        synchronized (session) {
            if (!Objects.equals(session.getAttribute(ATTRIBUTE), expected))
                throw WebSessionException.conflict();
            request.changeSessionId();
            session.setAttribute(ATTRIBUTE, handle);
        }
    }

    @Override
    public void clear(HttpServletRequest request, HttpServletResponse response, String expected) {
        HttpSession session = request.getSession(false);
        if (session != null)
            synchronized (session) {
                if (!Objects.equals(session.getAttribute(ATTRIBUTE), expected))
                    throw WebSessionException.conflict();
                session.removeAttribute(ATTRIBUTE);
            }
        response.addHeader(
                HttpHeaders.SET_COOKIE,
                ResponseCookie.from(cookieName, "")
                        .path("/")
                        .httpOnly(true)
                        .secure(secure)
                        .sameSite("Lax")
                        .maxAge(Duration.ZERO)
                        .build()
                        .toString());
    }
}
