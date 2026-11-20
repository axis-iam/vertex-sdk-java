package com.chaosguide.iam.vertex.web;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import java.time.Duration;
/** Dedicated opaque Cookie carrier; no Servlet Session or second authentication Cookie. */
public final class CookieWebSessionCarrier implements WebSessionCarrier {
    private final String name;
    private final boolean secure;
    public CookieWebSessionCarrier(WebBffConfig config) {
        secure = "https".equals(config.origin().getScheme());
        name = secure ? "__Host-axis-session" : "axis-dev-session";
    }
    @Override public String read(HttpServletRequest request) {
        String value = null;
        if (request.getCookies() != null) for (Cookie cookie : request.getCookies()) if (cookie.getName().equals(name)) {
            if (value != null) throw WebSessionException.invalid(); value = cookie.getValue();
        }
        return value;
    }
    private void set(HttpServletResponse response, String value, Duration age) {
        response.addHeader(HttpHeaders.SET_COOKIE,ResponseCookie.from(name,value).path("/").httpOnly(true)
                .secure(secure).sameSite("Lax").maxAge(age).build().toString());
    }
    @Override public void bind(HttpServletRequest request, HttpServletResponse response, String expected, String handle) {
        set(response,handle,Duration.ofHours(1));
    }
    @Override public void clear(HttpServletRequest request, HttpServletResponse response, String expected) {
        set(response,"",Duration.ZERO);
    }
}
