package com.chaosguide.iam.vertex.web;

/** Sanitized public failure. Upstream bodies, credentials and causes are never included. */
public final class WebSessionException extends RuntimeException {
    private final int status;
    private final String code;
    private final Integer retryAfter;
    public WebSessionException(int status, String code) { this(status, code, null); }
    public WebSessionException(int status, String code, Integer retryAfter) {
        super(safeCode(code));
        if (status < 400 || status > 599 || (retryAfter != null && retryAfter < 0))
            throw new IllegalArgumentException("Invalid public authentication error");
        this.status = status; this.code = code; this.retryAfter = retryAfter;
    }
    private static String safeCode(String code) {
        if (code == null || !code.matches("[A-Za-z][A-Za-z0-9_]{0,127}"))
            throw new IllegalArgumentException("Invalid public authentication error code");
        return code;
    }
    public int status() { return status; }
    public String code() { return code; }
    public Integer retryAfter() { return retryAfter; }
    static WebSessionException invalid() { return new WebSessionException(400, "VALIDATION_ERROR"); }
    static WebSessionException protocol() { return new WebSessionException(502, "IAM_PROTOCOL_ERROR"); }
    static WebSessionException conflict() { return new WebSessionException(409, "SESSION_ACTION_PENDING"); }
    static WebSessionException absent() { return new WebSessionException(401, "SESSION_REQUIRED"); }
}
