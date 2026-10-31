package com.chaosguide.iam.vertex.exception;

public final class AccountSecurityException extends IamSdkException {
    private final int status;
    private final String code;
    private final Integer retryAfterSeconds;
    public AccountSecurityException(int status, String code, Integer retryAfterSeconds) {
        super("Account security request rejected: HTTP " + status + " " + code);
        this.status = status;
        this.code = code;
        this.retryAfterSeconds = retryAfterSeconds;
    }
    public int status() {
        return status;
    }
    public String code() {
        return code;
    }
    public Integer retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
