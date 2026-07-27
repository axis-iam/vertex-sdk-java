package com.chaosguide.iam.vertex.portal;

import com.chaosguide.iam.vertex.exception.IamSdkException;

/** Failure returned by a Portal {@code /open/v1/**} resource request. */
public class PortalOpenApiException extends IamSdkException {

    private final int statusCode;
    private final String code;
    private final String body;
    private final String retryAfter;

    public PortalOpenApiException(String message, int statusCode, String code, String body) {
        this(message, statusCode, code, body, null);
    }

    public PortalOpenApiException(String message, int statusCode, String code, String body, String retryAfter) {
        super(message);
        this.statusCode = statusCode;
        this.code = code;
        this.body = body;
        this.retryAfter = retryAfter;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getCode() {
        return code;
    }

    public String getBody() {
        return body;
    }

    /** Raw Retry-After header returned by Portal for rate-limited requests, when present. */
    public String getRetryAfter() {
        return retryAfter;
    }
}
