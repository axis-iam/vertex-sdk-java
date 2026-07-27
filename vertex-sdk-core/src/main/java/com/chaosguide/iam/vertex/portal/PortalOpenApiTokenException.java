package com.chaosguide.iam.vertex.portal;

import com.chaosguide.iam.vertex.exception.IamSdkException;

/** Failure while requesting or validating a Portal Open API machine token. */
public class PortalOpenApiTokenException extends IamSdkException {

    private final int statusCode;
    private final String code;
    private final String body;

    public PortalOpenApiTokenException(String message, String code) {
        this(message, 0, code, null);
    }

    public PortalOpenApiTokenException(String message, int statusCode, String code, String body) {
        super(message);
        this.statusCode = statusCode;
        this.code = code;
        this.body = body;
    }

    public PortalOpenApiTokenException(String message, Throwable cause) {
        super(message, cause);
        this.statusCode = 0;
        this.code = "transport_error";
        this.body = null;
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
}
