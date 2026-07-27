package com.chaosguide.iam.vertex.exception;

/**
 * Base exception for all IAM SDK errors.
 */
/** SDK 运行时异常基类，用于包裹 HTTP、JSON、JWKS 等接入侧错误。 */
public class IamSdkException extends RuntimeException {

    public IamSdkException(String message) {
        super(message);
    }

    public IamSdkException(String message, Throwable cause) {
        super(message, cause);
    }
}
