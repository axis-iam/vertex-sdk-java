package com.chaosguide.iam.vertex.exception;

public final class AccountSecurityProtocolException extends IamSdkException {
    public AccountSecurityProtocolException() {
        super("Invalid or unsupported account security response");
    }
}
