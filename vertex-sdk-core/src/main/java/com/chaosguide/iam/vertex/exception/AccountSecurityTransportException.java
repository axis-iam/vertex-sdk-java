package com.chaosguide.iam.vertex.exception;

public final class AccountSecurityTransportException extends IamSdkException {
    private final boolean outcomeUnknown;
    public AccountSecurityTransportException(boolean outcomeUnknown) {
        super("Account security transport failed; no automatic replay");
        this.outcomeUnknown = outcomeUnknown;
    }
    public boolean outcomeUnknown() {
        return outcomeUnknown;
    }
}
