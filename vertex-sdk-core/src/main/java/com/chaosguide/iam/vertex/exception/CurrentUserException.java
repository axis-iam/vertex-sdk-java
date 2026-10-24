package com.chaosguide.iam.vertex.exception;

/** HTTP failure reading the safe current-user view, without upstream diagnostic text. */
public final class CurrentUserException extends IamSdkException {
    private final int status;
    public CurrentUserException(int status) { super("Current-user request failed: HTTP " + status); this.status = status; }
    public int status() { return status; }
}
