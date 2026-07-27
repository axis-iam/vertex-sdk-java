package com.chaosguide.iam.vertex.context;

/** Delegating actor carried by the JWT {@code act} claim during impersonation. */
public record IamActor(String subject) {
}
