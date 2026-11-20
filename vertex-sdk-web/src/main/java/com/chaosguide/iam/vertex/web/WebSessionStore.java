package com.chaosguide.iam.vertex.web;
import java.util.Optional;
/**
 * Linearizable host storage port. Empty means absent/expired only. Failures throw typed exceptions.
 * Conditional replace validates id/version/kind/creation/deadline and atomically replaces or rotates.
 * Invalidation is terminal; a stale replacement never recreates a missing record.
 * A rotation keeps a consumed-handle termination link until its derived session expires/terminates:
 * read(consumed) is absent, while invalidate(consumed) atomically terminates that derived session.
 * This link contains no credential and never enables callback/token response recovery.
 */
public interface WebSessionStore extends AutoCloseable {
    Optional<WebSessionRecord> read(String id);
    void create(WebSessionRecord record);
    boolean replace(WebSessionRecord expected, WebSessionRecord replacement);
    Optional<WebSessionRecord> invalidate(String id);
    void validateTopology(int processes);
    @Override void close();
}
