package com.chaosguide.iam.vertex.web;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.util.Objects;

/** Provider-only snapshot. Never return this type from an application controller. */
public final class WebSessionRecord {
    public enum Kind { PRELOGIN, SESSION, REGISTRATION }
    public enum Lifecycle { READY, OWNED, SEND_INTENT }
    private final String id;
    private final Kind kind;
    private final long version;
    private final Instant createdAt, absoluteExpiresAt, idleExpiresAt;
    private final Lifecycle lifecycle;
    private final ObjectNode data;
    public WebSessionRecord(String id, Kind kind, long version, Instant createdAt,
            Instant absoluteExpiresAt, Instant idleExpiresAt, Lifecycle lifecycle, ObjectNode data) {
        if (id == null || !id.matches("[A-Za-z0-9_-]{43}") || version < 0
                || !absoluteExpiresAt.isAfter(createdAt) || idleExpiresAt.isAfter(absoluteExpiresAt))
            throw new IllegalArgumentException("Invalid session record");
        this.id = id; this.kind = Objects.requireNonNull(kind); this.version = version;
        this.createdAt = createdAt; this.absoluteExpiresAt = absoluteExpiresAt; this.idleExpiresAt = idleExpiresAt;
        this.lifecycle = Objects.requireNonNull(lifecycle); this.data = data.deepCopy();
    }
    public int schemaVersion() { return 1; }
    public String id() { return id; }
    public Kind kind() { return kind; }
    public long version() { return version; }
    public Instant createdAt() { return createdAt; }
    public Instant absoluteExpiresAt() { return absoluteExpiresAt; }
    public Instant idleExpiresAt() { return idleExpiresAt; }
    public Lifecycle lifecycle() { return lifecycle; }
    @JsonIgnore public ObjectNode data() { return data.deepCopy(); }
    public boolean expired(Instant now) { return !absoluteExpiresAt.isAfter(now) || !idleExpiresAt.isAfter(now); }
    public WebSessionRecord next(Lifecycle state, ObjectNode values, Instant idle) {
        return new WebSessionRecord(id, kind, version + 1, createdAt, absoluteExpiresAt, idle, state, values);
    }
    @Override public String toString() { return "WebSessionRecord[" + kind + ",v=" + version + ",redacted]"; }
}
