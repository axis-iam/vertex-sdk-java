package com.chaosguide.iam.vertex.web;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/** Bounded volatile single-JVM provider. Construct one shared instance per application. */
public final class MemoryWebSessionStore implements WebSessionStore {
    private final Map<String, WebSessionRecord> records = new HashMap<>();
    private final Map<String,String> consumedBindings = new HashMap<>();
    private final Clock clock;
    private final int maxSessions, maxPrelogins, maxRecordBytes;
    private final ScheduledExecutorService cleaner;
    private boolean closed;
    public MemoryWebSessionStore() { this(Clock.systemUTC(), 10000, 1000, 65536, Duration.ofSeconds(60)); }
    public MemoryWebSessionStore(Clock clock, int maxSessions, int maxPrelogins, int maxRecordBytes, Duration cleanup) {
        if (maxSessions < 1 || maxPrelogins < 1 || maxRecordBytes < 1 || cleanup.isZero()
                || cleanup.isNegative() || cleanup.toMillis() < 1)
            throw new IllegalArgumentException("Positive finite memory limits required");
        this.clock = Objects.requireNonNull(clock); this.maxSessions = maxSessions;
        this.maxPrelogins = maxPrelogins; this.maxRecordBytes = maxRecordBytes;
        cleaner = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "axis-web-session-cleanup"); t.setDaemon(true); return t;
        });
        cleaner.scheduleWithFixedDelay(this::purge, cleanup.toMillis(), cleanup.toMillis(), TimeUnit.MILLISECONDS);
    }
    private void checkOpen() { if (closed) throw new WebSessionException(503, "SESSION_STORE_CLOSED"); }
    public synchronized void purge() {
        records.values().removeIf(r -> r.expired(clock.instant()));
        consumedBindings.values().removeIf(id -> !records.containsKey(id));
    }
    @Override public synchronized Optional<WebSessionRecord> read(String id) {
        checkOpen(); purge(); return Optional.ofNullable(records.get(id));
    }
    private void size(WebSessionRecord value, String excluded) {
        if (value.data().toString().getBytes(StandardCharsets.UTF_8).length + 512 > maxRecordBytes)
            throw new WebSessionException(503, "SESSION_STORE_CAPACITY");
        long count = records.values().stream().filter(r -> !r.id().equals(excluded)
                && (r.kind() == WebSessionRecord.Kind.SESSION) == (value.kind() == WebSessionRecord.Kind.SESSION)).count();
        if (count >= (value.kind() == WebSessionRecord.Kind.SESSION ? maxSessions : maxPrelogins))
            throw new WebSessionException(503, "SESSION_STORE_CAPACITY");
    }
    @Override public synchronized void create(WebSessionRecord value) {
        checkOpen(); purge();
        if (value.expired(clock.instant())) throw new IllegalArgumentException("Cannot create expired record");
        if (records.containsKey(value.id()) || consumedBindings.containsKey(value.id())) throw WebSessionException.conflict();
        if (value.version() != 0) throw new IllegalArgumentException("Initial version must be zero");
        size(value, null); records.put(value.id(), value);
    }
    @Override public synchronized boolean replace(WebSessionRecord expected, WebSessionRecord value) {
        checkOpen(); purge();
        WebSessionRecord current = records.get(expected.id());
        if (current == null || current.version() != expected.version() || current.kind() != expected.kind()
                || !current.createdAt().equals(expected.createdAt())
                || !current.absoluteExpiresAt().equals(expected.absoluteExpiresAt())) return false;
        boolean rotation = !expected.id().equals(value.id());
        if (value.expired(clock.instant()) || (rotation && (records.containsKey(value.id()) || consumedBindings.containsKey(value.id()))))
            return false;
        if (!rotation && (value.version() != expected.version() + 1 || value.kind() != expected.kind()
                || !value.createdAt().equals(expected.createdAt())
                || value.absoluteExpiresAt().isAfter(expected.absoluteExpiresAt())))
            throw new IllegalArgumentException("Invalid conditional update");
        if (rotation && (value.version() != 0 || expected.lifecycle() != WebSessionRecord.Lifecycle.SEND_INTENT
                || expected.kind() != WebSessionRecord.Kind.PRELOGIN
                || value.kind() != WebSessionRecord.Kind.SESSION))
            throw new IllegalArgumentException("Only consumed prelogin rotates to a session");
        size(value, expected.id()); records.remove(expected.id()); records.put(value.id(), value);
        if (rotation) consumedBindings.put(expected.id(),value.id());
        return true;
    }
    @Override public synchronized Optional<WebSessionRecord> invalidate(String id) {
        checkOpen(); purge();
        String target=consumedBindings.getOrDefault(id,id);
        WebSessionRecord removed=records.remove(target);
        consumedBindings.values().removeIf(value -> value.equals(target));
        return Optional.ofNullable(removed);
    }
    @Override public void validateTopology(int processes) {
        if (processes != 1) throw new IllegalArgumentException("Memory sessions require one JVM process");
    }
    @Override public synchronized void close() {
        closed = true; cleaner.shutdownNow(); records.clear(); consumedBindings.clear();
    }
}
