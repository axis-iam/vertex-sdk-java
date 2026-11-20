package com.chaosguide.iam.vertex.web;

import org.junit.jupiter.api.Test;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.Callable;
import static org.assertj.core.api.Assertions.*;
import static com.chaosguide.iam.vertex.web.WebSessionRecord.Kind.*;
import static com.chaosguide.iam.vertex.web.WebSessionRecord.Lifecycle.*;

class WebSessionMemoryTest {
    static final class MutableClock extends Clock {
        Instant now = Instant.now();
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
    private WebSessionRecord record(MutableClock clock) {
        return new WebSessionRecord(WebSessionService.random(),PRELOGIN,0,clock.now,clock.now.plusSeconds(60),clock.now.plusSeconds(60),READY,
                WebWire.object().put("state","PRELOGIN").put("csrfToken",WebSessionService.random()));
    }
    @Test void concurrentConsumeHasOneWinnerAndInvalidationIsTerminal() throws Exception {
        MutableClock clock = new MutableClock();
        try (MemoryWebSessionStore store = new MemoryWebSessionStore(clock,1,1,65536,Duration.ofSeconds(60))) {
            WebSessionRecord r = record(clock); store.create(r);
            var pool = Executors.newFixedThreadPool(8);
            try {
                List<Callable<Boolean>> calls = new ArrayList<>();
                for (int i=0;i<32;i++) calls.add(() -> store.replace(r,r.next(OWNED,r.data(),r.idleExpiresAt())));
                long winners=0; for (var f : pool.invokeAll(calls)) if (f.get()) winners++;
                assertThat(winners).isEqualTo(1);
                WebSessionRecord owned=store.read(r.id()).orElseThrow(); store.invalidate(r.id());
                assertThat(store.replace(owned,owned.next(READY,owned.data(),owned.idleExpiresAt()))).isFalse();
            } finally { pool.shutdownNow(); }
        }
    }
    @Test void capacityPurgesExpiredNeverEvictsLiveAndClosedIsTyped() {
        MutableClock clock=new MutableClock();
        MemoryWebSessionStore store=new MemoryWebSessionStore(clock,1,1,1024,Duration.ofSeconds(60));
        WebSessionRecord first=record(clock); store.create(first);
        assertThatThrownBy(() -> store.create(record(clock))).isInstanceOf(WebSessionException.class).hasMessage("SESSION_STORE_CAPACITY");
        assertThat(store.read(first.id())).isPresent();
        clock.now=clock.now.plusSeconds(61); store.create(record(clock)); assertThat(store.read(first.id())).isEmpty();
        store.close(); assertThatThrownBy(() -> store.read(first.id())).hasMessage("SESSION_STORE_CLOSED");
        assertThatThrownBy(() -> store.create(record(clock))).hasMessage("SESSION_STORE_CLOSED");
    }
    @Test void isolatedCopiesBoundedSizeAndRestart() {
        MutableClock clock=new MutableClock();
        try (MemoryWebSessionStore store=new MemoryWebSessionStore(clock,1,2,1024,Duration.ofSeconds(60))) {
            WebSessionRecord r=record(clock); store.create(r); store.read(r.id()).orElseThrow().data().put("csrfToken","changed");
            assertThat(store.read(r.id()).orElseThrow().data().path("csrfToken").asText()).hasSize(43);
            WebSessionRecord big=new WebSessionRecord(WebSessionService.random(),PRELOGIN,0,clock.now,clock.now.plusSeconds(60),clock.now.plusSeconds(60),READY,WebWire.object().put("huge","x".repeat(2048)));
            assertThatThrownBy(() -> store.create(big)).hasMessage("SESSION_STORE_CAPACITY");
        }
        try (MemoryWebSessionStore restarted=new MemoryWebSessionStore()) { assertThat(restarted.read("a".repeat(43))).isEmpty(); }
    }
    @Test void memoryCannotClaimMultipleProcessesAndRecordDiagnosticsAreRedacted() {
        try (MemoryWebSessionStore store=new MemoryWebSessionStore()) {
            assertThatThrownBy(() -> store.validateTopology(2)).isInstanceOf(IllegalArgumentException.class);
            MutableClock c=new MutableClock(); WebSessionRecord r=record(c);
            assertThat(r.toString()).doesNotContain(r.id(),r.data().path("csrfToken").asText());
            assertThatThrownBy(() -> new MemoryWebSessionStore(c,0,1,1024,Duration.ofSeconds(1))).isInstanceOf(IllegalArgumentException.class);
        }
    }
}
