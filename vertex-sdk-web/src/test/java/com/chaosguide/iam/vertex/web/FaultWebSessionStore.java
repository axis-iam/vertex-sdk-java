package com.chaosguide.iam.vertex.web;
import java.util.Optional;
import static com.chaosguide.iam.vertex.web.WebSessionRecord.Lifecycle.*;
/** Injects acknowledged provider failures without substituting absent/empty success. */
final class FaultWebSessionStore implements WebSessionStore {
    final WebSessionStore delegate;
    boolean failRead, failInvalidate, failCommit, failIntent;
    FaultWebSessionStore(WebSessionStore delegate) { this.delegate=delegate; }
    private WebSessionException unavailable() { return new WebSessionException(503,"SESSION_STORE_UNAVAILABLE"); }
    @Override public Optional<WebSessionRecord> read(String id) { if(failRead) throw unavailable(); return delegate.read(id); }
    @Override public void create(WebSessionRecord r) { delegate.create(r); }
    @Override public boolean replace(WebSessionRecord from, WebSessionRecord to) {
        if (failIntent && to.lifecycle()==SEND_INTENT) { failIntent=false; throw unavailable(); }
        if (failCommit && from.lifecycle()==SEND_INTENT && (to.lifecycle()==READY || !from.id().equals(to.id()))) throw unavailable();
        return delegate.replace(from,to);
    }
    @Override public Optional<WebSessionRecord> invalidate(String id) { if(failInvalidate) throw unavailable(); return delegate.invalidate(id); }
    @Override public void validateTopology(int count) { delegate.validateTopology(count); }
    @Override public void close() { delegate.close(); }
}
