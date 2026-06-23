package com.platypus.proxy.handler.warp;

import com.platypus.proxy.io.warp.TunnelOpener;
import java.io.Closeable;
import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

final class WarpOriginPool implements Closeable {

    private static final long IDLE_TIMEOUT_MS = 60_000;

    private final ConcurrentHashMap<String, WarpOriginSession> sessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, CompletableFuture<WarpOriginSession>> pendingCreations
            = new ConcurrentHashMap<>();
    private final TunnelOpener warpOpener;
    private final ScheduledExecutorService evictor;

    WarpOriginPool(TunnelOpener warpOpener) {
        this.warpOpener = warpOpener;
        this.evictor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "warp-pool-evictor");
            t.setDaemon(true);
            return t;
        });
        this.evictor.scheduleWithFixedDelay(this::evictIdle, 15_000, 15_000, TimeUnit.MILLISECONDS);
    }

    WarpOriginSession getOrCreate(String host, int port) throws IOException {
        String key = host + ":" + port;

        WarpOriginSession existing = sessions.get(key);
        if (existing != null && !existing.isClosed()) return existing;

        CompletableFuture<WarpOriginSession> future =
                pendingCreations.computeIfAbsent(key, k -> new CompletableFuture<>());
        if (future.isDone()) {
            try {
                return future.get();
            } catch (Exception e) {
                pendingCreations.remove(key, future);
                throw rethrowIoException(e);
            }
        }

        try {
            WarpOriginSession session = new WarpOriginSession(host, port, warpOpener);
            sessions.put(key, session);
            future.complete(session);
            return session;
        } catch (Exception e) {
            future.completeExceptionally(e);
            pendingCreations.remove(key, future);
            throw e;
        }
    }

    void evict(String host, int port) {
        String key = host + ":" + port;
        WarpOriginSession removed = sessions.remove(key);
        if (removed != null) removed.close();
    }

    private void evictIdle() {
        long deadline = System.nanoTime() - TimeUnit.MILLISECONDS.toNanos(IDLE_TIMEOUT_MS);
        sessions.forEach((key, session) -> {
            if (session.isIdle(deadline)) {
                sessions.remove(key, session);
                session.close();
            }
        });
    }

    @Override
    public void close() {
        evictor.shutdownNow();
        sessions.forEach((k, v) -> v.close());
        sessions.clear();
        pendingCreations.clear();
    }

    private static IOException rethrowIoException(Throwable t) {
        if (t instanceof IOException) return (IOException) t;
        if (t instanceof RuntimeException) throw (RuntimeException) t;
        return new IOException(t);
    }
}
