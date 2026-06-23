package com.platypus.proxy.handler.h2;

import com.platypus.proxy.logging.CondLogger;
import java.io.IOException;
import java.net.Socket;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Intelligent per-host connection pool for h2 upstream connections.
 *
 * <p>Each host:port key gets:
 * <ul>
 *   <li>A {@link LinkedBlockingQueue} of idle connections for reuse.</li>
 *   <li>An {@link AtomicInteger} active counter capped at {@value #MAX_PER_HOST}.</li>
 *   <li>A fair {@link Semaphore} limiting concurrent connections per host.</li>
 * </ul>
 *
 * Global limit of {@value #MAX_TOTAL} sockets enforced by a top-level semaphore.
 * A background sweeper evicts idle connections older than {@value #IDLE_TTL_MS}.
 *
 * <p>Callers use {@link #acquireForHost(String)} which blocks until a connection
 * is available (either from idle cache or a new permit), then call
 * {@link #returnConnection(String, H2TunnelConnection, boolean)} to return
 * the connection for reuse (reusable=true) or close it (reusable=false).
 */
public class H2UpstreamPool {

    // RFC 9113 §9.1 connection management -- reuse; pool bounds guard against §10.5 DoS
    private static final int MAX_TOTAL = 1024;
    private static final int MAX_PER_HOST = 128;
    private static final int MAX_IDLE_PER_HOST = 32;
    private static final long ACQUIRE_TIMEOUT_MS = 5_000;
    private static final long IDLE_TTL_MS = 30_000;
    private static final long SWEEPER_INTERVAL_MS = 10_000;

    private final Semaphore globalPermits = new Semaphore(MAX_TOTAL, true);
    private final Set<Socket> leased = ConcurrentHashMap.newKeySet();

    private final Map<String, HostPool> hostPools = new ConcurrentHashMap<>();
    private final CondLogger logger;
    private final Thread sweeper;
    private volatile boolean shuttingDown = false;

    public H2UpstreamPool(CondLogger logger) {
        this.logger = logger;
        this.sweeper = new Thread(this::sweeperLoop, "h2-pool-sweeper");
        this.sweeper.setDaemon(true);
        this.sweeper.start();
    }

    // =====================================================================
    //  Host pool management
    // =====================================================================

    private HostPool getOrCreate(String key) {
        return hostPools.computeIfAbsent(key, k -> new HostPool(k));
    }

    // RFC 9113 §9.1.1 connection reuse -- prefer idle connection, fall back to new
    public AcquireResult acquireForHost(String key) throws IOException {
        HostPool hp = getOrCreate(key);
        long deadline = System.currentTimeMillis() + ACQUIRE_TIMEOUT_MS;

        // Spin: check idle cache, then try permits with short timeouts.
        // This ensures connections returned to idle are found quickly
        // even when all per-host permits are taken.
        while (true) {
            H2TunnelConnection cached = hp.pollIdle();
            if (cached != null && isValid(cached)) {
                cached.checkout();
                logger.Debug("[H2-POOL] Reusing idle connection for %s (idle=%dms)",
                        key, System.currentTimeMillis() - hp.lastCheckout);
                return AcquireResult.reused(cached);
            }
            if (cached != null) {
                cached.forceClose();
            }

            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= 0) {
                throw new IOException("H2 pool: timeout acquiring permits for " + key
                        + " (host=" + hp.hostSemaphore.availablePermits()
                        + ", global=" + globalPermits.availablePermits() + ")");
            }
            long waitMs = Math.min(remaining, 50);

            boolean gotHost = false;
            try {
                gotHost = hp.hostSemaphore.tryAcquire(waitMs, TimeUnit.MILLISECONDS);
                if (gotHost) {
                    if (globalPermits.tryAcquire(waitMs, TimeUnit.MILLISECONDS)) {
                        hp.activeCount.incrementAndGet();
                        hp.lastCheckout = System.currentTimeMillis();
                        return AcquireResult.create();
                    }
                    // Global permit timed out -- release host permit
                    hp.hostSemaphore.release();
                }
            } catch (InterruptedException e) {
                if (gotHost) hp.hostSemaphore.release();
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted acquiring permits for " + key);
            }
        }
    }

    /**
     * Track a newly created socket as leased.
     * Must be called after {@link #acquireForHost(String)} returns create().
     */
    public void trackNew(Socket socket) {
        leased.add(socket);
    }

    // RFC 9113 §9.1 -- return idle connection for reuse or close
    public void returnConnection(String key, H2TunnelConnection conn, boolean reusable) {
        HostPool hp = getOrCreate(key);

        if (!reusable || shuttingDown || !isValid(conn)) {
            closeConnection(conn, hp);
            return;
        }

        if (hp.idleQueue.size() >= MAX_IDLE_PER_HOST) {
            closeConnection(conn, hp);
            logger.Debug("[H2-POOL] Idle cache full for %s, closing", key);
            return;
        }

        hp.idleQueue.offer(new PooledEntry(conn, System.currentTimeMillis()));
        logger.Debug("[H2-POOL] Returned idle connection for %s (idle=%d, active=%d)",
                key, hp.idleQueue.size(), hp.activeCount.get());
    }

    private void closeConnection(H2TunnelConnection conn, HostPool hp) {
        Socket poolSocket = conn.poolSocket();
        boolean removed = leased.remove(poolSocket);
        if (removed) {
            globalPermits.release();
            hp.hostSemaphore.release();
            hp.activeCount.decrementAndGet();
        }
        try { conn.socket().close(); } catch (Exception ignored) {}
    }

    // Fast check: no blocking, no permit consumption -- idle connection still holds permits
    public H2TunnelConnection tryAcquireIdle(String key) {
        HostPool hp = getOrCreate(key);
        H2TunnelConnection cached = hp.pollIdle();
        if (cached != null && isValid(cached)) {
            cached.checkout();
            logger.Debug("[H2-POOL] Reusing idle connection for %s", key);
            return cached;
        }
        if (cached != null) cached.forceClose();
        return null;
    }

    /**
     * Forceful release: close socket + release permits.
     * Used when a connection is known to be broken.
     */
    public void releaseOwnedSocket(Socket socket) {
        if (socket == null) return;
        boolean removed = leased.remove(socket);
        if (removed) {
            globalPermits.release();
            for (HostPool hp : hostPools.values()) {
                if (hp.hostSemaphore.tryAcquire()) {
                    hp.hostSemaphore.release();
                    hp.activeCount.decrementAndGet();
                    break;
                }
            }
        }
        closeQuietly(socket);
    }

    // =====================================================================
    //  Legacy compat (used by H2ProxyService.passthrough etc.)
    // =====================================================================

    public void acquirePermit() throws IOException {
        try {
            if (!globalPermits.tryAcquire(ACQUIRE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                throw new IOException("H2 upstream pool exhausted");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted");
        }
    }

    public boolean tryAcquireGlobalPermit(long timeoutMs) throws InterruptedException {
        return globalPermits.tryAcquire(timeoutMs, TimeUnit.MILLISECONDS);
    }

    public void track(Socket socket) {
        leased.add(socket);
    }

    /**
     * Release a previously acquired global permit without a socket.
     * Used when socket creation fails after the permit was acquired.
     */
    public void releaseGlobalPermit() {
        globalPermits.release();
    }

    // =====================================================================
    //  Stats / lifecycle
    // =====================================================================

    public int leasedCount() { return leased.size(); }
    public int availablePermits() { return globalPermits.availablePermits(); }
    public int idleCount() {
        int total = 0;
        for (HostPool hp : hostPools.values()) total += hp.idleQueue.size();
        return total;
    }
    public int activeForHost(String key) {
        HostPool hp = hostPools.get(key);
        return hp != null ? hp.activeCount.get() : 0;
    }
    public int maxPerHost() { return MAX_PER_HOST; }

    public static String hostKey(String host, int port) {
        return host + ":" + port;
    }

    public void close() {
        shuttingDown = true;
        sweeper.interrupt();
        // Close all leased sockets (includes both active and idle
        // connections since idle connections remain in 'leased').
        for (Socket s : leased) closeQuietly(s);
        leased.clear();
        for (HostPool hp : hostPools.values()) {
            PooledEntry e;
            while ((e = hp.idleQueue.poll()) != null) {
                try { e.connection().socket().close(); } catch (Exception ignored) {}
            }
        }
        hostPools.clear();
        globalPermits.drainPermits();
        globalPermits.release(MAX_TOTAL);
    }

    // =====================================================================
    //  Internal
    // =====================================================================

    private static boolean isValid(H2TunnelConnection conn) {
        Socket s = conn.socket();
        if (s == null || s.isClosed()) return false;
        try {
            s.getOOBInline();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private void sweeperLoop() {
        while (!shuttingDown) {
            try { Thread.sleep(SWEEPER_INTERVAL_MS); }
            catch (InterruptedException e) { if (shuttingDown) return; }
            sweepIdle();
        }
    }

    private void sweepIdle() {
        long now = System.currentTimeMillis();
        int evicted = 0;
        for (var entry : hostPools.entrySet()) {
            HostPool hp = entry.getValue();
            PooledEntry peek = hp.idleQueue.peek();
            while (peek != null) {
                if (now - peek.timestamp() > IDLE_TTL_MS) {
                    PooledEntry removed = hp.idleQueue.poll();
                    if (removed != null) {
                        logger.Debug("[H2-POOL] Sweeper evicted idle connection for %s (age=%dms)", hp.key, now - removed.timestamp());
                        closeConnection(removed.connection(), hp);
                        evicted++;
                    }
                    peek = hp.idleQueue.peek();
                } else break;
            }
        }
        if (evicted > 0)
            logger.Debug("[H2-POOL] Sweeper evicted %d idle connections", evicted);
    }

    private static void closeQuietly(Socket s) {
        try { if (s != null) s.close(); } catch (Exception ignored) {}
    }

    // =====================================================================
    //  Inner types
    // =====================================================================

    private static final class HostPool {
        final String key;
        final Semaphore hostSemaphore = new Semaphore(MAX_PER_HOST, true);
        final AtomicInteger activeCount = new AtomicInteger(0);
        final ConcurrentLinkedQueue<PooledEntry> idleQueue = new ConcurrentLinkedQueue<>();
        volatile long lastCheckout = 0;

        HostPool(String key) { this.key = key; }

        H2TunnelConnection pollIdle() {
            PooledEntry e = idleQueue.poll();
            return e != null ? e.connection() : null;
        }
    }

    private record PooledEntry(H2TunnelConnection connection, long timestamp) {}

    /**
     * Result of {@link #acquireForHost} -- either a reused connection
     * or a signal to create a new one.
     */
    public static final class AcquireResult {
        private final H2TunnelConnection reused;
        private final boolean create;

        private AcquireResult(H2TunnelConnection reused, boolean create) {
            this.reused = reused;
            this.create = create;
        }

        static AcquireResult reused(H2TunnelConnection conn) {
            return new AcquireResult(conn, false);
        }

        static AcquireResult create() {
            return new AcquireResult(null, true);
        }

        public boolean isCreate() { return create; }
        public boolean isReused() { return !create; }
        public H2TunnelConnection connection() { return reused; }
    }
}
