package com.platypus.proxy.resolver.advanced;

import java.net.InetAddress;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

final class CacheEntry {
    final List<InetAddress> addresses;
    final boolean isNegative;
    final long createdAtMs;
    final long ttlMs;
    final long staleExpiresAtMs;
    // AtomicLong ensures cross-thread
    // visibility of writes from touch().
    final AtomicLong lastAccessedAt;

    private CacheEntry(List<InetAddress> addresses, boolean isNegative, long ttlMs) {
        this.addresses = addresses;
        this.isNegative = isNegative;
        this.createdAtMs = System.currentTimeMillis();
        this.ttlMs = ttlMs;
        this.staleExpiresAtMs = createdAtMs + ttlMs + AdvancedResolver.STALE_TTL_MS;
        this.lastAccessedAt = new AtomicLong(System.nanoTime());
    }

    boolean isExpired() {
        return System.currentTimeMillis() > createdAtMs + ttlMs;
    }

    boolean isStaleExpired() {
        return System.currentTimeMillis() > staleExpiresAtMs;
    }

    boolean isApproachingExpiry() {
        long now = System.currentTimeMillis();
        long refreshAt = createdAtMs + (long) (ttlMs * AdvancedResolver.REFRESH_FRACTION);
        return now >= refreshAt;
    }

    void touch() {
        lastAccessedAt.set(System.nanoTime());
    }

    static CacheEntry positive(List<InetAddress> addresses, long ttlMs) {
        return new CacheEntry(addresses, false, ttlMs);
    }

    static CacheEntry negative() {
        return new CacheEntry(Collections.emptyList(), true, AdvancedResolver.NEGATIVE_TTL_MS);
    }

    static CacheEntry negative(long ttlMs) {
        return new CacheEntry(Collections.emptyList(), true, ttlMs);
    }
}
