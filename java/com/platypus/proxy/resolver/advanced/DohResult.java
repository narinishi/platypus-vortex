package com.platypus.proxy.resolver.advanced;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public record DohResult(
        List<InetAddress> addresses,
        long minTtlSeconds,
        long cnameTtlSeconds,
        boolean nxDomain,
        Throwable error,
        String cnameTarget,
        long soaMinimumTtl) {

    static final DohResult EMPTY = new DohResult(List.of(), Long.MAX_VALUE, Long.MAX_VALUE, false, null, null, -1);

    static DohResult nxDomain(long soaMinimumTtl) {
        return new DohResult(List.of(), 0L, Long.MAX_VALUE, true, null, null, soaMinimumTtl);
    }

    static DohResult error(Throwable t) {
        return new DohResult(List.of(), Long.MAX_VALUE, Long.MAX_VALUE, false, t, null, -1);
    }

    static DohResult cname(String target, long cnameTtl) {
        return new DohResult(List.of(), Long.MAX_VALUE, cnameTtl, false, null, target, -1);
    }

    static DohResult success(List<InetAddress> addrs, long addressTtl, long cnameTtl) {
        return new DohResult(addrs, addressTtl, cnameTtl, false, null, null, -1);
    }

    DohResult merge(DohResult other) {
        if (this.nxDomain && other.nxDomain) {
            long mergedSoa = mergeSoaMinimumTtl(this.soaMinimumTtl, other.soaMinimumTtl);
            return new DohResult(List.of(), 0L, Long.MAX_VALUE, true, null, null, mergedSoa);
        }
        if (this.nxDomain) return other;
        if (other.nxDomain) return this;

        boolean hasError = this.error != null || other.error != null;
        Throwable mergedError = this.error != null ? this.error : other.error;
        String mergedCname = this.cnameTarget != null ? this.cnameTarget : other.cnameTarget;
        long mergedCnameTtl = Math.min(this.cnameTtlSeconds, other.cnameTtlSeconds);

        List<InetAddress> mergedAddresses = new ArrayList<>();
        if (!this.addresses.isEmpty()) {
            mergedAddresses.addAll(this.addresses);
        }
        if (!other.addresses.isEmpty()) {
            for (InetAddress addr : other.addresses) {
                if (!mergedAddresses.contains(addr)) {
                    mergedAddresses.add(addr);
                }
            }
        }

        if (mergedAddresses.isEmpty()) {
            if (mergedCname != null) {
                return cname(mergedCname, mergedCnameTtl);
            }
            if (hasError) return error(mergedError);
            return EMPTY;
        }

        long mergedTtl = Math.min(this.minTtlSeconds, other.minTtlSeconds);
        return new DohResult(
                Collections.unmodifiableList(mergedAddresses), mergedTtl, mergedCnameTtl, false, null, mergedCname, -1);
    }

    private static long mergeSoaMinimumTtl(long a, long b) {
        if (a < 0 && b < 0) return -1;
        if (a < 0) return b;
        if (b < 0) return a;
        return Math.min(a, b);
    }
}
