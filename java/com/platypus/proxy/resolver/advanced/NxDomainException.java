package com.platypus.proxy.resolver.advanced;

import java.net.UnknownHostException;

/**
 * Thrown when the DNS response RCODE is NXDOMAIN (3).
 * Carries the SOA minimum TTL extracted from the
 * authority section (if present) so that negative
 * cache entries use the authoritative TTL per
 * RFC 2308 §5.
 */
public class NxDomainException extends UnknownHostException {
    private final long soaMinimumTtl;

    public NxDomainException(String host) {
        this(host, -1);
    }

    public NxDomainException(String host, long soaMinimumTtl) {
        super(host);
        this.soaMinimumTtl = soaMinimumTtl;
    }

    public long getSoaMinimumTtl() {
        return soaMinimumTtl;
    }
}
