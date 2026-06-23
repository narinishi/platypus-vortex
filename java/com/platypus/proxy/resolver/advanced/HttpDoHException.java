package com.platypus.proxy.resolver.advanced;

/**
 * Thrown when the upstream DoH server returns a non-2xx
 * HTTP status code. Carries the status code so callers
 * can distinguish server errors (5xx, worth failover)
 * from client errors (4xx, likely a malformed query).
 */
public class HttpDoHException extends RuntimeException {
    private final int statusCode;

    public HttpDoHException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
