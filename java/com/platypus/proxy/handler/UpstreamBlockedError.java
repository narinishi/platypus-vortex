package com.platypus.proxy.handler;

import java.io.IOException;

/**
 * Thrown by {@link BaslineProxyDialer} when the upstream proxy returns a 403
 * indicating the target host is blocked. {@link RetryDialer} catches
 * this and retries with a resolved IP address.
 */
public class UpstreamBlockedError extends IOException {
    public UpstreamBlockedError(String message) {
        super(message);
    }
}
