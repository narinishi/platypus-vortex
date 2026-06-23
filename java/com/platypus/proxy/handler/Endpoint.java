package com.platypus.proxy.handler;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;

public record Endpoint(String host, int port, String tlsName) {

    public Endpoint {
        Objects.requireNonNull(host, "host");
        if (port < 0 || port > 65535) {
            throw new IllegalArgumentException("port out of range: " + port);
        }
    }

    public boolean isDirect() {
        return "127.0.0.1".equals(host) && port == 0 && (tlsName == null || tlsName.isEmpty());
    }

    public URI getUri() {
        try {
            String scheme = (tlsName == null || tlsName.isEmpty()) ? "http" : "https";
            return new URI(scheme, null, host, port, null, null, null);
        } catch (URISyntaxException e) {
            // Should not be reachable: host/port are validated in the
            // compact constructor and the scheme is one of two literals.
            throw new IllegalStateException("Invalid endpoint URI: " + this, e);
        }
    }

    public String getNetAddr() {
        return host + ":" + port;
    }
}
