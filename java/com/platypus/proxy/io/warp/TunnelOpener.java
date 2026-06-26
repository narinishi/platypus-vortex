package com.platypus.proxy.io.warp;

import java.io.IOException;

@FunctionalInterface
public interface TunnelOpener {
    TunnelConnection open(String host, int port, byte[] initialData) throws IOException;
    default TunnelConnection open(String host, int port) throws IOException {
        return open(host, port, null);
    }
}
