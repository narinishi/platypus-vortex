package com.platypus.proxy.io;

import java.io.IOException;

/**
 * Functional interface that opens a TCP connection to an address.
 */
@FunctionalInterface
public interface TcpConnector {
    TunnelConnection connect(String network, String address) throws IOException;
}
