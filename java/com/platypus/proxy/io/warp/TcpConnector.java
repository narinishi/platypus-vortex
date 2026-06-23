package com.platypus.proxy.io.warp;

import java.io.IOException;

@FunctionalInterface
public interface TcpConnector {
    TunnelConnection connect(String network, String address) throws IOException;
}
