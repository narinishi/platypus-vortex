package com.platypus.proxy.io;

import java.io.IOException;

@FunctionalInterface
public interface TunnelOpener {
    TunnelConnection open(String host, int port) throws IOException;
}
