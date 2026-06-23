// ConnectionTunneller.java
package com.platypus.proxy.handler;

import com.platypus.proxy.io.TunnelConnection;
import java.io.IOException;

/**
 * Delegates tunnel creation to {@link ProxyHandler}.
 *
 * @deprecated This class is retained only as a thin delegation layer.
 *             Callers should use {@link ProxyHandler#connectTunnel} directly.
 */
@Deprecated
public final class ConnectionTunneller {

    private ConnectionTunneller() {}

    public static TunnelConnection connectTunnel(ProxyHandler proxyHandler, String host, int port) throws IOException {
        return proxyHandler.connectTunnel(host, port);
    }
}
