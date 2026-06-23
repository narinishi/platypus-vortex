package com.platypus.proxy.provider;

import com.platypus.proxy.handler.Endpoint;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * A provider-specific handshake that may be required before the CONNECT
 * tunnel is established. For example, a proxy that demands a
 * challenge-response (407 / 200) can implement this interface.
 *
 * <p>The handshake is called once for each new tunnel. It receives the
 * first socket (already connected and TLS-wrapped, with a global
 * connection permit already held). If a second socket is necessary, it
 * can be obtained from {@code socketFactory}; the handshake is
 * responsible for releasing any socket it discards using
 * {@code releaseSocket}.
 */
public interface ProviderProxyIntercept {

    /**
     * Result of a successful handshake - the authenticated socket and
     * an {@link InputStream} that is positioned after any HTTP response
     * headers (i.e. ready for tunnelled data).
     */
    record InterceptResult(Socket socket, InputStream tunnelStream) {}

    Socket manualWrapTls(Socket socket, String serverName, Consumer<Socket> releaseSocket) throws IOException;

    /**
     * Performs the handshake.
     *
     * @param firstSocket   a freshly connected, possibly TLS-wrapped
     *                      socket to the proxy. It already holds a
     *                      global connection permit.
     * @param targetHost    the target host for the CONNECT request
     * @param targetPort    the target port
     * @param socketFactory a supplier that creates a new socket
     *                      (connected and, if applicable, TLS-wrapped)
     *                      and acquires a new global permit. May be
     *                      called zero or one times.
     * @param releaseSocket a consumer that releases the socket (closes
     *                      it and returns the global permit). Must be
     *                      called for every socket that is not returned
     *                      in the final {@link InterceptResult}.
     * @return the authenticated socket and its tunnel data stream
     * @throws IOException if the handshake fails; all sockets must have
     *                     been released before throwing
     */
    InterceptResult intercept(
            Socket firstSocket,
            String targetHost,
            int targetPort,
            Supplier<Socket> socketFactory,
            Consumer<Socket> releaseSocket,
            Endpoint endpoint)
            throws IOException;
}
