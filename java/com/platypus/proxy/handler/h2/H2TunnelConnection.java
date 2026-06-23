package com.platypus.proxy.handler.h2;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * H2-specific upstream connection wrapper with intelligent pool reuse.
 *
 * <p>RFC 9113 §9.1 connection management -- supports connection reuse
 * via the upstream pool.  The {@code hostKey} field (set at creation or
 * checkout) allows automatic return to the correct per-host idle cache.
 *
 * <p>Two disposal paths:
 * <ul>
 *   <li>{@link #reuse()} -- return to {@link H2UpstreamPool}'s idle cache.</li>
 *   <li>{@link #close()} -- forceful close: closes socket, releases permits.</li>
 * </ul>
 */
public final class H2TunnelConnection implements AutoCloseable {

    private final Socket socket;
    private final InputStream inputStream;
    private final H2UpstreamPool pool;
    private final Socket poolSocket;
    private String hostKey;
    private volatile boolean released = false;

    public H2TunnelConnection(Socket socket, InputStream inputStream, H2UpstreamPool pool) {
        this(socket, inputStream, pool, socket);
    }

    public H2TunnelConnection(Socket socket, InputStream inputStream, H2UpstreamPool pool, Socket poolSocket) {
        this.socket = socket;
        this.inputStream = inputStream;
        this.pool = pool;
        this.poolSocket = poolSocket;
    }

    public Socket socket() { return socket; }
    public InputStream inputStream() { return inputStream; }
    public OutputStream outputStream() throws IOException { return socket.getOutputStream(); }
    Socket poolSocket() { return poolSocket; }
    public String hostKey() { return hostKey; }
    public void hostKey(String hostKey) { this.hostKey = hostKey; }

    void checkout() { released = false; }
    void transfer() { released = true; }

    public void reuse() {
        if (released) return;
        released = true;
        if (pool != null && hostKey != null) {
            pool.returnConnection(hostKey, this, true);
        } else {
            closeQuietly();
        }
    }

    public void reuse(String key) {
        this.hostKey = key;
        reuse();
    }

    @Override
    public void close() {
        if (released) return;
        released = true;
        forceClose();
    }

    public void close(String key) {
        this.hostKey = key;
        if (released) return;
        released = true;
        if (pool != null) {
            pool.returnConnection(hostKey, this, false);
        } else {
            closeQuietly();
        }
    }

    void forceClose() {
        try { if (socket != null) socket.close(); } catch (IOException ignored) {}
        if (pool != null) pool.releaseOwnedSocket(poolSocket);
    }

    private void closeQuietly() {
        try { if (socket != null) socket.close(); } catch (IOException ignored) {}
    }
}
