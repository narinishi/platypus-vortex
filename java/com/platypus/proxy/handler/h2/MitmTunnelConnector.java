package com.platypus.proxy.handler.h2;

import com.platypus.proxy.ProxyApplication;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.security.SecureRandom;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public final class MitmTunnelConnector {

    // Shared client-side SSLContext for upstream connections. Uses default CA trust
    // (no MITM cert generation) to avoid the ~50-100ms overhead per tunnel.
    private static final SSLContext CLIENT_SSL_CONTEXT = createClientSslContext();

    private static SSLContext createClientSslContext() {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, null, new SecureRandom());
            return ctx;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create client SSLContext", e);
        }
    }

    // RFC 9113 §9.1.1 connection reuse -- validate idle connections with read probe
    private static final int MAX_PROBE_ATTEMPTS = 2;

    private MitmTunnelConnector() {}

    public static H2TunnelConnection connect(H2ProxyService proxyService, String host, int port, String scheme)
            throws IOException {

        long startNs = System.nanoTime();
        String key = H2UpstreamPool.hostKey(host, port);

        if (proxyService.hasWarpTunnelOpener() && proxyService.warpPool() != null) {
            return proxyService.warpPool().acquire(host, port, scheme);
        }

        H2TunnelConnection cached = proxyService.pool().tryAcquireIdle(key);
        int probesAttempted = 0;
        CompletableFuture<H2TunnelConnection> pendingFresh = null;
        boolean kickedOffFresh = false;

        if (cached != null) {
            kickedOffFresh = true;
            pendingFresh = CompletableFuture.supplyAsync(() -> {
                try {
                    return createFreshConnection(proxyService, host, port, scheme);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        }

        while (cached != null && probesAttempted < MAX_PROBE_ATTEMPTS) {
            Socket s = cached.socket();
            if (s.isClosed() || !s.isConnected()) {
                ProxyApplication.getLogger().Debug("[H2-POOL] Pooled connection for %s is closed, discarding", key);
                cached.close();
                cached = proxyService.pool().tryAcquireIdle(key);
                continue;
            }
            probesAttempted++;
            try {
                s.setSoTimeout(1);
                InputStream probe = cached.inputStream();
                int peek = probe.read();
                if (peek == -1) {
                    ProxyApplication.getLogger().Debug("[H2-POOL] Pooled connection for %s EOF on probe, discarding", key);
                    cached.close();
                    cached = proxyService.pool().tryAcquireIdle(key);
                    continue;
                }
                java.io.PushbackInputStream pb = (java.io.PushbackInputStream) probe;
                pb.unread(peek);
                s.setSoTimeout(30_000);
                if (pendingFresh != null) pendingFresh.cancel(true);
                long probeMs = (System.nanoTime() - startNs) / 1_000_000;
                ProxyApplication.getLogger().Debug("[H2-POOL] Reusing pooled connection for %s (probe took %dms)", key, probeMs);
                return cached;
            } catch (java.net.SocketTimeoutException ok) {
                s.setSoTimeout(30_000);
                if (pendingFresh != null) pendingFresh.cancel(true);
                long probeMs = (System.nanoTime() - startNs) / 1_000_000;
                ProxyApplication.getLogger().Debug("[H2-POOL] Reusing pooled connection for %s (probe took %dms, timeout=alive)", key, probeMs);
                return cached;
            } catch (IOException e) {
                ProxyApplication.getLogger().Debug("[H2-POOL] Pooled connection for %s probe failed: %s, discarding", key, e.getMessage());
                cached.close();
                cached = proxyService.pool().tryAcquireIdle(key);
                continue;
            }
        }

        if (probesAttempted >= MAX_PROBE_ATTEMPTS) {
            ProxyApplication.getLogger().Debug("[H2-POOL] Probe limit (%d) reached for %s, switching to fresh connection", MAX_PROBE_ATTEMPTS, key);
        }

        long freshStartNs = System.nanoTime();
        H2TunnelConnection result;
        if (pendingFresh != null) {
            try {
                result = pendingFresh.get();
            } catch (ExecutionException e) {
                throw new IOException(e.getCause());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted waiting for fresh connection");
            }
        } else {
            result = createFreshConnection(proxyService, host, port, scheme);
        }
        long freshMs = (System.nanoTime() - freshStartNs) / 1_000_000;
        long totalMs = (System.nanoTime() - startNs) / 1_000_000;
        ProxyApplication.getLogger().Debug("[MITM-CONNECT] Fresh connection to %s took %dms (total connect phase %dms)", key, freshMs, totalMs);
        return result;
    }

    // RFC 7301 ALPN -- negotiate "http/1.1"; RFC 9113 §9.2 TLS features for upstream
    private static H2TunnelConnection createFreshConnection(H2ProxyService proxyService, String host, int port, String scheme)
            throws IOException {

        String connectHost;
        try {
            connectHost = proxyService.resolveForDirectDns(host);
        } catch (UnknownHostException e) {
            throw new IOException(e);
        }
        ProxyApplication.getLogger().Debug("[MITM-CONNECT] createFreshConnection to %s:%d (warp=%b)", host, port, proxyService.hasWarpTunnelOpener());
        H2TunnelConnection rawTunnel = proxyService.connectTunnelForMitmResolved(host, connectHost, port);
        ProxyApplication.getLogger().Debug("[MITM-CONNECT] rawTunnel obtained for %s:%d (socket=%s)", host, port, rawTunnel.socket() != null);

        boolean secure = "https".equalsIgnoreCase(scheme) || (scheme == null && port == 443);
        if (!secure) {
            // rawTunnel already has pool=null when WARP backend is used
            // (set by H2ProxyService.wrapTunnelAsH2). Non-WARP case keeps
            // the pool reference inside connectTunnelForMitmResolved.
            return rawTunnel;
        }

        Socket socket = rawTunnel.socket();
        Socket rawPoolSocket = rawTunnel.poolSocket();
        rawTunnel.transfer();
        ProxyApplication.getLogger().Debug("[MITM-CONNECT] wrapping TLS on raw tunnel for %s:%d (socket class=%s)", host, port, socket.getClass().getName());

        SSLSocketFactory factory = CLIENT_SSL_CONTEXT.getSocketFactory();
        SSLSocket sslSocket;
        long tlsStart = System.nanoTime();
        try {
            ProxyApplication.getLogger().Debug("[MITM-CONNECT] creating SSLSocket for %s:%d...", host, port);
            sslSocket = (SSLSocket) factory.createSocket(socket, host, port, true);
            sslSocket.setSoTimeout(5_000);
            ProxyApplication.getLogger().Debug("[MITM-CONNECT] starting TLS handshake to %s:%d...", host, port);
            sslSocket.startHandshake();
            ProxyApplication.getLogger().Debug("[MITM-CONNECT] TLS handshake completed to %s:%d", host, port);
        } catch (IOException e) {
            ProxyApplication.getLogger().Error("[MITM-CONNECT] TLS handshake to %s:%d failed: %s",
                    host, port, e.getMessage());
            try { socket.close(); } catch (IOException ignored) {}
            throw e;
        }
        long tlsMs = (System.nanoTime() - tlsStart) / 1_000_000;

        String negotiatedAlpn = sslSocket.getApplicationProtocol();
        ProxyApplication.getLogger().Info("[MITM-CONNECT] Upstream TLS to %s:%d established, ALPN=%s (TLS=%dms)",
                host, port, negotiatedAlpn, tlsMs);

        InputStream tlsIn = sslSocket.getInputStream();
        OutputStream tlsOut = sslSocket.getOutputStream();
        InputStream pbTlsIn = new java.io.PushbackInputStream(tlsIn, 8192);

        Socket wrappedSocket = new Socket() {
            @Override
            public OutputStream getOutputStream() throws IOException {
                return tlsOut;
            }
            @Override
            public InputStream getInputStream() throws IOException {
                return pbTlsIn;
            }
            @Override
            public void close() throws IOException {
                sslSocket.close();
            }
            @Override
            public boolean isClosed() { return sslSocket.isClosed(); }
            @Override
            public boolean isConnected() { return sslSocket.isConnected(); }
            @Override
            public java.net.InetAddress getInetAddress() { return sslSocket.getInetAddress(); }
            @Override
            public int getPort() { return sslSocket.getPort(); }
            @Override
            public java.nio.channels.SocketChannel getChannel() { return socket.getChannel(); }
            @Override
            public void setSoTimeout(int timeout) throws java.net.SocketException {
                sslSocket.setSoTimeout(timeout);
            }
            @Override
            public int getSoTimeout() throws java.net.SocketException {
                return sslSocket.getSoTimeout();
            }
            @Override public boolean getOOBInline() throws java.net.SocketException { return sslSocket.getOOBInline(); }
            @Override public void setOOBInline(boolean on) throws java.net.SocketException { sslSocket.setOOBInline(on); }
            @Override public void setKeepAlive(boolean on) throws java.net.SocketException { sslSocket.setKeepAlive(on); }
            @Override public boolean getKeepAlive() throws java.net.SocketException { return sslSocket.getKeepAlive(); }
            @Override public void setTcpNoDelay(boolean on) throws java.net.SocketException { sslSocket.setTcpNoDelay(on); }
            @Override public boolean getTcpNoDelay() throws java.net.SocketException { return sslSocket.getTcpNoDelay(); }
        };

        return new H2TunnelConnection(
                wrappedSocket,
                pbTlsIn,
                proxyService.pool(),
                rawPoolSocket);
    }

    static void evictFromPool(H2ProxyService proxyService, String host, int port) {
        if (proxyService.hasWarpTunnelOpener() && proxyService.warpPool() != null) {
            proxyService.warpPool().evict(host, port);
        } else {
            String key = H2UpstreamPool.hostKey(host, port);
            H2TunnelConnection stale = proxyService.pool().tryAcquireIdle(key);
            if (stale != null) stale.close();
        }
    }
}
