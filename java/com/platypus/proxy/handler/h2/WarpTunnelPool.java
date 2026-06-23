package com.platypus.proxy.handler.h2;

import com.platypus.proxy.ProxyApplication;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Semaphore;
import java.security.SecureRandom;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public final class WarpTunnelPool {

    // Shared client-side SSLContext — no MITM cert generation, trusts default CAs.
    // Avoids ~50-100ms of cert generation + KeyManager setup per tunnel.
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

    private static final int MAX_IDLE_PER_HOST = 64;
    // Tunnels idle longer than this are evicted — the underlying H3 CONNECT
    // stream can be finished asynchronously by the H3 dispatcher, so keeping
    // tunnels idle for too long risks handing out a dead SSLSocket that will
    // hang on the first read.
    private static final long MAX_IDLE_MS = 2_000L;

    private static final class CacheEntry {
        final H2TunnelConnection tunnel;
        final long idleSinceNanos;
        CacheEntry(H2TunnelConnection tunnel) {
            this.tunnel = tunnel;
            this.idleSinceNanos = System.nanoTime();
        }
    }

    private final H2ProxyService proxyService;
    private final ConcurrentHashMap<String, ConcurrentLinkedQueue<CacheEntry>> cache = new ConcurrentHashMap<>();
    // creationSemaphore limits concurrent tunnel creation (H3 CONNECT +
    // optional TLS handshake). Set to match streamSemaphore(150) so the
    // QUIC stream limit is the only bottleneck.
    private final Semaphore creationSemaphore = new Semaphore(150, false);

    public WarpTunnelPool(H2ProxyService proxyService) {
        this.proxyService = proxyService;
    }

    public H2TunnelConnection acquire(String host, int port, String scheme) throws IOException {
        String key = H2UpstreamPool.hostKey(host, port);
        boolean secure = "https".equalsIgnoreCase(scheme) || (scheme == null && port == 443);

        // Fast path: cached tunnel for this host
        H2TunnelConnection cached = pollCache(key);
        if (cached != null) {
            cached.checkout();
            ProxyApplication.getLogger().Debug("[WARP-POOL] Reusing cached %s", key);
            return cached;
        }

        // Creation gate — limits how many tunnels are being built at once
        try {
            creationSemaphore.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted waiting for tunnel creation permit");
        }
        // Second cache lookup — another thread may have cached one while we blocked
        cached = pollCache(key);
        if (cached != null) {
            cached.checkout();
            creationSemaphore.release();
            ProxyApplication.getLogger().Debug("[WARP-POOL] Reusing cached %s (post-permit)", key);
            return cached;
        }
        ProxyApplication.getLogger().Debug("[WARP-POOL] Creating new connection for %s (secure=%b)", key, secure);

        try {
            return createConnection(host, port, scheme, secure, key);
        } finally {
            creationSemaphore.release();
        }
    }



    private H2TunnelConnection pollCache(String key) {
        ConcurrentLinkedQueue<CacheEntry> q = cache.get(key);
        if (q == null) return null;
        long deadlineNanos = System.nanoTime() - MAX_IDLE_MS * 1_000_000L;
        while (true) {
            CacheEntry entry = q.poll();
            if (entry == null) return null;
            H2TunnelConnection c = entry.tunnel;
            boolean stale = entry.idleSinceNanos < deadlineNanos;
            if (c.socket() == null || c.socket().isClosed() || !c.socket().isConnected()) {
                ProxyApplication.getLogger().Debug("[WARP-POOL] Discarding dead cached %s (socket closed)", key);
                try { c.forceClose(); } catch (Exception ignored) {}
                continue;
            }
            if (stale) {
                ProxyApplication.getLogger().Debug("[WARP-POOL] Discarding stale cached %s (idle > %dms)", key, MAX_IDLE_MS);
                try { c.forceClose(); } catch (Exception ignored) {}
                continue;
            }
            // Probe the socket: a finished QUIC stream reports isClosed=false
            // and isConnected=true, but read returns -1 immediately.
            if (!probeAlive(c)) {
                ProxyApplication.getLogger().Debug("[WARP-POOL] Discarding dead cached %s (probe EOF)", key);
                try { c.forceClose(); } catch (Exception ignored) {}
                continue;
            }
            return c;
        }
    }

    private static boolean probeAlive(H2TunnelConnection c) {
        Socket s = c.socket();
        try {
            s.setSoTimeout(1);
            java.io.InputStream probe = c.inputStream();
            int peek = probe.read();
            if (peek == -1) return false;
            ((java.io.PushbackInputStream) probe).unread(peek);
            return true;
        } catch (java.net.SocketTimeoutException e) {
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            try { s.setSoTimeout(5_000); } catch (Exception ignored) {}
        }
    }

    private H2TunnelConnection createConnection(String host, int port, String scheme, boolean secure, String key) throws IOException {
        String connectHost;
        try {
            connectHost = proxyService.resolveForDirectDns(host);
        } catch (java.net.UnknownHostException e) {
            throw new IOException(e);
        }
        ProxyApplication.getLogger().Debug("[WARP-POOL] createConnection to %s:%d", host, port);
        H2TunnelConnection rawTunnel = proxyService.connectTunnelForMitmResolved(host, connectHost, port);

        if (!secure) {
            return rawTunnel;
        }

        Socket socket = rawTunnel.socket();
        rawTunnel.transfer();

        SSLSocketFactory factory = CLIENT_SSL_CONTEXT.getSocketFactory();
        SSLSocket sslSocket;
        long tlsStart = System.nanoTime();
        try {
            sslSocket = (SSLSocket) factory.createSocket(socket, host, port, true);
            sslSocket.setSoTimeout(5_000);
            sslSocket.startHandshake();
        } catch (IOException e) {
            ProxyApplication.getLogger().Error("[WARP-POOL] TLS handshake to %s:%d failed: %s", host, port, e.getMessage());
            try { socket.close(); } catch (IOException ignored) {}
            throw e;
        }
        long tlsMs = (System.nanoTime() - tlsStart) / 1_000_000;
        String negotiatedAlpn = sslSocket.getApplicationProtocol();
        ProxyApplication.getLogger().Info("[WARP-POOL] TLS to %s:%d established, ALPN=%s (TLS=%dms)", host, port, negotiatedAlpn, tlsMs);

        InputStream tlsIn = sslSocket.getInputStream();
        OutputStream tlsOut = sslSocket.getOutputStream();
        InputStream pbTlsIn = new java.io.PushbackInputStream(tlsIn, 8192);

        Socket wrappedSocket = new Socket() {
            @Override public OutputStream getOutputStream() throws IOException { return tlsOut; }
            @Override public InputStream getInputStream() throws IOException { return pbTlsIn; }
            @Override public void close() throws IOException { sslSocket.close(); }
            @Override public boolean isClosed() { return sslSocket.isClosed(); }
            @Override public boolean isConnected() { return sslSocket.isConnected(); }
            @Override public java.net.InetAddress getInetAddress() { return sslSocket.getInetAddress(); }
            @Override public int getPort() { return sslSocket.getPort(); }
            @Override public void setSoTimeout(int timeout) throws java.net.SocketException { sslSocket.setSoTimeout(timeout); }
            @Override public int getSoTimeout() throws java.net.SocketException { return sslSocket.getSoTimeout(); }
            @Override public boolean getOOBInline() throws java.net.SocketException { return sslSocket.getOOBInline(); }
            @Override public void setOOBInline(boolean on) throws java.net.SocketException { sslSocket.setOOBInline(on); }
            @Override public void setKeepAlive(boolean on) throws java.net.SocketException { sslSocket.setKeepAlive(on); }
            @Override public boolean getKeepAlive() throws java.net.SocketException { return sslSocket.getKeepAlive(); }
            @Override public void setTcpNoDelay(boolean on) throws java.net.SocketException { sslSocket.setTcpNoDelay(on); }
            @Override public boolean getTcpNoDelay() throws java.net.SocketException { return sslSocket.getTcpNoDelay(); }
        };

        return new H2TunnelConnection(wrappedSocket, pbTlsIn, new WarpPoolAdapter(key));
    }

    void returnToCache(String key, H2TunnelConnection conn) {
        ConcurrentLinkedQueue<CacheEntry> queue = cache.computeIfAbsent(key, k -> new ConcurrentLinkedQueue<>());
        if (queue.size() < MAX_IDLE_PER_HOST) {
            queue.offer(new CacheEntry(conn));
            ProxyApplication.getLogger().Debug("[WARP-POOL] Returning %s to cache (idle=%d)", key, queue.size());
        } else {
            ProxyApplication.getLogger().Debug("[WARP-POOL] Cache full for %s, discarding", key);
            try { conn.forceClose(); } catch (Exception ignored) {}
        }
    }

    public void evict(String host, int port) {
        String key = H2UpstreamPool.hostKey(host, port);
        ConcurrentLinkedQueue<CacheEntry> queue = cache.remove(key);
        if (queue != null) {
            CacheEntry entry;
            while ((entry = queue.poll()) != null) {
                try { entry.tunnel.forceClose(); } catch (Exception ignored) {}
            }
            ProxyApplication.getLogger().Debug("[WARP-POOL] Evicted all connections for %s", key);
        }
    }

    public void clear() {
        for (var entry : cache.entrySet()) {
            CacheEntry ce;
            while ((ce = entry.getValue().poll()) != null) {
                try { ce.tunnel.forceClose(); } catch (Exception ignored) {}
            }
        }
        cache.clear();
    }

    private final class WarpPoolAdapter extends H2UpstreamPool {
        private final String key;

        WarpPoolAdapter(String key) {
            super(null);
            this.key = key;
        }

        @Override
        public void returnConnection(String k, H2TunnelConnection conn, boolean keepOpen) {
            if (keepOpen) {
                returnToCache(k, conn);
            } else {
                try { conn.forceClose(); } catch (Exception ignored) {}
            }
        }

        @Override
        public void releaseOwnedSocket(Socket s) {
            try { s.close(); } catch (IOException ignored) {}
        }
    }
}
