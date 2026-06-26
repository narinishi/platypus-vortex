package com.platypus.proxy.handler.warp;

import com.platypus.proxy.ProxyApplication;
import com.platypus.proxy.io.warp.TunnelConnection;
import com.platypus.proxy.io.warp.TunnelOpener;
import com.platypus.proxy.logging.CondLogger;
import gnu.crypto.der.DER;
import gnu.crypto.der.DERValue;
import gnu.crypto.der.DERWriter;
import gnu.crypto.der.OID;
import gnu.crypto.pki.X500Name;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.StandardConstants;

public final class WarpServe implements Closeable {

    private static final CondLogger log = ProxyApplication.getLogger();

    private static final int RELAY_BUF_SIZE = 65536;
    private static final int MAX_POOL_PER_HOST = 4;
    private static final long POOL_IDLE_TIMEOUT_MS = 500;
    private static final long MAX_TUNNEL_AGE_MS = 15_000;
    private static final long HIGH_THROUGHPUT_BYTES = 1_000_000;
    private static final long RELAY_IDLE_TIMEOUT_MS = 5_000;
    private static final long DOH_IDLE_TIMEOUT_MS = 8_000;
    private static final long HANDSHAKE_TIMEOUT_MS = 15_000;

    private static final class PooledTunnel {
        final TunnelConnection tunnel;
        final long idleSince;
        final long createdAt;
        PooledTunnel(TunnelConnection tunnel, long idleSince) {
            this.tunnel = tunnel;
            this.idleSince = idleSince;
            this.createdAt = System.currentTimeMillis();
        }
        boolean isTooOld() {
            return System.currentTimeMillis() - createdAt > MAX_TUNNEL_AGE_MS;
        }
    }

    // Per-stream relay state shared between c2o, o2c, and the watchdog.
    // All cleanup goes through the `closed` flag to prevent double-close.
    private static final class StreamState {
        final int connId;
        final int streamId;
        final H2ServerSession session;
        final H2ServerSession.ServerStream stream;
        final Thread c2o;
        final Thread o2c;
        final TunnelConnection tunnel;
        final OutputStream browserOut;
        final AtomicLong lastDataTime;
        final AtomicInteger c2oChunks;
        final String host;
        volatile boolean c2oDied;
        volatile boolean relayTimedOut;
        volatile boolean closed;
        StreamState(int connId, int streamId, H2ServerSession session, H2ServerSession.ServerStream stream,
                    Thread c2o, Thread o2c, TunnelConnection tunnel, OutputStream browserOut,
                    AtomicLong lastDataTime, AtomicInteger c2oChunks, String host) {
            this.connId = connId;
            this.streamId = streamId;
            this.session = session;
            this.stream = stream;
            this.c2o = c2o;
            this.o2c = o2c;
            this.tunnel = tunnel;
            this.browserOut = browserOut;
            this.lastDataTime = lastDataTime;
            this.c2oChunks = c2oChunks;
            this.host = host;
        }
    }

    private final SSLServerSocket serverSocket;
    private final TunnelOpener warpOpener;
    private final Runnable warpCloser;
    private final Executor executor;
    private final Thread acceptThread;
    private final Thread watchdogThread;
    private final ConcurrentHashMap<String, ConcurrentLinkedQueue<PooledTunnel>> tunnelPool = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Integer, StreamState> activeRelays = new ConcurrentHashMap<>();
    private final AtomicInteger adguardStreamCount = new AtomicInteger(0);
    private final AtomicInteger connCounter = new AtomicInteger(1);

    public WarpServe(String bindAddress, TunnelOpener warpOpener, Executor executor, Runnable warpCloser) throws Exception {
        this.warpOpener = warpOpener;
        this.warpCloser = warpCloser;
        this.executor = executor;

        String[] parts = bindAddress.split(":");
        String host = parts[0];
        int port = Integer.parseInt(parts[1]);

        SSLContext sslCtx = createServerSslContext();
        SSLServerSocketFactory ssf = sslCtx.getServerSocketFactory();
        // Backlog 50 allows up to 50 pending TCP connections.  backlog=0
        // is documented as "use default" by Java but some JDK implementations
        // interpret it literally, causing connection refused when Chrome opens
        // many parallel H2 connections to the proxy during the warmup phase.
        SSLServerSocket sslSock = (SSLServerSocket) ssf.createServerSocket(port, 50, java.net.InetAddress.getByName(host));
        sslSock.setReuseAddress(true);
        sslSock.setNeedClientAuth(false);
        sslSock.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
        sslSock.setEnabledCipherSuites(sslSock.getSupportedCipherSuites());
        SSLParameters params = sslSock.getSSLParameters();
        params.setApplicationProtocols(new String[]{"h2", "http/1.1"});
        // SNI matcher is set per-connection in acceptLoop, not on the server
        // socket, because we need per-connection state to log "no SNI" cases.
        sslSock.setSSLParameters(params);
        this.serverSocket = sslSock;

        if (log != null) log.Info("Starting WARP HTTPS proxy on %s:%d", host, port);

        this.acceptThread = new Thread(this::acceptLoop, "warp-accept");
        this.acceptThread.setDaemon(true);
        this.acceptThread.start();

        this.watchdogThread = Thread.startVirtualThread(this::watchdogLoop);
        this.watchdogThread.setName("warp-relay-watchdog");

        if (log != null) log.Info("WARP HTTPS proxy running on %s:%d", host, port);
    }

    private SSLContext createServerSslContext() throws Exception {
        // Generate self-signed cert
        SecureRandom rng = new SecureRandom();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4), rng);
        KeyPair kp = kpg.generateKeyPair();

        X509Certificate cert = generateSelfSignedCert(kp, "WarpProxy", rng);

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("proxy", kp.getPrivate(), "changeit".toCharArray(),
                new java.security.cert.Certificate[]{cert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, rng);
        return ctx;
    }

    private void acceptLoop() {
        while (!serverSocket.isClosed()) {
            try {
                SSLSocket client = (SSLSocket) serverSocket.accept();
                int cid = connCounter.getAndIncrement();
                if (log != null) log.Debug("[WARP] TCP conn#%d from %s", cid, client.getRemoteSocketAddress());
                // Per-connection SNI detection: set a matcher on the accepted
                // socket that captures whether the browser sent TLS SNI.
                // Chrome may omit SNI when connecting to a proxy by IP address.
                final AtomicBoolean sniSeen = new AtomicBoolean(false);
                final CondLogger sniLog = log;
                SSLParameters clientParams = client.getSSLParameters();
                clientParams.setSNIMatchers(Collections.singletonList(new SNIMatcher(StandardConstants.SNI_HOST_NAME) {
                    @Override public boolean matches(SNIServerName serverName) {
                        sniSeen.set(true);
                        if (serverName instanceof SNIHostName && sniLog != null)
                            sniLog.Debug("[WARP] conn#%d TLS SNI=%s", cid, ((SNIHostName) serverName).getAsciiName());
                        return true;
                    }
                }));
                client.setSSLParameters(clientParams);
                executor.execute(() -> handleTlsConnection(client, cid, sniSeen));
            } catch (IOException e) {
                if (!serverSocket.isClosed() && log != null)
                    log.Debug("[WARP] Accept error: %s", e.getMessage());
            }
        }
    }

    private void handleTlsConnection(SSLSocket sslSocket, int connId, AtomicBoolean sniSeen) {
        try {
            long t0 = System.nanoTime();
            sslSocket.startHandshake();
            long t1 = System.nanoTime();
            String alpn = sslSocket.getApplicationProtocol();
            if (log != null) {
                if (sniSeen.get()) {
                    log.Debug("[WARP] conn#%d TLS handshake done in %.1fms, ALPN=%s", connId, (t1 - t0) / 1e6, alpn);
                } else {
                    // Chrome connects to the proxy IP without SNI by default.
                    // This is expected and normal for an HTTPS proxy.
                    log.Debug("[WARP] conn#%d TLS handshake done in %.1fms, ALPN=%s, NO SNI", connId, (t1 - t0) / 1e6, alpn);
                }
            }

            InputStream in = sslSocket.getInputStream();
            OutputStream out = sslSocket.getOutputStream();

            if ("h2".equals(alpn)) {
                if (log != null) log.Debug("[WARP] conn#%d Chrome negotiated HTTP/2 (ALPN=h2) → using H2 CONNECT", connId);
                handleH2(in, out, connId);
            } else {
                String proto = alpn != null && !alpn.isEmpty() ? alpn : "http/1.1";
                if (log != null) log.Debug("[WARP] conn#%d Chrome using %s → HTTP/1.1 CONNECT", connId, proto);
                handleH1(in, out);
            }
        } catch (IOException e) {
            if (log != null) log.Debug("[WARP] conn#%d TLS error: %s", connId, e.getMessage());
        } finally {
            if (log != null) log.Debug("[WARP] conn#%d closed", connId);
            closeQuietly(sslSocket);
        }
    }

    private static void closeQuietly(java.net.Socket s) {
        try { s.close(); } catch (IOException ignored) {}
    }

    private void handleH2(InputStream in, OutputStream out, int connId) throws IOException {
        H2ServerSession session = new H2ServerSession(in, out,
            (session2, streamId, stream, authority, headers) ->
                handleH2Connect(connId, session2, streamId, stream, authority),
            (session2, streamId, stream, method, authority, path, headers) ->
                handleH2Request(session2, streamId, stream, method, authority, path, headers),
            log);

        // H2 PING keep-alive: prevents Chrome from closing the H2 connection
        // during idle periods (e.g. user reading a page).  PING is a connection-
        // level frame with no stream association, so it does not interfere with
        // any active CONNECT streams.
        AtomicBoolean pingRunning = new AtomicBoolean(true);
        Thread pingThread = Thread.startVirtualThread(() -> {
            while (pingRunning.get()) {
                try { Thread.sleep(30_000); } catch (InterruptedException e) { return; }
                if (!pingRunning.get()) return;
                try {
                    session.sendPing();
                } catch (IOException e) {
                    return;
                }
            }
        });
        pingThread.setName("h2-ping-keepalive");

        try {
            session.awaitTermination();
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        } finally {
            pingRunning.set(false);
            pingThread.interrupt();
        }
    }

    private static boolean isDohServer(String host) {
        String h = host.toLowerCase();
        return h.contains("dns") || h.contains("doh")
            || h.contains("openbld")
            || h.contains("cira");
    }

    private void watchdogLoop() {
        // Centralized timeout monitor for all active streams.  Runs every 100ms
        // and closes streams that have been idle beyond their graduated timeout.
        // This replaces the per-stream blocking relay loop so that handleH2Connect
        // returns immediately, freeing Chrome to dispatch testing-phase streams
        // on connections that still have idle warmup streams.
        long lastStallCheck = 0;
        while (!serverSocket.isClosed()) {
            try { Thread.sleep(100); } catch (InterruptedException e) { return; }
            long now = System.currentTimeMillis();
            boolean anyC2oAlive = false;
            boolean allO2cStalled = true;
            long stallSince = Long.MAX_VALUE;
            for (StreamState ss : activeRelays.values()) {
                if (ss.closed) continue;
                // Check c2o death (Chrome sent RST_STREAM on this stream)
                if (!ss.c2o.isAlive()) {
                    ss.c2oDied = true;
                    closeStream(ss, "c2o died");
                    continue;
                }
                anyC2oAlive = true;
                // Check o2c normal completion (tunnel QUIC stream ended)
                if (!ss.o2c.isAlive()) {
                    closeStream(ss, "o2c done");
                    continue;
                }
                long idle = now - ss.lastDataTime.get();
                if (idle < 5_000) allO2cStalled = false;
                else stallSince = Math.min(stallSince, ss.lastDataTime.get());
                // Check idle timeout
                long timeout;
                if (ss.c2oChunks.get() >= 2) {
                    timeout = isDohServer(ss.host) ? DOH_IDLE_TIMEOUT_MS : RELAY_IDLE_TIMEOUT_MS;
                } else {
                    timeout = HANDSHAKE_TIMEOUT_MS;
                }
                if (idle > timeout) {
                    ss.relayTimedOut = true;
                    if (log != null) log.Debug("[WARP] conn#%d H2 CONNECT stream=%d app idle %dms > %dms, watchdog sending END_STREAM",
                            ss.connId, ss.streamId, idle, timeout);
                    closeStream(ss, "idle timeout");
                }
            }
            // Stall detection: all active o2c threads idle >5s but c2o still alive
            if (anyC2oAlive && allO2cStalled && stallSince != Long.MAX_VALUE) {
                long stalledFor = now - stallSince;
                if (stalledFor > 5_000 && lastStallCheck == 0) {
                    lastStallCheck = now;
                } else if (stalledFor > 7_000 && lastStallCheck > 0) {
                    if (log != null) log.Error("[WARP] All relays stalled for %dms — closing WARP connection to force reconnect", stalledFor);
                    warpCloser.run();
                    lastStallCheck = 0;
                }
            } else {
                lastStallCheck = 0;
            }
        }
    }

    private void closeStream(StreamState ss, String reason) {
        if (!ss.closed) {
            ss.closed = true;
            activeRelays.remove(ss.streamId);
            try { ss.browserOut.close(); } catch (IOException ignored) {}
            try { ss.tunnel.abortRead(); } catch (Exception ignored) {}
            try { ss.tunnel.close(); } catch (Exception ignored) {}
            if (log != null) log.Debug("[WARP] conn#%d H2 CONNECT stream=%d relay ended (%s)", ss.connId, ss.streamId, reason);
            checkAdguardExit(ss);
        }
    }

    private void checkAdguardExit(StreamState ss) {
        if (!"dns.adguard-dns.com".equals(ss.host)) return;
        adguardStreamCount.incrementAndGet();
        if (adguardStreamCount.get() > 12 && (ss.c2oDied || ss.relayTimedOut)) {
            if (log != null) log.Error("AdGuard failed (c2oDied=%s relayTimedOut=%s count=%d) — exiting for rapid iteration",
                    ss.c2oDied, ss.relayTimedOut, adguardStreamCount.get());
            System.exit(1);
        }
    }

    private void handleH2Connect(int connId, H2ServerSession session, int streamId, H2ServerSession.ServerStream stream, String authority) {
        if (log != null) log.Debug("[WARP] conn#%d CONNECT stream=%d to %s", connId, streamId, authority);

        int colon = authority.lastIndexOf(':');
        if (colon < 0) {
            try { session.sendRstStream(streamId, 0x8); } catch (IOException ignored) {}
            return;
        }
        String host = authority.substring(0, colon);
        int port = Integer.parseInt(authority.substring(colon + 1));

        // Send :status=200 immediately so Chrome doesn't stall its H2 stream
        // scheduler while we open the WARP tunnel.
        Map<String, String> resp = new LinkedHashMap<>();
        resp.put(":status", "200");
        try {
            session.sendHeaders(streamId, resp, H2ServerSession.FLAG_END_HEADERS);
        } catch (IOException e) {
            if (log != null) log.Debug("[WARP] H2 CONNECT stream=%d send error: %s", streamId, e.getMessage());
            return;
        }

        final ConcurrentLinkedQueue<byte[]> pendingData = new ConcurrentLinkedQueue<>();
        final AtomicReference<OutputStream> originOutRef = new AtomicReference<>();
        final CondLogger logRef = log;
        final AtomicInteger c2oChunks = new AtomicInteger(0);
        final AtomicLong lastDataTime = new AtomicLong(System.currentTimeMillis());
        OutputStream browserOut = stream.outputStream();

        // c2o — reads browser data, writes to the WARP tunnel.
        Thread c2o = Thread.startVirtualThread(() -> {
            if (logRef != null) logRef.Debug("[WARP] H2 CONNECT stream=%d relay c2o started", streamId);
            try {
                while (true) {
                    byte[] chunk;
                    try { chunk = stream.readChunk(); } catch (IOException e) { break; }
                    if (chunk == null) break;
                    c2oChunks.incrementAndGet();
                    lastDataTime.set(System.currentTimeMillis());
                    OutputStream out = originOutRef.get();
                    if (out != null) {
                        out.write(chunk); out.flush();
                    } else {
                        pendingData.add(chunk);
                    }
                }
            } catch (IOException e) {
                if (logRef != null) logRef.Debug("[WARP] pipeFromStream stream=%d error: %s", streamId, e.getMessage());
            }
        });
        c2o.setName("warp-c2o-" + streamId);

        // Open WARP tunnel
        TunnelConnection tunnel;
        try {
            long t0 = System.nanoTime();
            tunnel = warpOpener.open(host, port, null);
            if (logRef != null) {
                long elapsed = (System.nanoTime() - t0) / 1_000_000;
                if (elapsed > 2000) logRef.Warning("[WARP] H2 CONNECT stream=%d slow tunnel open %.0fms", streamId, (double) elapsed);
                else logRef.Debug("[WARP] H2 CONNECT stream=%d tunnel opened in %.1fms", streamId, (double) elapsed);
            }
        } catch (IOException e) {
            if (logRef != null) logRef.Debug("[WARP] H2 CONNECT stream=%d openTunnel error: %s", streamId, e.getMessage());
            try { session.sendRstStream(streamId, 0x8); } catch (IOException ignored) {}
            return;
        }

        if (!c2o.isAlive()) {
            if (logRef != null) logRef.Debug("[WARP] H2 CONNECT stream=%d c2o died while opening tunnel; abandoning", streamId);
            try { tunnel.close(); } catch (Exception ignored) {}
            return;
        }

        OutputStream tunnelOut = tunnel.outputStream();
        try {
            byte[] buffered;
            while ((buffered = pendingData.poll()) != null) {
                tunnelOut.write(buffered); tunnelOut.flush();
            }
        } catch (IOException e) {
            if (logRef != null) logRef.Debug("[WARP] H2 CONNECT stream=%d flush buffered data error: %s", streamId, e.getMessage());
        }
        originOutRef.set(tunnelOut);

        // o2c — reads from WARP tunnel, writes to browser H2 stream.
        // On normal completion (tunnel QUIC stream ends), sends END_STREAM.
        // Under watchdog-initiated close, the closed flag prevents double-close.
        InputStream tunnelIn = tunnel.inputStream();
        Thread o2c = Thread.startVirtualThread(() -> {
            if (logRef != null) logRef.Debug("[WARP] H2 CONNECT stream=%d relay o2c started", streamId);
            byte[] buf = new byte[RELAY_BUF_SIZE];
            long totalReceived = 0;
            long nextLogThreshold = 10_000_000;
            try {
                int n;
                while ((n = tunnelIn.read(buf)) >= 0) {
                    if (n > 0) lastDataTime.set(System.currentTimeMillis());
                    totalReceived += n;
                    if (totalReceived >= nextLogThreshold) {
                        if (logRef != null) logRef.Debug("[WARP] H2 CONNECT stream=%d received %d bytes total", streamId, totalReceived);
                        nextLogThreshold = totalReceived + 10_000_000;
                    }
                    browserOut.write(buf, 0, n);
                    browserOut.flush();
                }
            } catch (IOException e) {
                if (logRef != null) logRef.Debug("[WARP] pipe stream=%d error: %s", streamId, e.getMessage());
            } finally {
                StreamState ss = activeRelays.get(streamId);
                if (ss != null && !ss.closed) {
                    ss.closed = true;
                    activeRelays.remove(streamId);
                    try { browserOut.close(); } catch (IOException ignored) {}
                    if (logRef != null) logRef.Debug("[WARP] conn#%d H2 CONNECT stream=%d relay ended (o2c done)", connId, streamId);
                }
            }
        });
        o2c.setName("warp-o2c-" + streamId);

        activeRelays.put(streamId, new StreamState(connId, streamId, session, stream,
                c2o, o2c, tunnel, browserOut, lastDataTime, c2oChunks, host));
    }

    private void handleH1(InputStream in, OutputStream out) {
        // HTTP/1.1 over TLS — simple CONNECT relay
        try {
            HttpRequest req = parseRequest(in);
            if (req == null || !"CONNECT".equalsIgnoreCase(req.method)) return;

            TunnelConnection tunnel = warpOpener.open(req.host, req.port); // NON-LEAK
            out.write("HTTP/1.1 200 OK\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            out.flush();

            Thread c2o = Thread.startVirtualThread(() -> pipe(in, tunnel.outputStream(), log));
            Thread o2c = Thread.startVirtualThread(() -> pipe(tunnel.inputStream(), out, log));
            try { c2o.join(); } catch (InterruptedException ignored) {}
            try { o2c.join(); } catch (InterruptedException ignored) {}
            tunnel.close();
        } catch (IOException e) {
            if (log != null) log.Debug("[WARP] H1 tunnel error: %s", e.getMessage());
        }
    }

    private static String parseHost(String authority) {
        int colon = authority.lastIndexOf(':');
        if (colon < 0) return authority;
        return authority.substring(0, colon);
    }

    private static int parsePort(String authority, int defaultPort) {
        int colon = authority.lastIndexOf(':');
        if (colon < 0) return defaultPort;
        return Integer.parseInt(authority.substring(colon + 1));
    }

    private static boolean isHopByHop(String key) {
        String lk = key.toLowerCase();
        return lk.equals("connection") || lk.equals("keep-alive") || lk.equals("proxy-connection")
                || lk.equals("transfer-encoding") || lk.equals("upgrade") || lk.equals("proxy-authenticate")
                || lk.equals("proxy-authorization") || lk.equals("te");
    }

    private void handleH2Request(H2ServerSession session, int streamId, H2ServerSession.ServerStream stream,
                                  String method, String authority, String path, Map<String, String> headers) {
        if (log != null) log.Debug("[WARP] H2 request stream=%d %s %s%s", streamId, method, authority, path);

        String scheme = headers.get(":scheme");
        int defaultPort = "https".equals(scheme) ? 443 : 80;
        String host = parseHost(authority);
        int port = parsePort(authority, defaultPort);
        if (path == null) path = "/";
        String poolKey = host + ":" + port;

        TunnelConnection tunnel = borrowTunnel(poolKey);
        if (tunnel == null) {
            if (log != null) log.Debug("[WARP] H2 req=%d no pooled tunnel, opening new one", streamId);
            try {
                tunnel = warpOpener.open(host, port);
            } catch (IOException e) {
                if (log != null) log.Debug("[WARP] H2 req=%d open error: %s", streamId, e.getMessage());
                try { session.sendRstStream(streamId, 0x8); } catch (IOException ignored) {}
                return;
            }
        } else {
            if (log != null) log.Debug("[WARP] H2 req=%d reusing pooled tunnel for %s", streamId, poolKey);
        }

        try {
            // Build HTTP/1.1 request
            StringBuilder req = new StringBuilder(512);
            req.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
            req.append("Host: ").append(host);
            if ((port == 80 && !"https".equals(scheme)) || (port == 443 && "https".equals(scheme))) {
                // default port, omit from Host
            } else {
                req.append(':').append(port);
            }
            req.append("\r\n");
            for (Map.Entry<String, String> e : headers.entrySet()) {
                String k = e.getKey();
                if (k.startsWith(":")) continue;
                if (isHopByHop(k)) continue;
                if ("host".equalsIgnoreCase(k)) continue; // added separately above
                req.append(k).append(": ").append(e.getValue()).append("\r\n");
            }
            req.append("Connection: keep-alive\r\n");
            req.append("\r\n");

            byte[] requestBytes = req.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            long totalBytes = requestBytes.length;
            if (log != null) log.Debug("[WARP] H2 req=%d sending %d bytes to origin", streamId, requestBytes.length);
            tunnel.outputStream().write(requestBytes);
            tunnel.outputStream().flush();

            // Read HTTP/1.1 response
            InputStream originIn = tunnel.inputStream();
            int statusCode = 0;
            LinkedHashMap<String, String> respHeaders = new LinkedHashMap<>();

            // Parse status line
            if (log != null) log.Debug("[WARP] H2 req=%d reading response status line", streamId);
            String statusLine = readLine(originIn);
            if (log != null) log.Debug("[WARP] H2 req=%d got status line: %s", streamId, statusLine);
            if (statusLine == null) throw new IOException("No response");
            String[] statusParts = statusLine.split(" ", 3);
            if (statusParts.length >= 2) {
                try { statusCode = Integer.parseInt(statusParts[1]); } catch (NumberFormatException ignored) {}
            }

            // Parse response headers (raw, before stripping hop-by-hop)
            String rawTe = null;
            String rawCl = null;
            while (true) {
                String line = readLine(originIn);
                if (line == null || line.isEmpty()) break;
                int c = line.indexOf(':');
                if (c > 0) {
                    String key = line.substring(0, c).trim().toLowerCase();
                    String val = line.substring(c + 1).trim();
                    if ("transfer-encoding".equals(key)) rawTe = val;
                    if ("content-length".equals(key)) rawCl = val;
                    if (!isHopByHop(key)) {
                        respHeaders.put(key, val);
                    }
                }
            }

            if (statusCode == 0) throw new IOException("Bad response status");
            if (log != null) log.Debug("[WARP] H2 req=%d status=%d, %d response headers", streamId, statusCode, respHeaders.size());

            // Send H2 response headers (hop-by-hop already stripped)
            LinkedHashMap<String, String> h2Resp = new LinkedHashMap<>();
            h2Resp.put(":status", Integer.toString(statusCode));
            for (Map.Entry<String, String> e : respHeaders.entrySet()) {
                h2Resp.put(e.getKey(), e.getValue());
            }
            session.sendHeaders(streamId, h2Resp, H2ServerSession.FLAG_END_HEADERS);

            // Relay response body (use raw headers, before hop-by-hop stripping)
            String te = rawTe;
            String cl = rawCl;
            if (log != null) log.Debug("[WARP] H2 req=%d piping body: te=%s cl=%s", streamId, te, cl);
            if ("chunked".equalsIgnoreCase(te)) {
                totalBytes += pipeChunked(originIn, session, streamId);
            } else if (cl != null) {
                long contentLen = Long.parseLong(cl);
                totalBytes += pipeBody(originIn, session, streamId, contentLen);
                session.sendData(streamId, new byte[0], H2ServerSession.FLAG_END_STREAM);
            } else if (statusCode >= 200 && statusCode != 204 && statusCode != 304) {
                totalBytes += pipeToEof(originIn, session, streamId);
                closeTunnel(poolKey, tunnel);
                tunnel = null;
            } else {
                session.sendData(streamId, new byte[0], H2ServerSession.FLAG_END_STREAM);
            }
            if (log != null) log.Debug("[WARP] H2 req=%d body done", streamId);

            // Return tunnel to pool if not closed — skip pooling high-throughput tunnels
            if (tunnel != null) {
                if (totalBytes > HIGH_THROUGHPUT_BYTES) {
                    if (log != null) log.Debug("[WARP] H2 req=%d not pooling high-throughput tunnel (%d bytes)", streamId, totalBytes);
                    closeTunnel(poolKey, tunnel);
                } else {
                    returnTunnel(poolKey, tunnel);
                }
                tunnel = null;
            }
        } catch (IOException e) {
            if (log != null) log.Debug("[WARP] H2 request stream=%d error: %s", streamId, e.getMessage());
            try { session.sendRstStream(streamId, 0x8); } catch (IOException ignored) {}
            closeTunnel(poolKey, tunnel);
            tunnel = null;
        } finally {
            if (tunnel != null) {
                closeTunnel(poolKey, tunnel);
            }
        }
    }

    private TunnelConnection borrowTunnel(String poolKey) {
        ConcurrentLinkedQueue<PooledTunnel> queue = tunnelPool.get(poolKey);
        if (queue == null) return null;
        long now = System.currentTimeMillis();
        PooledTunnel pt;
        while ((pt = queue.poll()) != null) {
            if (pt.isTooOld()) {
                if (log != null) log.Debug("[WARP] discard tunnel too old (age=%dms)", now - pt.createdAt);
                try { pt.tunnel.close(); } catch (Exception ignored) {}
                continue;
            }
            if (now - pt.idleSince >= POOL_IDLE_TIMEOUT_MS) {
                if (log != null) log.Debug("[WARP] discard stale tunnel idle %dms", now - pt.idleSince);
                try { pt.tunnel.close(); } catch (Exception ignored) {}
                continue;
            }
            if (!pt.tunnel.isOpen()) {
                if (log != null) log.Debug("[WARP] discard closed tunnel from pool");
                continue;
            }
            if (log != null) log.Debug("[WARP] borrow tunnel idle %dms", now - pt.idleSince);
            return pt.tunnel;
        }
        return null;
    }

    private void returnTunnel(String poolKey, TunnelConnection tunnel) {
        PooledTunnel pt = new PooledTunnel(tunnel, System.currentTimeMillis());
        if (pt.isTooOld()) {
            if (log != null) log.Debug("[WARP] not pooling tunnel too old (age=%dms)", System.currentTimeMillis() - pt.createdAt);
            try { tunnel.close(); } catch (Exception ignored) {}
            return;
        }
        ConcurrentLinkedQueue<PooledTunnel> queue = tunnelPool.computeIfAbsent(poolKey, k -> new ConcurrentLinkedQueue<>());
        if (queue.size() < MAX_POOL_PER_HOST) {
            queue.offer(pt);
        } else {
            try { tunnel.close(); } catch (Exception ignored) {}
        }
    }

    private void closeTunnel(String poolKey, TunnelConnection tunnel) {
        if (tunnel != null) {
            try { tunnel.close(); } catch (Exception ignored) {}
        }
    }

    private static long pipeChunked(InputStream in, H2ServerSession session, int streamId) throws IOException {
        long total = 0;
        while (true) {
            String chunkSizeLine = readLine(in);
            if (chunkSizeLine == null) break;
            int chunkSize = Integer.parseInt(chunkSizeLine.trim(), 16);
            if (chunkSize == 0) {
                readLine(in); // trailing CRLF
                session.sendData(streamId, new byte[0], H2ServerSession.FLAG_END_STREAM);
                return total;
            }
            byte[] chunk = new byte[chunkSize];
            readExact(in, chunk);
            total += chunkSize;
            readLine(in); // trailing CRLF
            session.sendData(streamId, chunk, 0);
        }
        return total;
    }

    private static long pipeBody(InputStream in, H2ServerSession session, int streamId, long len) throws IOException {
        byte[] buf = new byte[65536];
        long total = 0;
        while (len > 0) {
            int n = in.read(buf, 0, (int) Math.min(buf.length, len));
            if (n < 0) break;
            len -= n;
            total += n;
            session.sendData(streamId, buf, 0, n, 0);
        }
        return total;
    }

    private static long pipeToEof(InputStream in, H2ServerSession session, int streamId) throws IOException {
        byte[] buf = new byte[65536];
        long total = 0;
        int n;
        while ((n = in.read(buf)) >= 0) {
            total += n;
            session.sendData(streamId, buf, 0, n, 0);
        }
        session.sendData(streamId, new byte[0], H2ServerSession.FLAG_END_STREAM);
        return total;
    }

    private static void readExact(InputStream in, byte[] dst) throws IOException {
        int off = 0;
        while (off < dst.length) {
            int n = in.read(dst, off, dst.length - off);
            if (n < 0) throw new IOException("Unexpected EOF");
            off += n;
        }
    }

    private static void pipe(InputStream in, OutputStream out, int streamId, AtomicBoolean done, AtomicLong lastDataTime, CondLogger log) {
        byte[] buf = new byte[RELAY_BUF_SIZE];
        try {
            int n;
            while (!done.get()) {
                long t0 = System.nanoTime();
                n = in.read(buf);
                long blockedMs = (System.nanoTime() - t0) / 1000000;
                if (n >= 0) {
                    if (lastDataTime != null) lastDataTime.set(System.currentTimeMillis());
                    if (log != null) log.Debug("[WARP] pipe stream=%d read %d bytes from tunnel (blocked %dms)", streamId, n, blockedMs);
                    out.write(buf, 0, n);
                    out.flush();
                } else {
                    if (log != null) log.Debug("[WARP] pipe stream=%d tunnel closed (blocked %dms)", streamId, blockedMs);
                    break;
                }
            }
        } catch (IOException e) {
            if (log != null) log.Debug("[WARP] pipe stream=%d error: %s", streamId, e.getMessage());
        }
    }

    private static void pipe(InputStream in, OutputStream out) {
        pipe(in, out, -1, null, null, null);
    }

    private static void pipe(InputStream in, OutputStream out, CondLogger log) {
        pipe(in, out, -1, null, null, log);
    }

    private static void pipe(InputStream in, OutputStream out, int streamId, AtomicBoolean done, CondLogger log) {
        pipe(in, out, streamId, done, null, log);
    }

    private static void pipeFromStream(H2ServerSession.ServerStream stream, OutputStream out) {
        pipeFromStream(stream, out, null, null);
    }

    private static void pipeFromStream(H2ServerSession.ServerStream stream, OutputStream out, CondLogger log) {
        pipeFromStream(stream, out, null, log);
    }

    private static void pipeFromStream(H2ServerSession.ServerStream stream, OutputStream out, AtomicBoolean done, CondLogger log) {
        try {
            byte[] chunk;
            while (done == null || !done.get()) {
                long t0 = System.nanoTime();
                chunk = stream.readChunk();
                long blockedMs = (System.nanoTime() - t0) / 1000000;
                if (chunk != null) {
                    if (log != null) log.Debug("[WARP] pipeFromStream stream=%d chunk=%d bytes (blocked %dms)", stream.streamId, chunk.length, blockedMs);
                    out.write(chunk);
                    out.flush();
                } else {
                    if (log != null) log.Debug("[WARP] pipeFromStream stream=%d browser closed (blocked %dms)", stream.streamId, blockedMs);
                    break;
                }
            }
        } catch (IOException e) {
            if (log != null) log.Debug("[WARP] pipeFromStream stream=%d error: %s", stream.streamId, e.getMessage());
        }
        if (log != null) log.Debug("[WARP] pipeFromStream stream=%d relay thread done", stream.streamId);
    }

    // ─── HTTP/1.1 request parsing ──────────────────────────────────────────

    private static final class HttpRequest {
        final String method;
        final String host;
        final int port;

        HttpRequest(String method, String host, int port) {
            this.method = method;
            this.host = host;
            this.port = port;
        }
    }

    private static HttpRequest parseRequest(InputStream in) throws IOException {
        String requestLine = readLine(in);
        if (requestLine == null || requestLine.isEmpty()) return null;
        String[] parts = requestLine.split(" ", 3);
        if (parts.length < 3) return null;
        String method = parts[0];
        String uri = parts[1];

        String host = null;
        int port = 443;
        if (uri.contains("://")) {
            // Absolute-form URI: CONNECT http://host:port/...
            String rest = uri.substring(uri.indexOf("://") + 3);
            int slash = rest.indexOf('/');
            if (slash > 0) rest = rest.substring(0, slash);
            int colon = rest.lastIndexOf(':');
            if (colon > 0) {
                host = rest.substring(0, colon);
                port = Integer.parseInt(rest.substring(colon + 1));
            } else {
                host = rest;
            }
        } else {
            // authority-form: CONNECT host:port
            int colon = uri.lastIndexOf(':');
            if (colon > 0) {
                host = uri.substring(0, colon);
                port = Integer.parseInt(uri.substring(colon + 1));
            } else {
                host = uri;
            }
        }
        return new HttpRequest(method, host, port);
    }

    // Per-thread scratch buffer for readLine to avoid per-byte reads
    private static final ThreadLocal<byte[]> LINE_SCRATCH = ThreadLocal.withInitial(() -> new byte[4096]);

    private static String readLine(InputStream in) throws IOException {
        byte[] scratch = LINE_SCRATCH.get();
        int pos = 0;
        int b = 0;
        while (pos < scratch.length) {
            b = in.read();
            if (b == -1) break;
            if (b == '\r') continue;
            if (b == '\n') break;
            scratch[pos++] = (byte) b;
        }
        return pos > 0 ? new String(scratch, 0, pos, java.nio.charset.StandardCharsets.ISO_8859_1) : (b == -1 ? null : "");
    }

    @Override
    public void close() {
        try { serverSocket.close(); } catch (IOException ignored) {}
    }

    // ─── Self-signed certificate generation ─────────────────────────────────

    private static final OID OID_COMMON_NAME = new OID("2.5.4.3");
    private static final String SIG_ALG = "SHA256withRSA";
    private static final String SIG_ALG_OID = "1.2.840.113549.1.1.11";

    private static X509Certificate generateSelfSignedCert(KeyPair kp, String cn, SecureRandom rng) throws Exception {
        X500Name subject = buildX500Name(cn);

        byte[] tbsCert = buildTbsCertificate(kp.getPublic(), subject, kp.getPublic(), rng);

        Signature sig = Signature.getInstance(SIG_ALG);
        sig.initSign(kp.getPrivate());
        sig.update(tbsCert);
        byte[] signatureBytes = sig.sign();

        ByteArrayOutputStream certBody = new ByteArrayOutputStream(tbsCert.length + 256);
        certBody.write(tbsCert);
        certBody.write(encodeAlgorithmIdentifier(SIG_ALG_OID));
        byte[] bitStringContent = new byte[signatureBytes.length + 1];
        bitStringContent[0] = 0;
        System.arraycopy(signatureBytes, 0, bitStringContent, 1, signatureBytes.length);
        certBody.write(DER.BIT_STRING);
        writeDerLength(certBody, bitStringContent.length);
        certBody.write(bitStringContent);

        byte[] encoded = wrapSequence(certBody.toByteArray());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoded));
    }

    private static byte[] buildTbsCertificate(PublicKey pubKey, X500Name subject,
                                              PublicKey issuerPubKey, SecureRandom rng) throws Exception {
        ByteArrayOutputStream content = new ByteArrayOutputStream(512);

        // version [0] EXPLICIT INTEGER v3 (2)
        byte[] verBytes = new DERValue(DER.INTEGER, BigInteger.valueOf(2)).getEncoded();
        content.write(0xA0);
        writeDerLength(content, verBytes.length);
        content.write(verBytes);

        // serialNumber
        byte[] serial = new byte[16];
        rng.nextBytes(serial);
        content.write(new DERValue(DER.INTEGER, new BigInteger(1, serial)).getEncoded());

        // signature AlgorithmIdentifier
        content.write(encodeAlgorithmIdentifier(SIG_ALG_OID));

        // issuer
        content.write(subject.getDer());

        // validity
        Date now = new Date();
        Date expires = new Date(now.getTime() + TimeUnit.DAYS.toMillis(365));
        List<DERValue> validity = new ArrayList<>();
        validity.add(encodeTime(now));
        validity.add(encodeTime(expires));
        DERWriter.write(content, new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, validity));

        // subject = issuer (self-signed)
        content.write(subject.getDer());

        // subjectPublicKeyInfo
        content.write(encodePublicKey(pubKey));

        byte[] tbsContent = content.toByteArray();
        return wrapSequence(tbsContent);
    }

    private static X500Name buildX500Name(String cn) throws IOException {
        List<DERValue> rdns = new ArrayList<>();
        List<DERValue> tv = new ArrayList<>();
        tv.add(new DERValue(DER.OBJECT_IDENTIFIER, OID_COMMON_NAME));
        tv.add(new DERValue(DER.UTF8_STRING, cn));
        rdns.add(new DERValue(DER.CONSTRUCTED | DER.SET, Collections.singletonList(
                new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, tv))));
        return new X500Name(new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, rdns).getEncoded());
    }

    private static byte[] encodeAlgorithmIdentifier(String oidStr) throws IOException {
        byte[] oidBytes = new DERValue(DER.OBJECT_IDENTIFIER, new OID(oidStr)).getEncoded();
        ByteArrayOutputStream baos = new ByteArrayOutputStream(oidBytes.length + 4);
        baos.write(DER.CONSTRUCTED | DER.SEQUENCE);
        writeDerLength(baos, oidBytes.length + 2);
        baos.write(oidBytes);
        baos.write(DER.NULL);
        baos.write(0);
        return baos.toByteArray();
    }

    private static byte[] encodePublicKey(PublicKey publicKey) throws GeneralSecurityException, IOException {
        byte[] encoded = publicKey.getEncoded();
        if (encoded != null && "X.509".equals(publicKey.getFormat())) return encoded;
        KeyFactory kf = KeyFactory.getInstance(publicKey.getAlgorithm());
        return kf.getKeySpec(publicKey, X509EncodedKeySpec.class).getEncoded();
    }

    private static DERValue encodeTime(Date date) {
        Instant instant = date.toInstant();
        ZonedDateTime utc = instant.atZone(ZoneOffset.UTC);
        int year = utc.getYear();
        String fmt = year >= 1950 && year < 2050 ? "yyMMddHHmmss" : "yyyyMMddHHmmss";
        return new DERValue(year >= 1950 && year < 2050 ? DER.UTC_TIME : DER.GENERALIZED_TIME,
                utc.format(DateTimeFormatter.ofPattern(fmt)) + "Z");
    }

    private static byte[] wrapSequence(byte[] inner) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(inner.length + 4);
        buf.write(DER.CONSTRUCTED | DER.SEQUENCE);
        writeDerLength(buf, inner.length);
        buf.write(inner);
        return buf.toByteArray();
    }

    private static void writeDerLength(OutputStream out, int len) throws IOException {
        if (len < 128) out.write(len);
        else if (len < 256) { out.write(0x81); out.write(len); }
        else if (len < 65536) { out.write(0x82); out.write(len >> 8); out.write(len); }
        else { out.write(0x83); out.write(len >> 16); out.write(len >> 8); out.write(len); }
    }
}
