package com.platypus.proxy.handler;

import com.platypus.proxy.handler.h2.H2ProxyService;
import com.platypus.proxy.handler.h2.MitmHandler;
import com.platypus.proxy.handler.h2.SSLEngineInputStream;
import com.platypus.proxy.handler.h2.SSLEngineOutputStream;
import com.platypus.proxy.handler.http.HttpHeaders;
import com.platypus.proxy.handler.http.HttpResponseParser;
import com.platypus.proxy.handler.http.HttpStatusConsumesHeaders;
import com.platypus.proxy.handler.protocol.BaselineProtocol;
import com.platypus.proxy.handler.protocol.OutboundProtocol;
import com.platypus.proxy.handler.protocol.Socks5Helper;
import com.platypus.proxy.io.ChunkedDecodingInputStream;
import com.platypus.proxy.io.LimitedInputStream;
import com.platypus.proxy.io.ReadUntilCloseInputStream;
import com.platypus.proxy.io.TunnelConnection;
import com.platypus.proxy.io.TunnelOpener;
import com.platypus.proxy.logging.CondLogger;
import com.platypus.proxy.provider.ProviderProxyIntercept;
import com.platypus.proxy.resolver.LookupNetIP;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.Supplier;
import javax.net.ssl.*;
import org.glassfish.grizzly.http.server.HttpHandler;
import org.glassfish.grizzly.http.server.Request;
import org.glassfish.grizzly.http.server.Response;
import org.glassfish.grizzly.nio.NIOConnection;
import org.glassfish.grizzly.ssl.SSLConnectionContext;
import org.glassfish.grizzly.ssl.SSLUtils;

/**
 * The proxy handler that implements HTTP/1.1 and HTTP/2 request forwarding
 * through a baseline proxy, with optional TLS-in-TLS MITM for traffic
 * inspection.  Merges the former {@code ConnectionManager} (socket pooling,
 * TLS wrapping, outbound proxy routing) and {@code ConnectionTunneller}
 * (CONNECT tunnel establishment) into a single class.
 */
public class ProxyHandler extends HttpHandler implements AutoCloseable {

    /**
     * Supplier of an upstream {@link com.platypus.proxy.io.TunnelConnection}
     * per inner h2 stream.  Implemented by
     * {@link com.platypus.proxy.handler.h2.MitmTunnelConnector} which
     * opens a CONNECT tunnel to the upstream HTTP/1.1 proxy and
     * optionally wraps it in TLS for the h2/h1 ALPN-negotiated inner
     * hop.  The {@code InnerH2MitmServerFilter} looks up a supplier
     * via a {@code Supplier<TunnelSupplier>} so the filter can be
     * created without a hard reference to the connector (which is
     * created per-outer-stream).
     */
    public interface TunnelSupplier {
        com.platypus.proxy.io.TunnelConnection open(String host, int port) throws IOException;
    }

    public static final int RELAY_BUF_SIZE = 1024 * 1024;
    public static final Set<String> HOP_BY_HOP =
            Set.of("Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Connection", "TE", "Trailers", "Upgrade");

    // =====================================================================
    //  Fields -- connection management (ex-ConnectionManager)
    // =====================================================================

    final String baselineHost;
    final int baselinePort;
    final String tlsServerName;
    final boolean tlsToBaseline;
    public final Supplier<String> authProvider;
    final boolean hideSNI;
    final CondLogger logger;
    final ChainedProxyConfig chainedProxyConfig;

    final boolean directDns;
    final LookupNetIP directResolver;

    final BaselineProtocol baselineProtocol;
    final ProviderProxyIntercept interceptor;
    private TunnelOpener warpTunnelOpener;

    private final Endpoint endpoint;
    private boolean directMode = false;

    private final ConcurrentLinkedQueue<PooledSocket> tunnelIdle = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<PooledSocket> httpIdle = new ConcurrentLinkedQueue<>();

    private static final int MAX_TOTAL = 2048;
    final Semaphore socketPermits;
    final Set<Socket> leasedSockets = ConcurrentHashMap.newKeySet();

    private final ScheduledExecutorService idleSocketEvictor;

    private static final int MAX_IDLE_RAW = 256;
    private static final int MAX_IDLE_BASELINE = 256;
    private static final long IDLE_TIMEOUT_MS = 60_000;

    private record PooledSocket(Socket socket, long returnTimeNanos) {}

    private static final int RECV_BUF_SIZE = 2048 * 1024;
    private static final int SEND_BUF_SIZE = 2048 * 1024;
    private static final String[] H2_ALPN_PROTOCOLS = {"h2", "http/1.1"};

    // =====================================================================
    //  Fields -- HTTP handler (ex-original ProxyHandler)
    // =====================================================================

    private final LookupNetIP resolver;
    private final AtomicLong tunnelIdSeq = new AtomicLong(0);
    private final boolean mitmEnabled;

    // =====================================================================
    //  Outbound proxy configuration record (ex-ConnectionManager inner)
    // =====================================================================

    public record ChainedProxyConfig(
            String host, int port, OutboundProtocol type, boolean remoteDns, Supplier<String> auth) {}

    // =====================================================================
    //  Constructor
    // =====================================================================

    public ProxyHandler(
            Endpoint endpoint,
            Supplier<String> authProvider,
            boolean hideSNI,
            String outboundProxyUrl,
            CondLogger logger,
            boolean directDns,
            LookupNetIP directResolver,
            BaselineProtocol baselineProtocol,
            ProviderProxyIntercept interceptor,
            LookupNetIP resolver,
            boolean mitmEnabled) {
        this.baselineHost = endpoint.host();
        this.baselinePort = endpoint.port();
        this.tlsToBaseline = endpoint.tlsName() != null && !endpoint.tlsName().isEmpty();
        this.tlsServerName =
                (endpoint.tlsName() != null && !endpoint.tlsName().isEmpty()) ? endpoint.tlsName() : baselineHost;
        this.authProvider = authProvider;
        this.hideSNI = hideSNI;
        this.logger = logger;
        this.directDns = directDns;
        this.directResolver = directResolver;
        this.baselineProtocol = baselineProtocol;
        this.interceptor = interceptor;
        this.endpoint = endpoint;

        if (outboundProxyUrl != null && !outboundProxyUrl.isEmpty()) {
            this.chainedProxyConfig = ConnectUtil.parseOutboundProxy(outboundProxyUrl);
        } else {
            this.chainedProxyConfig = null;
        }

        this.socketPermits = new Semaphore(MAX_TOTAL, true);

        this.idleSocketEvictor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "conn-mgr-cleaner");
            t.setDaemon(true);
            return t;
        });
        idleSocketEvictor.scheduleWithFixedDelay(this::evictExpired, 30, 30, TimeUnit.SECONDS);

        this.resolver = resolver;
        this.mitmEnabled = mitmEnabled;
    }

    // =====================================================================
    //  Lifecycle
    // =====================================================================

    @Override
    public void close() {
        idleSocketEvictor.shutdown();
        try {
            idleSocketEvictor.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            idleSocketEvictor.shutdownNow();
        }
        PooledSocket is;
        while ((is = tunnelIdle.poll()) != null) {
            releaseOwnedSocket(is.socket());
        }
        while ((is = httpIdle.poll()) != null) {
            releaseOwnedSocket(is.socket());
        }
    }

    // =====================================================================
    //  Public connection API (ex-ConnectionManager)
    // =====================================================================

    public TunnelConnection openTcpConnectionTo(String targetHost, int targetPort) throws IOException {
        Socket socket;
        if (chainedProxyConfig != null) {
            socket = dialThroughOutboundProxy(targetHost, targetPort);
        } else {
            socket = new Socket(targetHost, targetPort);
            socket.setTcpNoDelay(true);
        }
        return new TunnelConnection(socket, socket.getInputStream());
    }

    public TunnelConnection connectTunnelDirect(String targetHost, int targetPort) throws IOException {
        acquireGlobalPermit();
        Socket socket;
        try {
            socket = createRawSocketTo(targetHost, targetPort);
            leasedSockets.add(socket);
        } catch (IOException e) {
            socketPermits.release();
            throw e;
        }
        tuneDirectSocket(socket);
        Consumer<Socket> releaseSocket = this::releaseOwnedSocket;
        return new TunnelConnection(socket, socket.getInputStream(), releaseSocket);
    }

    public Socket borrowTunnelSocket(boolean requireFresh) throws IOException {
        if (!requireFresh) {
            PooledSocket is = pollIdle(tunnelIdle);
            if (is != null) {
                return is.socket();
            }
        }
        acquireGlobalPermit();
        try {
            Socket sock = createBaselineSocket();
            leasedSockets.add(sock);
            return sock;
        } catch (IOException e) {
            socketPermits.release();
            throw e;
        }
    }

    public Socket borrowHttpSocket() throws IOException {
        PooledSocket is = pollIdle(httpIdle);
        if (is != null) {
            Socket s = is.socket();
            if (ConnectUtil.isAlive(s)) {
                return s;
            }
            releaseOwnedSocket(s);
        }
        acquireGlobalPermit();
        try {
            Socket raw = createBaselineSocket();
            leasedSockets.add(raw);
            if (tlsToBaseline) {
                TlsHelper.TlsHandshakeResult result =
                        TlsHelper.wrapWithAlpn(raw, tlsServerName, hideSNI, H2_ALPN_PROTOCOLS);
                SSLSocket sslSock = result.socket();
                String negotiated = result.alpnProtocol();
                if (negotiated != null && !negotiated.isEmpty()) {
                    logger.Info("ALPN negotiated with %s: %s", tlsServerName, negotiated);
                } else {
                    logger.Warning("No ALPN protocol selected by %s - proceeding with HTTP/1.1", tlsServerName);
                }
                return sslSock;
            }
            return raw;
        } catch (IOException e) {
            socketPermits.release();
            throw e;
        }
    }

    public void releaseHttpSocket(Socket socket) {
        returnToPool(socket, httpIdle, MAX_IDLE_BASELINE);
    }

    public void releaseTunnelSocket(Socket socket) {
        returnToPool(socket, tunnelIdle, MAX_IDLE_RAW);
    }

    public void evictSocket(Socket socket) {
        if (socket == null) return;
        tunnelIdle.removeIf(is -> is.socket().equals(socket));
        httpIdle.removeIf(is -> is.socket().equals(socket));
        releaseOwnedSocket(socket);
    }

    // =====================================================================
    //  CONNECT tunnel establishment (ex-ConnectionTunneller)
    // =====================================================================

    /**
     * Creates a tunnel to the given target through the baseline proxy.
     * Merged from the former {@code ConnectionTunneller} class.
     */
    public TunnelConnection connectTunnel(String host, int port) throws IOException {
        // --- Direct forward proxy (127.0.0.1:0) --------------------
        if ("127.0.0.1".equals(baselineHost) && baselinePort == 0 && chainedProxyConfig == null) {
            logger.Debug("Direct tunnel to %s:%d", host, port);
            acquireGlobalPermit();
            Socket sock = createRawSocketTo(host, port);
            leasedSockets.add(sock);
            try {
                return new TunnelConnection(sock, sock.getInputStream(), this::releaseOwnedSocket);
            } catch (IOException e) {
                releaseOwnedSocket(sock);
                throw e;
            }
        }

        // --- Resolve target host (direct DNS if enabled) ----------
        String resolvedHost = host;
        if (directDns && directResolver != null && !isIpLiteral(host)) {
            List<InetAddress> addrs = directResolver.lookup(host);
            if (addrs.isEmpty()) {
                throw new UnknownHostException(host);
            }
            InetAddress addr = addrs.get(0);
            if (addr instanceof Inet6Address) {
                resolvedHost = "[" + addr.getHostAddress() + "]";
            } else {
                resolvedHost = addr.getHostAddress();
            }
            logger.Debug("direct DNS: %s -> %s", host, resolvedHost);
        }
        if (resolvedHost.contains(":") && !resolvedHost.startsWith("[")) {
            try {
                InetAddress addr = InetAddress.getByName(resolvedHost);
                if (addr instanceof Inet6Address) {
                    resolvedHost = "[" + resolvedHost + "]";
                }
            } catch (UnknownHostException ignored) {
            }
        }

        // --- Protocol-specific tunneling ---------------------------
        if (baselineProtocol == BaselineProtocol.WARP_MASQUE && warpTunnelOpener != null) {
            return warpTunnelOpener.open(host, port);
        }

        if (baselineProtocol == BaselineProtocol.SOCKS5) {
            return connectTunnelSocks5(resolvedHost, port);
        }

        if (interceptor != null) {
            return connectTunnelWithIntercept(resolvedHost, port);
        }

        // --- Standard HTTP CONNECT with optional TLS wrapping ------
        acquireGlobalPermit();
        Socket sock;
        try {
            sock = createBaselineSocket();
            leasedSockets.add(sock);
        } catch (IOException e) {
            socketPermits.release();
            throw e;
        }

        try {
            if (tlsToBaseline) {
                sock = TlsHelper.wrap(sock, tlsServerName, hideSNI);
            }

            String request = ConnectUtil.buildConnectRequest(resolvedHost, port, authProvider);
            OutputStream out = sock.getOutputStream();
            out.write(request.getBytes(StandardCharsets.UTF_8));
            out.flush();

            PushbackInputStream pin = new PushbackInputStream(sock.getInputStream(), 8192);
            String statusLineText = HttpHeaders.consumeHeadersAndReadStatusLine(pin);
            HttpStatusConsumesHeaders response = HttpStatusConsumesHeaders.parseStatusLine(statusLineText);
            if (response == null || response.statusCode() != 200) {
                if (response != null && response.statusCode() == 403) {
                    throw new UpstreamBlockedError("Host blocked: " + resolvedHost);
                }
                throw new IOException("CONNECT failed: " + (response != null ? response.statusLine() : "null"));
            }

            logger.Debug("connectTunnel: tunnel established");
            return new TunnelConnection(sock, pin, this::releaseOwnedSocket);
        } catch (IOException e) {
            releaseOwnedSocket(sock);
            throw e;
        }
    }

    /**
     * Creates a CONNECT tunnel through the baseline proxy to the given
     * target, dedicated for MITM forwarding.  This method does NOT branch
     * on SOCKS5 / intercept / chained-proxy -- it always uses HTTP CONNECT
     * over a fresh baseline socket wrapped with TLS when tlsToBaseline is
     * set.  The caller assumes ownership of the returned TunnelConnection
     * and MUST close it when done.
     */
    public String resolveForDirectDns(String host) throws UnknownHostException {
        if (!directDns || directResolver == null || isIpLiteral(host)) {
            return host;
        }
        List<InetAddress> addrs = directResolver.lookup(host);
        if (addrs.isEmpty()) {
            throw new UnknownHostException(host);
        }
        InetAddress addr = addrs.get(0);
        String resolved = addr instanceof Inet6Address ? "[" + addr.getHostAddress() + "]" : addr.getHostAddress();
        logger.Debug("direct DNS: %s -> %s", host, resolved);
        return resolved;
    }

    public TunnelConnection connectTunnelForMitm(String targetHost, int targetPort) throws IOException {
        return connectTunnelForMitmResolved(targetHost, resolveForDirectDns(targetHost), targetPort);
    }

    public TunnelConnection connectTunnelForMitmResolved(String originalHost, String resolvedHost, int targetPort) throws IOException {
        if (baselineProtocol == BaselineProtocol.WARP_MASQUE && warpTunnelOpener != null) {
            return warpTunnelOpener.open(originalHost, targetPort);
        }

        acquireGlobalPermit();
        Socket sock;
        try {
            sock = createBaselineSocket();
            leasedSockets.add(sock);
        } catch (IOException e) {
            socketPermits.release();
            throw e;
        }
        try {
            if (tlsToBaseline) {
                sock = TlsHelper.wrap(sock, tlsServerName, hideSNI);
            }

            String request = ConnectUtil.buildConnectRequest(resolvedHost, targetPort, authProvider);
            OutputStream out = sock.getOutputStream();
            out.write(request.getBytes(StandardCharsets.UTF_8));
            out.flush();

            PushbackInputStream pin = new PushbackInputStream(sock.getInputStream(), 8192);
            String statusLineText = HttpHeaders.consumeHeadersAndReadStatusLine(pin);
            HttpStatusConsumesHeaders response = HttpStatusConsumesHeaders.parseStatusLine(statusLineText);
            if (response == null || response.statusCode() != 200) {
                throw new IOException("CONNECT failed for " + originalHost + ":" + targetPort + ": "
                        + (response != null ? response.statusLine() : "null"));
            }
            logger.Debug("connectTunnelForMitm: tunnel to %s:%d established", originalHost, targetPort);
            return new TunnelConnection(sock, pin, this::releaseOwnedSocket);
        } catch (IOException e) {
            releaseOwnedSocket(sock);
            throw e;
        }
    }

    /**
     * Plain byte passthrough for CONNECTs to non-HTTP ports (XMPP, MQTT,
     * raw TCP, ...).  Opens a raw tunnel through the upstream proxy and
     * shuttles bytes bidirectionally between the outer TLS streams and
     * the tunnel.  No protocol parsing, no MITM, no HPACK.
     *
     * <p>Reading from {@code outerIn} and writing to {@code tunnelOut}
     * runs in one virtual thread; the reverse runs in a sibling
     * virtual thread.  When either direction returns EOF, both are
     * torn down.
     */
    public void passthrough(
            SSLEngineInputStream outerIn,
            SSLEngineOutputStream outerOut,
            String host,
            int port,
            SocketChannel clientCh) {
        TunnelConnection tunnel;
        try {
            tunnel = connectTunnelForMitm(host, port);
        } catch (IOException e) {
            logger.Error("passthrough: CONNECT to %s:%d failed: %s", host, port, e.getMessage());
            return;
        }
        AtomicBoolean done = new AtomicBoolean(false);
        Thread upstreamToClient = new Thread(
                () -> {
                    byte[] buf = new byte[RELAY_BUF_SIZE];
                    try (InputStream in = tunnel.inputStream()) {
                        int n;
                        while (!done.get() && (n = in.read(buf)) != -1) {
                            outerOut.write(buf, 0, n);
                            outerOut.flush();
                        }
                    } catch (IOException ignored) {
                    } finally {
                        done.set(true);
                    }
                },
                "passthrough-up2client-" + host + ":" + port);
        upstreamToClient.setDaemon(true);
        upstreamToClient.start();

        byte[] buf = new byte[RELAY_BUF_SIZE];
        try (OutputStream tunnelOut = tunnel.socket().getOutputStream()) {
            int n;
            while (!done.get() && (n = outerIn.read(buf)) != -1) {
                tunnelOut.write(buf, 0, n);
                tunnelOut.flush();
            }
        } catch (IOException ignored) {
        } finally {
            done.set(true);
            try {
                upstreamToClient.join(2000);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            closeQuietly(tunnel);
        }
    }

    // =====================================================================
    //  Internal connection helpers (ex-ConnectionManager)
    // =====================================================================

    Socket createRawSocketTo(String targetHost, int targetPort) throws IOException {
        if (chainedProxyConfig != null) {
            return dialThroughOutboundProxy(targetHost, targetPort);
        } else {
            Socket s = new Socket(targetHost, targetPort);
            s.setTcpNoDelay(true);
            return s;
        }
    }

    private void tuneDirectSocket(Socket socket) throws SocketException {
        socket.setSoTimeout(30_000);
        socket.setReceiveBufferSize(RECV_BUF_SIZE);
        socket.setSendBufferSize(SEND_BUF_SIZE);
    }

    Socket createBaselineSocket() throws IOException {
        Socket sock;
        if (chainedProxyConfig != null) {
            sock = dialThroughOutboundProxy(baselineHost, baselinePort);
        } else {
            sock = new Socket(baselineHost, baselinePort);
        }
        sock.setTcpNoDelay(true);
        sock.setReceiveBufferSize(RECV_BUF_SIZE);
        sock.setSendBufferSize(SEND_BUF_SIZE);
        return sock;
    }

    @SuppressWarnings("unused")
    private Socket createSocks5Tunnel(String targetHost, int targetPort) throws IOException {
        Socket sock = createBaselineSocket();
        try {
            Socks5Helper.handshake(sock, targetHost, targetPort, false, authProvider);
            return sock;
        } catch (IOException e) {
            sock.close();
            throw e;
        }
    }

    TunnelConnection connectTunnelSocks5(String targetHost, int targetPort) throws IOException {
        acquireGlobalPermit();
        Socket proxySocket;
        try {
            proxySocket = createBaselineSocket();
            leasedSockets.add(proxySocket);
        } catch (IOException e) {
            socketPermits.release();
            throw e;
        }
        try {
            Socks5Helper.handshake(proxySocket, targetHost, targetPort, false, authProvider);
            InputStream in = proxySocket.getInputStream();
            return new TunnelConnection(proxySocket, in);
        } catch (IOException e) {
            releaseOwnedSocket(proxySocket);
            throw e;
        }
    }

    TunnelConnection connectTunnelWithIntercept(String resolvedHost, int targetPort) throws IOException {
        Consumer<Socket> releaseSocket = this::releaseOwnedSocket;

        acquireGlobalPermit();
        Socket sock1;
        try {
            sock1 = createBaselineSocket();
            leasedSockets.add(sock1);
        } catch (IOException e) {
            socketPermits.release();
            throw e;
        }

        Supplier<Socket> socketFactory = () -> {
            try {
                acquireGlobalPermit();
                Socket s = createBaselineSocket();
                leasedSockets.add(s);
                if (tlsToBaseline) {
                    s = TlsHelper.wrap(s, tlsServerName, hideSNI);
                }
                return s;
            } catch (IOException e) {
                socketPermits.release();
                throw new UncheckedIOException(e);
            }
        };

        try {
            ProviderProxyIntercept.InterceptResult hr =
                    interceptor.intercept(sock1, resolvedHost, targetPort, socketFactory, releaseSocket, endpoint);
            return new TunnelConnection(hr.socket(), hr.tunnelStream());
        } catch (IOException e) {
            throw e;
        }
    }

    private Socket dialThroughOutboundProxy(String targetHost, int targetPort) throws IOException {
        if (chainedProxyConfig == null) {
            return new Socket(targetHost, targetPort);
        }

        Socket proxySock = new Socket(chainedProxyConfig.host, chainedProxyConfig.port);
        proxySock.setTcpNoDelay(true);

        if (chainedProxyConfig.type == OutboundProtocol.HTTP || chainedProxyConfig.type == OutboundProtocol.HTTPS) {
            if (chainedProxyConfig.type == OutboundProtocol.HTTPS) {
                proxySock = TlsHelper.wrap(proxySock, chainedProxyConfig.host, false);
            }
            String connectReq = ConnectUtil.buildConnectRequest(targetHost, targetPort, chainedProxyConfig.auth);
            OutputStream out = proxySock.getOutputStream();
            out.write(connectReq.getBytes(StandardCharsets.UTF_8));
            out.flush();

            InputStream in = proxySock.getInputStream();
            PushbackInputStream pin = new PushbackInputStream(in, 8192);
            try {
                validateConnectResponse(pin);
            } catch (IOException e) {
                proxySock.close();
                throw e;
            }
            return proxySock;
        } else if (chainedProxyConfig.type == OutboundProtocol.SOCKS5) {
            Socks5Helper.handshake(
                    proxySock, targetHost, targetPort, chainedProxyConfig.remoteDns, chainedProxyConfig.auth);
            return proxySock;
        } else {
            throw new IOException("Unsupported outbound proxy type");
        }
    }

    private static void validateConnectResponse(PushbackInputStream in) throws IOException {
        String statusLine = readLineRaw(in);
        int statusCode;
        try {
            String[] parts = statusLine.split(" ");
            if (parts.length < 2) {
                throw new IOException("Malformed status line: " + statusLine);
            }
            statusCode = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw new IOException("Invalid status line: " + statusLine);
        }
        if (statusCode != 200) {
            throw new IOException("Outbound proxy CONNECT rejected with status " + statusCode + ": " + statusLine);
        }

        @SuppressWarnings("unused")
        String line;
        while (!(line = readLineRaw(in)).isEmpty()) {
            // skip header
        }
    }

    private static String readLineRaw(PushbackInputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int prev = -1;
        while (true) {
            int cur = in.read();
            if (cur == -1) {
                if (sb.length() == 0) {
                    throw new EOFException("Unexpected end of stream while reading HTTP response");
                }
                break;
            }
            if (cur == '\n') {
                if (prev == '\r' && sb.length() > 0 && sb.charAt(sb.length() - 1) == '\r') {
                    sb.setLength(sb.length() - 1);
                }
                break;
            }
            sb.append((char) cur);
            prev = cur;
        }
        return sb.toString();
    }

    // =====================================================================
    //  Global permit management (ex-ConnectionManager)
    // =====================================================================

    void acquireGlobalPermit() throws IOException {
        try {
            if (!socketPermits.tryAcquire(5, TimeUnit.SECONDS)) {
                logger.Debug("Global connection pool exhausted");
                throw new IOException("Global connection pool exhausted");
            }
        } catch (InterruptedException e) {
            throw new IOException("Interrupted while acquiring global connection permit");
        }
    }

    public void releaseOwnedSocket(Socket socket) {
        if (socket == null) return;
        if (leasedSockets.remove(socket)) {
            socketPermits.release();
        }
        closeSocketQuietly(socket);
    }

    private void returnToPool(Socket socket, ConcurrentLinkedQueue<PooledSocket> idle, int maxIdle) {
        if (socket == null || socket.isClosed()) {
            releaseOwnedSocket(socket);
            return;
        }
        if (idle.size() < maxIdle) {
            idle.add(new PooledSocket(socket, System.nanoTime()));
        } else {
            releaseOwnedSocket(socket);
        }
    }

    // =====================================================================
    //  Idle pool maintenance (ex-ConnectionManager)
    // =====================================================================

    private static PooledSocket pollIdle(ConcurrentLinkedQueue<PooledSocket> idle) {
        PooledSocket is;
        while ((is = idle.poll()) != null) {
            if (!is.socket().isClosed() && !isExpired(is)) {
                return is;
            }
            closeSocketQuietly(is.socket());
        }
        return null;
    }

    private void evictExpired() {
        long now = System.nanoTime();
        evictFrom(tunnelIdle, now);
        evictFrom(httpIdle, now);
    }

    private void evictFrom(ConcurrentLinkedQueue<PooledSocket> idle, long nowNanos) {
        PooledSocket is;
        while ((is = idle.peek()) != null && isExpired(is, nowNanos)) {
            if (idle.remove(is)) {
                releaseOwnedSocket(is.socket());
            }
        }
    }

    private static boolean isExpired(PooledSocket is) {
        return isExpired(is, System.nanoTime());
    }

    private static boolean isExpired(PooledSocket is, long nowNanos) {
        long elapsedNanos = nowNanos - is.returnTimeNanos();
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(elapsedNanos);
        return elapsedMs > IDLE_TIMEOUT_MS;
    }

    private static void closeSocketQuietly(Socket s) {
        try {
            if (s != null) s.close();
        } catch (IOException ignored) {
        }
    }

    static boolean isIpLiteral(String host) {
        if (host.startsWith("[") && host.endsWith("]")) {
            return true;
        }
        try {
            InetAddress.getByName(host);
            return true;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private H2ProxyService h2ProxyService;

    public void setH2ProxyService(H2ProxyService h2ProxyService) {
        this.h2ProxyService = h2ProxyService;
    }

    public void setWarpTunnelOpener(TunnelOpener tunnelOpener) {
        this.warpTunnelOpener = tunnelOpener;
    }

    public void setDirectMode(boolean directMode) {
        this.directMode = directMode;
    }

    public boolean isDirectMode() {
        return directMode;
    }

    public boolean isMitmEnabled() {
        return mitmEnabled;
    }

    // =====================================================================

    @Override
    public void service(Request request, Response response) throws Exception {
        String method = request.getMethod().getMethodString();
        String uri = request.getRequestURI();

        logger.Info("%s:%d %s %s", request.getRemoteAddr(), request.getRemotePort(), method, uri);

        if ("CONNECT".equalsIgnoreCase(method)) {
            handleTunnel(request, response, uri);
        } else {
            handleRequest(request, response, method, uri);
        }
    }

    // =====================================================================
    //  CONNECT tunnel handling
    // =====================================================================

    private void handleTunnel(Request request, Response response, String target) throws Exception {
        logger.Info(
                ">>>>>> CONNECT request for %s (mitmEnabled=%b, secure=%b)", target, mitmEnabled, request.isSecure());

        String[] parts = target.split(":");
        if (parts.length < 2) {
            sendError(response, 400, "Bad CONNECT target");
            return;
        }
        String host = parts[0];
        int port;
        try {
            port = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            sendError(response, 400, "Invalid port");
            return;
        }

        if (request.isSecure() && mitmEnabled) {
            String protocol = request.getProtocol().getProtocolString();
            if (protocol != null && protocol.contains("2.0")) {
                logger.Error("HTTP/2 CONNECT reached handleTunnel -- this should be "
                        + "handled by Http2MitmServerFilter. Rejecting to prevent "
                        + "socket detachment on multiplexed connection.");
                response.setStatus(500);
                response.setContentType("text/plain");
                response.getWriter().write("HTTP/2 CONNECT must be handled at the stream level");
                return;
            }
        }

        final SSLEngine outerEngine = mitmEnabled ? getClientSslEngine(request) : null;

        if (outerEngine != null) {
            SocketChannel clientCh;
            try {
                clientCh = detachClientChannel(request);
                tuneClientSocket(clientCh.socket());
            } catch (IOException e) {
                logger.Error("Failed to detach client channel: %s", e.getMessage());
                sendError(response, 500, "Internal error");
                return;
            }
            final ReentrantLock sslLock = new ReentrantLock();
            flushSslEngine(outerEngine, clientCh, sslLock);

            SSLEngineInputStream outerIn = new SSLEngineInputStream(outerEngine, clientCh, clientCh, sslLock);
            SSLEngineOutputStream outerOut = new SSLEngineOutputStream(outerEngine, clientCh, sslLock);

            MitmHandler.handleMitmTunnel(h2ProxyService, outerIn, outerOut, clientCh, host, port, request);
            return;
        }

        logger.Debug("[DEBUG-TUNNEL] Taking plain CONNECT relay path");
        TunnelConnection tunnel = null;
        try {
            tunnel = connectTunnel(host, port);
            logger.Debug("Tunnel to %s:%d established", host, port);
            if (tunnel.hasSocket()) {
                tuneClientSocket(tunnel.socket());
            }

            response.setStatus(200);
            response.setContentLengthLong(0);
            response.getOutputStream().flush();

            SocketChannel clientCh = detachClientChannel(request);
            tuneClientSocket(clientCh.socket());
            long id = tunnelIdSeq.incrementAndGet();
            startRelay(null, null, clientCh, id, tunnel);
        } catch (UpstreamBlockedError e) {
            logger.Info("Host %s blocked by upstream - retrying with resolved IPs", host);
            boolean retried = HostRetryExecutor.execute(host, 3, 500, logger, () -> {
                try {
                    List<java.net.InetAddress> addrs = resolver.lookup(host);
                    for (java.net.InetAddress addr : addrs) {
                        logger.Info("Retrying CONNECT to %s via IP %s", host, addr.getHostAddress());
                            try {
                                TunnelConnection retryTunnel = connectTunnel(addr.getHostAddress(), port);
                                if (retryTunnel.hasSocket()) {
                                    tuneClientSocket(retryTunnel.socket());
                                }
                                response.setStatus(200);
                                response.setContentLengthLong(0);
                                response.getOutputStream().flush();
                                SocketChannel ch = detachClientChannel(request);
                                tuneClientSocket(ch.socket());
                                long id2 = tunnelIdSeq.incrementAndGet();
                                startRelay(null, null, ch, id2, retryTunnel);
                                return true;
                            } catch (Exception ex) {
                                /* try next */
                            }
                    }
                    return false;
                } catch (Exception ex) {
                    return false;
                }
            });
            if (!retried) {
                logger.Error("All retry attempts failed for host %s", host);
                sendError(response, 403, "Host blocked");
            }
        } catch (Exception e) {
            logger.Error("Cannot satisfy CONNECT: %s - %s", target, e.getMessage());
            sendError(response, 502, "Bad Gateway");
            closeQuietly(tunnel);
        }
    }

    // =====================================================================
    //  Inner TLS handshake
    // =====================================================================

    public static ByteBuffer doInnerHandshake(
            SSLEngine engine, ReadableByteChannel in, WritableByteChannel out, SSLEngineOutputStream outerOut)
            throws IOException {
        return doInnerHandshake(engine, in, out, () -> {
            try {
                outerOut.flush();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }

    public static ByteBuffer doInnerHandshake(
            SSLEngine engine, ReadableByteChannel in, WritableByteChannel out, Runnable flusher) throws IOException {

        ByteBuffer clientHello = readFullTlsRecord(in);
        ByteBuffer appBuf = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());
        int maxAppSize = appBuf.capacity();

        ByteBuffer stray = null;

        while (clientHello.hasRemaining()) {
            SSLEngineResult initResult = engine.unwrap(clientHello, appBuf);
            switch (initResult.getStatus()) {
                case BUFFER_OVERFLOW:
                    appBuf.flip();
                    maxAppSize *= 2;
                    ByteBuffer larger = ByteBuffer.allocate(maxAppSize);
                    larger.put(appBuf);
                    appBuf = larger;
                    break;
                case BUFFER_UNDERFLOW:
                    throw new SSLException("Unexpected BUFFER_UNDERFLOW for ClientHello");
                case CLOSED:
                    return stray != null ? stray : ByteBuffer.allocate(0);
                case OK:
                    break;
            }
            if (appBuf.position() > 0) {
                stray = appendAppData(stray, appBuf);
                appBuf.clear();
            }
            runDelegatedTasks(engine);
        }

        ByteBuffer netOut = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
        int maxNetSize = netOut.capacity();
        boolean done = false;
        while (!done) {
            // JDK 20 added NEED_UNWRAP_AGAIN (TLS 1.3 can interleave handshake
            // and application data in ways the old NEED_UNWRAP does not capture).
            // Treat it as NEED_UNWRAP
            switch (engine.getHandshakeStatus()) {
                case NEED_WRAP: {
                    netOut.clear();
                    SSLEngineResult wr = engine.wrap(ByteBuffer.allocate(0), netOut);
                    netOut.flip();
                    switch (wr.getStatus()) {
                        case BUFFER_UNDERFLOW:
                            // No input data to wrap during handshake; nothing to write
                            break;
                        case CLOSED:
                            done = true;
                            break;
                        case BUFFER_OVERFLOW:
                            maxNetSize *= 2;
                            netOut = ByteBuffer.allocate(maxNetSize);
                            continue;
                        case OK:
                            break;
                    }
                    writeAll(out, netOut);
                    try {
                        flusher.run();
                    } catch (UncheckedIOException e) {
                        throw e.getCause();
                    }
                    runDelegatedTasks(engine);
                    break;
                }
                case NEED_UNWRAP_AGAIN:
                case NEED_UNWRAP: {
                    ByteBuffer rec = readFullTlsRecord(in);
                    appBuf.clear();
                    boolean needMore;
                    do {
                        needMore = false;
                        SSLEngineResult unwr = engine.unwrap(rec, appBuf);
                        switch (unwr.getStatus()) {
                            case BUFFER_UNDERFLOW:
                                ByteBuffer more = readFullTlsRecord(in);
                                ByteBuffer combined = ByteBuffer.allocate(rec.remaining() + more.remaining());
                                combined.put(rec);
                                combined.put(more);
                                combined.flip();
                                rec = combined;
                                needMore = true;
                                break;
                            case BUFFER_OVERFLOW:
                                maxAppSize *= 2;
                                appBuf = ByteBuffer.allocate(maxAppSize);
                                needMore = true;
                                break;
                            case CLOSED:
                                done = true;
                                break;
                            case OK:
                                break;
                        }
                    } while (needMore);

                    if (appBuf.position() > 0) {
                        stray = appendAppData(stray, appBuf);
                        appBuf.clear();
                    }
                    runDelegatedTasks(engine);
                    break;
                }
                case NEED_TASK:
                    runDelegatedTasks(engine);
                    break;
                case FINISHED:
                case NOT_HANDSHAKING:
                    done = true;
                    break;
            }
        }

        if (stray != null) {
            stray.flip();
            return stray;
        }
        return ByteBuffer.allocate(0);
    }

    private static ByteBuffer appendAppData(ByteBuffer acc, ByteBuffer src) {
        int srcLen = src.position();
        if (acc == null) {
            ByteBuffer b = ByteBuffer.allocate(srcLen);
            b.put(src.array(), 0, srcLen);
            return b;
        }
        int newPos = acc.position() + srcLen;
        if (newPos > acc.capacity()) {
            ByteBuffer larger = ByteBuffer.allocate(newPos * 2);
            larger.put(acc);
            acc = larger;
        }
        acc.put(src.array(), 0, srcLen);
        return acc;
    }

    public static ByteBuffer readFullTlsRecord(ReadableByteChannel ch) throws IOException {
        ByteBuffer header = ByteBuffer.allocate(5);
        readExact(ch, header);
        header.flip();
        byte type = header.get();
        short version = header.getShort();
        int length = header.getShort() & 0xFFFF;
        ByteBuffer record = ByteBuffer.allocate(length + 5);
        record.put(new byte[] {type, (byte) (version >>> 8), (byte) version, (byte) (length >>> 8), (byte) length});
        ByteBuffer body = ByteBuffer.allocate(length);
        readExact(ch, body);
        body.flip();
        record.put(body);
        record.flip();
        return record;
    }

    private static void readExact(ReadableByteChannel ch, ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) if (ch.read(buf) == -1) throw new EOFException("Unexpected end of stream");
    }

    public static void writeAll(WritableByteChannel ch, ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) ch.write(buf);
    }

    public static void runDelegatedTasks(SSLEngine engine) {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) task.run();
    }

    // =====================================================================
    //  Relay
    // =====================================================================

    private void startRelay(
            SSLEngineInputStream clientIn,
            SSLEngineOutputStream clientOut,
            SocketChannel clientCh,
            long id,
            TunnelConnection tunnel) {
        // DIVERGENCE: tunnel.socket() throws on stream-based tunnels (WARP/H3).
        //             Resolve an OutputStream and an optional half-close callable
        //             that work for both socket- and stream-backed tunnels.
        final Socket upstream;
        final OutputStream upstreamOut;
        final Runnable upstreamShutdownOutput;
        if (tunnel.hasSocket()) {
            upstream = tunnel.socket();
            try {
                upstreamOut = upstream.getOutputStream();
            } catch (IOException e) {
                logger.Error("Failed to obtain upstream output stream for relay %d: %s", id, e.getMessage());
                closeQuietly(tunnel);
                closeQuietly(clientCh);
                return;
            }
            upstreamShutdownOutput = () -> {
                try {
                    upstream.shutdownOutput();
                } catch (IOException ignored) {
                }
            };
        } else {
            // Stream-based tunnel (e.g. WARP H3 CONNECT). No Socket to half-close.
            upstream = null;
            upstreamOut = tunnel.outputStream();
            upstreamShutdownOutput = null;
        }
        final InputStream upstreamIn = tunnel.inputStream();
        final AtomicBoolean closed = new AtomicBoolean(false);
        Runnable closeBoth = () -> {
            if (closed.compareAndSet(false, true)) {
                closeQuietly(upstream);
                closeQuietly(clientCh);
                closeQuietly(tunnel);
            }
        };

        final InputStream clientInputStream;
        final OutputStream clientOutputStream;
        try {
            clientInputStream = clientIn != null ? clientIn : clientCh.socket().getInputStream();
        } catch (IOException e) {
            logger.Error("Failed to obtain client input stream for relay %d: %s", id, e.getMessage());
            closeBoth.run();
            return;
        }
        try {
            clientOutputStream =
                    clientOut != null ? clientOut : clientCh.socket().getOutputStream();
        } catch (IOException e) {
            logger.Error("Failed to obtain client output stream for relay %d: %s", id, e.getMessage());
            closeBoth.run();
            return;
        }

        Executor vtExec = task -> Thread.ofVirtual().name("relay-" + id).start(task);

        CompletableFuture<Void> c2u = CompletableFuture.runAsync(
                        () -> {
                            try {
                                byte[] buf = new byte[RELAY_BUF_SIZE];
                                int n;
                                while ((n = clientInputStream.read(buf)) != -1) {
                                    upstreamOut.write(buf, 0, n);
                                    upstreamOut.flush();
                                }
                            } catch (IOException e) {
                                logger.Debug("c2u relay %d ended: %s", id, e.getMessage());
                            } finally {
                                if (upstreamShutdownOutput != null) upstreamShutdownOutput.run();
                            }
                        },
                        vtExec)
                .exceptionally(ex -> {
                    closeBoth.run();
                    return null;
                });

        CompletableFuture<Void> u2c = CompletableFuture.runAsync(
                        () -> {
                            try {
                                byte[] buf = new byte[RELAY_BUF_SIZE];
                                int n;
                                while ((n = upstreamIn.read(buf)) != -1) {
                                    clientOutputStream.write(buf, 0, n);
                                    clientOutputStream.flush();
                                }
                            } catch (IOException e) {
                                logger.Debug("u2c relay %d ended: %s", id, e.getMessage());
                            } finally {
                                try {
                                    upstreamIn.close();
                                } catch (IOException ignored) {
                                }
                            }
                        },
                        vtExec)
                .exceptionally(ex -> {
                    closeBoth.run();
                    return null;
                });

        CompletableFuture.allOf(c2u, u2c).whenComplete((v, ex) -> closeBoth.run());
    }

    // =====================================================================
    //  HTTP request forwarding
    // =====================================================================

    private void handleRequest(Request request, Response response, String method, String uri) throws Exception {
        logger.Debug("Forwarding %s request for %s", method, uri);
        String host = request.getHeader("Host");

        if (host == null || host.isEmpty()) {
            logger.Warning("Request with no Host header: %s %s", method, uri);
            sendError(response, 400, "Bad Request - no Host header");
            return;
        }

        int targetPort = uri.startsWith("https://") ? 443 : 80;
        String targetHost = host;
        int portSep = host.lastIndexOf(':');
        if (portSep > 0) {
            try {
                targetPort = Integer.parseInt(host.substring(portSep + 1));
                targetHost = host.substring(0, portSep);
            } catch (NumberFormatException ignored) {
            }
        }

        if (baselineProtocol == BaselineProtocol.WARP_MASQUE && warpTunnelOpener != null) {
            handleRequestViaWarpTunnel(request, response, method, uri, targetHost, targetPort);
            return;
        }

        Socket upstream = null;
        try {
            upstream = borrowHttpSocket();
            OutputStream upOut = upstream.getOutputStream();
            InputStream upIn = upstream.getInputStream();

            Map<String, String> reqHeaders = new LinkedHashMap<>();
            for (String name : request.getHeaderNames())
                if (!HOP_BY_HOP.contains(name) && !"Host".equalsIgnoreCase(name))
                    reqHeaders.put(name, request.getHeader(name));
            String auth = authProvider.get();
            if (auth != null && !auth.isEmpty()) reqHeaders.put("Proxy-Authorization", auth);

            long contentLen = request.getContentLengthLong();
            String reqUri = request.getRequestURI();
            String path =
                    reqUri.startsWith("http://") || reqUri.startsWith("https://") ? reqUri : "http://" + host + reqUri;

            sendHttpRequest(upOut, method, path, host, reqHeaders, request.getInputStream(), contentLen);

            HttpResponseParser parser = new HttpResponseParser(upIn, 65536);
            parser.parse();
            int statusCode = parser.getStatusCode();
            Map<String, List<String>> respHeaders = parser.getHeaders();
            InputStream bodyStream = parser.getBodyStream();

            response.setStatus(statusCode);
            for (var e : respHeaders.entrySet()) {
                String name = e.getKey();
                if ("Transfer-Encoding".equalsIgnoreCase(name))
                    for (String v : e.getValue()) response.addHeader(name, v);
                else if (!HOP_BY_HOP.contains(name) && !"Connection".equalsIgnoreCase(name))
                    for (String v : e.getValue()) response.addHeader(name, v);
            }
            InputStream decodedBody = decodeBody(bodyStream, respHeaders);
            OutputStream clientOut = response.getOutputStream();
            clientOut.flush();

            if (!"HEAD".equalsIgnoreCase(method) && !isStatusWithoutBody(statusCode)) {
                byte[] buf = new byte[RELAY_BUF_SIZE];
                int n;
                while ((n = decodedBody.read(buf)) != -1) clientOut.write(buf, 0, n);
            }
            clientOut.flush();

            if (!isStatusWithoutBody(statusCode) && !"HEAD".equalsIgnoreCase(method)) drain(decodedBody);
            boolean keepAlive = !isConnectionClose(respHeaders);
            if (keepAlive) releaseHttpSocket(upstream);
            else evictSocket(upstream);
            upstream = null;
        } catch (IOException e) {
            logger.Error("HTTP fetch error: %s", e.getMessage());
            if (upstream != null) evictSocket(upstream);
            sendError(response, 502, "Bad Gateway: " + e.getMessage());
        } finally {
            closeQuietly(upstream);
        }
    }

    private void handleRequestViaWarpTunnel(Request request, Response response, String method, String uri, String targetHost, int targetPort) throws Exception {
        logger.Debug("Forwarding via WARP tunnel: %s %s -> %s:%d", method, uri, targetHost, targetPort);
        TunnelConnection tunnel = null;
        try {
            tunnel = warpTunnelOpener.open(targetHost, targetPort);
            OutputStream tunnelOut = tunnel.outputStream();
            InputStream tunnelIn = tunnel.inputStream();

            long contentLen = request.getContentLengthLong();
            String reqUri = request.getRequestURI();
            String path = reqUri.startsWith("http://") || reqUri.startsWith("https://") ? reqUri : "http://" + targetHost + reqUri;

            Map<String, String> reqHeaders = new LinkedHashMap<>();
            for (String name : request.getHeaderNames()) {
                if (!HOP_BY_HOP.contains(name) && !"Host".equalsIgnoreCase(name)) {
                    reqHeaders.put(name, request.getHeader(name));
                }
            }

            sendHttpRequest(tunnelOut, method, path, targetHost, reqHeaders, request.getInputStream(), contentLen);

            HttpResponseParser parser = new HttpResponseParser(tunnelIn, 65536);
            parser.parse();
            int statusCode = parser.getStatusCode();
            Map<String, List<String>> respHeaders = parser.getHeaders();
            InputStream bodyStream = parser.getBodyStream();

            response.setStatus(statusCode);
            for (var e : respHeaders.entrySet()) {
                String name = e.getKey();
                if ("Transfer-Encoding".equalsIgnoreCase(name))
                    for (String v : e.getValue()) response.addHeader(name, v);
                else if (!HOP_BY_HOP.contains(name) && !"Connection".equalsIgnoreCase(name))
                    for (String v : e.getValue()) response.addHeader(name, v);
            }
            InputStream decodedBody = decodeBody(bodyStream, respHeaders);
            OutputStream clientOut = response.getOutputStream();
            clientOut.flush();

            if (!"HEAD".equalsIgnoreCase(method) && !isStatusWithoutBody(statusCode)) {
                byte[] buf = new byte[RELAY_BUF_SIZE];
                int n;
                while ((n = decodedBody.read(buf)) != -1) clientOut.write(buf, 0, n);
            }
            clientOut.flush();
        } catch (IOException e) {
            logger.Error("WARP HTTP fetch error: %s", e.getMessage());
            sendError(response, 502, "Bad Gateway: " + e.getMessage());
        } finally {
            if (tunnel != null) tunnel.close();
        }
    }

    // =====================================================================
    //  Shared helpers
    // =====================================================================

    public void sendHttpRequest(
            OutputStream out,
            String method,
            String uri,
            String host,
            Map<String, String> headers,
            InputStream bodyStream,
            long contentLen)
            throws IOException {
        StringBuilder sb = new StringBuilder(512);
        sb.append(method)
                .append(' ')
                .append(uri)
                .append(" HTTP/1.1\r\n")
                .append("Host: ")
                .append(host)
                .append("\r\n");
        for (var h : headers.entrySet())
            if (!"Content-Length".equalsIgnoreCase(h.getKey()))
                sb.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");
        if (contentLen > 0) sb.append("Content-Length: ").append(contentLen).append("\r\n");
        sb.append("Connection: keep-alive\r\n\r\n");
        out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        if (bodyStream != null && contentLen > 0) {
            byte[] buf = new byte[RELAY_BUF_SIZE];
            long remaining = contentLen;
            while (remaining > 0) {
                int toRead = (int) Math.min(buf.length, remaining);
                int n = bodyStream.read(buf, 0, toRead);
                if (n == -1) break;
                out.write(buf, 0, n);
                remaining -= n;
            }
        }
        out.flush();
    }

    public InputStream decodeBody(InputStream in, Map<String, List<String>> headers) {
        long cl = parseContentLength(headers);
        if (cl >= 0) return new LimitedInputStream(in, cl);
        if (isChunked(headers)) return new ChunkedDecodingInputStream(in);
        return new ReadUntilCloseInputStream(in);
    }

    private static long parseContentLength(Map<String, List<String>> headers) {
        List<String> cl = headers.get("Content-Length");
        if (cl != null && !cl.isEmpty())
            try {
                return Long.parseLong(cl.get(0).trim());
            } catch (NumberFormatException ignored) {
            }
        return -1;
    }

    private static boolean isChunked(Map<String, List<String>> headers) {
        List<String> te = headers.get("Transfer-Encoding");
        return te != null && te.stream().anyMatch(v -> "chunked".equalsIgnoreCase(v.trim()));
    }

    public static boolean isStatusWithoutBody(int status) {
        return (status >= 100 && status < 200) || status == 204 || status == 304;
    }

    public static boolean isConnectionClose(Map<String, List<String>> headers) {
        List<String> values = headers.get("Connection");
        return values != null && values.stream().anyMatch(v -> "close".equalsIgnoreCase(v.trim()));
    }

    // =====================================================================
    //  SSL / channel utilities
    // =====================================================================

    private static void flushSslEngine(SSLEngine engine, SocketChannel channel, ReentrantLock lock) throws IOException {
        ByteBuffer netOut = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
        ByteBuffer empty = ByteBuffer.allocate(0);
        lock.lock();
        try {
            while (true) {
                netOut.clear();
                SSLEngineResult result = engine.wrap(empty, netOut);
                netOut.flip();
                if (netOut.hasRemaining()) while (netOut.hasRemaining()) channel.write(netOut);
                if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) task.run();
                }
                SSLEngineResult.HandshakeStatus hstatus = engine.getHandshakeStatus();
                if (!netOut.hasRemaining()
                        && (hstatus == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
                                || hstatus == SSLEngineResult.HandshakeStatus.FINISHED)) break;
                if (result.getStatus() == SSLEngineResult.Status.CLOSED) break;
            }
        } finally {
            lock.unlock();
        }
    }

    private static SSLEngine getClientSslEngine(Request request) {
        org.glassfish.grizzly.Connection<?> conn = request.getContext().getConnection();
        if (conn instanceof NIOConnection nioConn) {
            SSLConnectionContext sslCtx = SSLUtils.getSslConnectionContext(nioConn);
            if (sslCtx != null) return sslCtx.getSslEngine();
        }
        return null;
    }

    private SocketChannel detachClientChannel(Request request) throws IOException {
        org.glassfish.grizzly.Connection<?> conn = request.getContext().getConnection();
        if (!(conn instanceof NIOConnection nioConn)) throw new IllegalStateException("Connection is not NIO");
        SocketChannel ch = (SocketChannel) nioConn.getChannel();
        if (nioConn.getSelectionKey() != null) nioConn.getSelectionKey().cancel();
        ch.configureBlocking(true);
        return ch;
    }

    // =====================================================================
    //  HTTP/1.1 MITM helpers
    // =====================================================================

    public static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        while (true) {
            int cur = in.read();
            if (cur == -1) {
                if (buf.size() == 0) return null;
                break;
            }
            if (cur == '\n') {
                byte[] data = buf.toByteArray();
                if (data.length > 0 && data[data.length - 1] == '\r')
                    return new String(data, 0, data.length - 1, StandardCharsets.US_ASCII);
                break;
            }
            buf.write(cur);
        }
        return buf.toString(StandardCharsets.US_ASCII);
    }

    public static void sendErrorLine(OutputStream out, int status, String msg) {
        try {
            String resp = "HTTP/1.1 " + status + " " + msg + "\r\nConnection: close\r\n\r\n";
            out.write(resp.getBytes(StandardCharsets.US_ASCII));
            out.flush();
        } catch (IOException ignored) {
        }
    }

    /**
     * Inner-tunnel HTTP/1.1 forwarder.  Reads one HTTP/1.1 request at
     * a time from {@code innerIn}, forwards it through {@code tunnel},
     * and writes the response (decoded, hop-by-hop stripped) back to
     * {@code innerOut}.
     *
     * <p>Used by the h1-over-CONNECT and h2-over-CONNECT (fallback)
     * MITM paths when ALPN negotiates {@code http/1.1}.
     */
    public void relayHttp1(InputStream innerIn, OutputStream innerOut, TunnelConnection tunnel, String host, int port)
            throws IOException {
        while (true) {
            String requestLine = readLine(innerIn);
            if (requestLine == null || requestLine.isEmpty()) return;
            logger.Debug("MITM request: %s", requestLine);
            String[] reqParts = requestLine.split(" ", 3);
            if (reqParts.length < 3) return;
            String method = reqParts[0];
            String uri = reqParts[1];

            Map<String, List<String>> rawHeaders = new LinkedHashMap<>();
            String headerLine;
            while (!(headerLine = readLine(innerIn)).isEmpty()) {
                int colon = headerLine.indexOf(':');
                if (colon > 0) {
                    String name = headerLine.substring(0, colon).trim();
                    String value = headerLine.substring(colon + 1).trim();
                    rawHeaders.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
                }
            }

            long contentLen = -1;
            boolean isChunked = false;
            for (var e : rawHeaders.entrySet()) {
                if ("content-length".equalsIgnoreCase(e.getKey())) {
                    try {
                        contentLen = Long.parseLong(e.getValue().get(0));
                    } catch (NumberFormatException ignored) {
                    }
                } else if ("transfer-encoding".equalsIgnoreCase(e.getKey())) {
                    for (String v : e.getValue()) if ("chunked".equalsIgnoreCase(v.trim())) isChunked = true;
                }
            }

            InputStream bodyStream = null;
            if (isChunked)
                bodyStream =
                        new com.platypus.proxy.io.ChunkedDecodingInputStream(new java.io.BufferedInputStream(innerIn));
            else if (contentLen > 0) bodyStream = new com.platypus.proxy.io.LimitedInputStream(innerIn, contentLen);

            String originPath;
            if (uri.startsWith("http://") || uri.startsWith("https://")) {
                int idx = uri.indexOf("://");
                int pathStart = uri.indexOf('/', idx + 3);
                originPath = (pathStart >= 0) ? uri.substring(pathStart) : "/";
            } else {
                originPath = uri;
            }

            try {
                OutputStream upOut = tunnel.socket().getOutputStream();
                InputStream upIn = tunnel.inputStream();

                Map<String, String> reqHeaders = new LinkedHashMap<>();
                for (var e : rawHeaders.entrySet())
                    if (!HOP_BY_HOP.contains(e.getKey()) && !"Host".equalsIgnoreCase(e.getKey()))
                        reqHeaders.put(e.getKey(), e.getValue().get(0));
                String auth = authProvider.get();
                if (auth != null && !auth.isEmpty()) reqHeaders.put("Proxy-Authorization", auth);

                byte[] bodyBytes = null;
                if (bodyStream != null && isChunked) {
                    bodyBytes = ProxyHandler.readAllBytes(bodyStream);
                    bodyStream = null;
                    contentLen = bodyBytes.length;
                }

                sendHttpRequest(
                        upOut,
                        method,
                        originPath,
                        host,
                        reqHeaders,
                        bodyStream != null
                                ? bodyStream
                                : (bodyBytes != null ? new ByteArrayInputStream(bodyBytes) : null),
                        bodyBytes != null ? bodyBytes.length : contentLen);

                com.platypus.proxy.handler.http.HttpResponseParser parser =
                        new com.platypus.proxy.handler.http.HttpResponseParser(upIn, 65536);
                parser.parse();
                int statusCode = parser.getStatusCode();
                Map<String, List<String>> respHeaders = parser.getHeaders();
                InputStream respBody = parser.getBodyStream();

                StringBuilder respBuilder = new StringBuilder(256);
                respBuilder
                        .append("HTTP/1.1 ")
                        .append(statusCode)
                        .append(' ')
                        .append(getReasonPhrase(statusCode))
                        .append("\r\n");

                boolean upstreamChunked = false;
                for (var e : respHeaders.entrySet()) {
                    String name = e.getKey();
                    if (HOP_BY_HOP.contains(name) || "Connection".equalsIgnoreCase(name)) continue;
                    if ("transfer-encoding".equalsIgnoreCase(name)) {
                        for (String v : e.getValue()) if ("chunked".equalsIgnoreCase(v.trim())) upstreamChunked = true;
                    }
                    for (String v : e.getValue())
                        respBuilder.append(name).append(": ").append(v).append("\r\n");
                }

                boolean closeConnection = isConnectionClose(respHeaders);
                respBuilder
                        .append(closeConnection ? "Connection: close\r\n" : "Connection: keep-alive\r\n")
                        .append("\r\n");

                innerOut.write(respBuilder.toString().getBytes(StandardCharsets.UTF_8));
                innerOut.flush();

                InputStream decodedBody = decodeBody(respBody, respHeaders);

                OutputStream writeTo = innerOut;
                com.platypus.proxy.io.ChunkedOutputStream chunkedOut = null;
                if (upstreamChunked) {
                    chunkedOut = new com.platypus.proxy.io.ChunkedOutputStream(innerOut);
                    writeTo = chunkedOut;
                }

                byte[] buf = new byte[RELAY_BUF_SIZE];
                int n;
                while ((n = decodedBody.read(buf)) != -1) writeTo.write(buf, 0, n);
                if (chunkedOut != null) chunkedOut.close();
                innerOut.flush();

                if (closeConnection) return;
            } catch (Exception e) {
                logger.Error("MITM forward error: %s", e.getMessage());
                sendErrorLine(innerOut, 502, "Bad Gateway");
                return;
            }
        }
    }

    /**
     * Read all remaining bytes from {@code in} into a byte array.
     * Used for chunked bodies that need to be materialised before the
     * upstream request can be issued.
     */
    public static byte[] readAllBytes(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[RELAY_BUF_SIZE];
        int n;
        while ((n = in.read(buf)) != -1) baos.write(buf, 0, n);
        return baos.toByteArray();
    }

    public static String getReasonPhrase(int code) {
        return switch (code) {
            case 200 -> "OK";
            case 201 -> "Created";
            case 204 -> "No Content";
            case 301 -> "Moved Permanently";
            case 302 -> "Found";
            case 303 -> "See Other";
            case 304 -> "Not Modified";
            case 307 -> "Temporary Redirect";
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            case 500 -> "Internal Server Error";
            case 502 -> "Bad Gateway";
            case 503 -> "Service Unavailable";
            default -> "Unknown";
        };
    }

    // =====================================================================
    //  Misc
    // =====================================================================

    private static void tuneClientSocket(Socket socket) throws SocketException {
        socket.setSoTimeout(30_000);
        socket.setTcpNoDelay(true);
        socket.setReceiveBufferSize(2048 * 1024);
        socket.setSendBufferSize(2048 * 1024);
    }

    private static void drain(InputStream in) {
        try {
            while (in.read() != -1)
                ;
        } catch (IOException ignored) {
        }
    }

    private static void sendError(Response response, int status, String msg) {
        if (response.isCommitted()) return;
        try {
            response.setStatus(status);
            response.setContentType("text/plain");
            response.getWriter().write(msg);
        } catch (Exception ignored) {
        }
    }

    public static void closeQuietly(Socket s) {
        try {
            if (s != null) s.close();
        } catch (Exception ignored) {
        }
    }

    private static void closeQuietly(SocketChannel ch) {
        try {
            if (ch != null) ch.close();
        } catch (Exception ignored) {
        }
    }

    @SuppressWarnings("unused")
    private static void closeQuietly(InputStream in) {
        try {
            if (in != null) in.close();
        } catch (IOException ignored) {
        }
    }

    @SuppressWarnings("unused")
    private static void closeQuietly(OutputStream out) {
        try {
            if (out != null) out.close();
        } catch (IOException ignored) {
        }
    }

    public static void closeQuietly(TunnelConnection tunnel) {
        try {
            if (tunnel != null) tunnel.close();
        } catch (Exception ignored) {
        }
    }
}
