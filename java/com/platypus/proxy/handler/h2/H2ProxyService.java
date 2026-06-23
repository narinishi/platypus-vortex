package com.platypus.proxy.handler.h2;

import com.platypus.proxy.handler.ConnectUtil;
import com.platypus.proxy.handler.Endpoint;
import com.platypus.proxy.handler.ProxyHandler;
import com.platypus.proxy.handler.TlsHelper;
import com.platypus.proxy.handler.http.HttpHeaders;
import com.platypus.proxy.handler.http.HttpStatusConsumesHeaders;
import com.platypus.proxy.handler.protocol.OutboundProtocol;
import com.platypus.proxy.io.ChunkedDecodingInputStream;
import com.platypus.proxy.io.LimitedInputStream;
import com.platypus.proxy.io.ReadUntilCloseInputStream;
import com.platypus.proxy.io.TunnelConnection;
import com.platypus.proxy.io.TunnelOpener;
import com.platypus.proxy.logging.CondLogger;
import com.platypus.proxy.resolver.LookupNetIP;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.io.UncheckedIOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

/**
 * H2-specific proxy service: holds configuration, an {@link H2UpstreamPool},
 * and all the h2-specific logic that was previously spread across
 * {@link com.platypus.proxy.handler.ProxyHandler}.
 *
 * <p>RFC 9113 §8.3.1 request pseudo-headers; RFC 9113 §8.2.2 connection-specific headers.
 *
 * <p>This class is the single dependency for all code in the
 * {@code h2} package.  It does NOT use ProxyHandler's pooling
 * infrastructure ({@code socketPermits}, {@code leasedSockets},
 * {@code tunnelIdle}, {@code httpIdle}); instead it uses its own
 * {@link H2UpstreamPool}.
 */
public final class H2ProxyService implements AutoCloseable {

    // =====================================================================
    //  TunnelSupplier interface (moved from ProxyHandler)
    // =====================================================================

    public interface TunnelSupplier {
        H2TunnelConnection open(String host, int port) throws IOException;
    }

    // =====================================================================
    //  Constants (ported from ProxyHandler)
    // =====================================================================

    // RFC 9113 §8.2.2 -- connection-specific headers MUST NOT be forwarded
    public static final int RELAY_BUF_SIZE = 1024 * 1024;

    public static final Set<String> HOP_BY_HOP =
            Set.of("connection", "keep-alive", "proxy-authenticate", "proxy-connection", "te", "trailers", "upgrade");

    private static final int RECV_BUF_SIZE = 2048 * 1024;
    private static final int SEND_BUF_SIZE = 2048 * 1024;

    // =====================================================================
    //  Configuration fields
    // =====================================================================

    private final String baselineHost;
    private final int baselinePort;
    private final String tlsServerName;
    private final boolean tlsToBaseline;
    private final boolean hideSNI;
    private final CondLogger logger;
    private final boolean directDns;
    private final LookupNetIP directResolver;
    private final boolean mitmEnabled;
    public final Supplier<String> authProvider;
    private final ProxyHandler.ChainedProxyConfig chainedProxyConfig;

    // Optional WARP MASQUE tunnel opener. When set, all upstream TCP dials
    // (TCP CONNECT, MITM TLS dial, openTcpConnectionTo, passthrough) are
    // routed through WARP MASQUE instead of a direct Socket. Mirrors the
    // ProxyHandler.setWarpTunnelOpener() hook used for HTTP/1.1 mode.
    private TunnelOpener warpTunnelOpener;
    private WarpTunnelPool warpPool;

    // =====================================================================
    //  Pool
    // =====================================================================

    private final H2UpstreamPool pool;

    // =====================================================================
    //  Chained proxy config (ported from ProxyHandler.ChainedProxyConfig)
    // =====================================================================

    public record ChainedProxyConfig(
            String host, int port, OutboundProtocol type, boolean remoteDns, Supplier<String> auth) {}

    // =====================================================================
    //  Constructor
    // =====================================================================

    public H2ProxyService(
            Endpoint endpoint,
            Supplier<String> authProvider,
            boolean hideSNI,
            String outboundProxyUrl,
            CondLogger logger,
            boolean directDns,
            LookupNetIP directResolver,
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
        this.mitmEnabled = mitmEnabled;
        this.pool = new H2UpstreamPool(logger);

        if (outboundProxyUrl != null && !outboundProxyUrl.isEmpty()) {
            this.chainedProxyConfig = ConnectUtil.parseOutboundProxy(outboundProxyUrl);
        } else {
            this.chainedProxyConfig = null;
        }
    }

    // Wire the WARP MASQUE upstream opener. When set, all upstream TCP
    // dials inside the h2 subsystem (MitmTunnelConnector, connectTunnelForMitm,
    // openTcpConnectionTo, passthrough) are routed through WARP rather than
    // direct sockets. Set once at startup; null means "no WARP backend".
    public void setWarpTunnelOpener(TunnelOpener opener) {
        this.warpTunnelOpener = opener;
        if (opener != null) {
            this.warpPool = new WarpTunnelPool(this);
            logger.Info("[H2] WARP MASQUE tunnel opener configured (pool enabled)");
        } else {
            if (this.warpPool != null) this.warpPool.clear();
            this.warpPool = null;
            logger.Info("[H2] WARP MASQUE tunnel opener cleared");
        }
    }

    public TunnelOpener warpTunnelOpener() { return warpTunnelOpener; }

    public boolean hasWarpTunnelOpener() { return warpTunnelOpener != null; }

    /**
     * Open a TCP tunnel via WARP MASQUE and return it as an
     * {@link H2TunnelConnection}. The returned tunnel wraps the WARP
     * stream pair in an anonymous Socket so the rest of the h2 upstream
     * code (which expects socket()-style IO and TLS wrapping) can treat
     * it like any other TCP connection.
     *
     * <p>Pool is null: WARP tunnels are not pooled because the MASQUE
     * endpoint establishes a fresh QUIC stream per CONNECT request.
     * Closing the returned H2TunnelConnection simply closes the WARP
     * tunnel.
     */
    public H2TunnelConnection openWarpTunnel(String host, int port) throws IOException {
        if (warpTunnelOpener == null) {
            throw new IOException("WARP tunnel opener not configured");
        }
        TunnelConnection tunnel = warpTunnelOpener.open(host, port);
        if (tunnel == null) {
            throw new IOException("WARP tunnel opener returned null for " + host + ":" + port);
        }
        return wrapTunnelAsH2(tunnel, host, port);
    }

    /**
     * Wrap a generic stream-based {@link TunnelConnection} into an
     * {@link H2TunnelConnection} backed by an anonymous Socket. Used for
     * WARP MASQUE tunnels (and could be reused for any other tunnel that
     * surfaces its IO as InputStream/OutputStream).
     *
     * <p>The anonymous Socket is needed because:
     * <ul>
     *   <li>{@link SSLSocketFactory#createSocket(Socket, ...)} requires a
     *       Socket for TLS wrapping in MITM mode.</li>
     *   <li>The rest of H2ProxyService assumes socket-based IO
     *       ({@code tunnel.socket().getOutputStream()}).</li>
     * </ul>
     */
    public static H2TunnelConnection wrapTunnelAsH2(TunnelConnection tunnel, String host, int port) {
        InputStream in = tunnel.inputStream();
        OutputStream out = tunnel.outputStream();
        Socket wrapped = new Socket() {
            @Override public OutputStream getOutputStream() { return out; }
            @Override public InputStream getInputStream() { return in; }
            @Override public void close() throws IOException { tunnel.close(); }
            @Override public boolean isClosed() { return false; }
            @Override public boolean isConnected() { return true; }
            @Override public java.net.InetAddress getInetAddress() {
                try { return java.net.InetAddress.getByName(host); }
                catch (UnknownHostException e) { return null; }
            }
            @Override public int getPort() { return port; }
            @Override public java.nio.channels.SocketChannel getChannel() { return null; }
            @Override public void setSoTimeout(int timeout) { /* WARP tunnel: no SO_TIMEOUT concept */ }
            @Override public int getSoTimeout() { return 0; }
        };
        return new H2TunnelConnection(wrapped, in, null, null);
    }

    // =====================================================================
    //  Accessors
    // =====================================================================

    public CondLogger logger() { return logger; }
    public boolean isMitmEnabled() { return mitmEnabled; }
    public H2UpstreamPool pool() { return pool; }
    public void releaseOwnedSocket(Socket socket) { pool.releaseOwnedSocket(socket); }

    // =====================================================================
    //  DNS resolution
    // =====================================================================

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

    // =====================================================================
    //  CONNECT tunnel establishment
    // =====================================================================

    // RFC 9113 §8.5 CONNECT method -- establish TCP tunnel to origin
    public H2TunnelConnection connectTunnelForMitm(String targetHost, int targetPort) throws IOException {
        return connectTunnelForMitmResolved(targetHost, resolveForDirectDns(targetHost), targetPort);
    }

    // RFC 9113 §8.5 -- CONNECT with resolved address; HTTP/1.1 CONNECT handshake
    public H2TunnelConnection connectTunnelForMitmResolved(String originalHost, String resolvedHost, int targetPort)
            throws IOException {
        // WARP backend: the dial itself IS the tunnel. No CONNECT handshake
        // required because WARP MASQUE's openTunnel() returns a ready TCP
        // stream. Skip the pool entirely.
        if (warpTunnelOpener != null) {
            logger.Debug("[H2] connectTunnelForMitm via WARP: %s:%d (resolved=%s)", originalHost, targetPort, resolvedHost);
            return openWarpTunnel(resolvedHost, targetPort);
        }
        try {
            if (!pool.tryAcquireGlobalPermit(5000)) {
                throw new IOException("H2 pool: timeout acquiring global permit for " + originalHost + ":" + targetPort);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted");
        }
        Socket sock;
        try {
            sock = createBaselineSocket();
            pool.track(sock);
        } catch (IOException e) {
            pool.releaseGlobalPermit();
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
            return new H2TunnelConnection(sock, pin, pool);
        } catch (IOException e) {
            pool.releaseOwnedSocket(sock);
            throw e;
        }
    }

    // =====================================================================
    //  Raw / direct socket helpers
    // =====================================================================

    public H2TunnelConnection openTcpConnectionTo(String targetHost, int targetPort) throws IOException {
        // Route through WARP MASQUE when a tunnel opener is configured
        // (matches ProxyHandler.handleRequestViaWarpTunnel pattern). This
        // preserves the chained-proxy fallback for HTTP/SOCKS5 outbound.
        if (warpTunnelOpener != null) {
            logger.Debug("[H2] openTcpConnectionTo via WARP: %s:%d", targetHost, targetPort);
            return openWarpTunnel(targetHost, targetPort);
        }
        Socket socket;
        if (chainedProxyConfig != null) {
            socket = dialThroughOutboundProxy(targetHost, targetPort);
        } else {
            socket = new Socket(targetHost, targetPort);
            socket.setTcpNoDelay(true);
        }
        return new H2TunnelConnection(socket, socket.getInputStream(), pool);
    }

    private Socket createBaselineSocket() throws IOException {
        Socket sock;
        if (chainedProxyConfig != null) {
            sock = dialThroughOutboundProxy(baselineHost, baselinePort);
        } else {
            // NOTE: DNS resolution occurs
            sock = new Socket(baselineHost, baselinePort);
        }
        sock.setTcpNoDelay(true);
        sock.setReceiveBufferSize(RECV_BUF_SIZE);
        sock.setSendBufferSize(SEND_BUF_SIZE);
        return sock;
    }

    private Socket dialThroughOutboundProxy(String targetHost, int targetPort) throws IOException {
        if (chainedProxyConfig == null) {
            return new Socket(targetHost, targetPort);
        }

        Socket proxySock = new Socket(chainedProxyConfig.host(), chainedProxyConfig.port());
        proxySock.setTcpNoDelay(true);

        if (chainedProxyConfig.type() == OutboundProtocol.HTTP
                || chainedProxyConfig.type() == OutboundProtocol.HTTPS) {
            if (chainedProxyConfig.type() == OutboundProtocol.HTTPS) {
                proxySock = TlsHelper.wrap(proxySock, chainedProxyConfig.host(), false);
            }
            String connectReq = ConnectUtil.buildConnectRequest(targetHost, targetPort, chainedProxyConfig.auth());
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
        } else if (chainedProxyConfig.type() == OutboundProtocol.SOCKS5) {
            com.platypus.proxy.handler.protocol.Socks5Helper.handshake(
                    proxySock, targetHost, targetPort, chainedProxyConfig.remoteDns(), chainedProxyConfig.auth());
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
    //  Passthrough (non-HTTP ports)
    // =====================================================================

    public void passthrough(
            SSLEngineInputStream outerIn,
            SSLEngineOutputStream outerOut,
            String host,
            int port,
            java.nio.channels.SocketChannel clientCh) {
        H2TunnelConnection tunnel;
        try {
            tunnel = connectTunnelForMitm(host, port);
        } catch (IOException e) {
            logger.Error("passthrough: CONNECT to %s:%d failed: %s", host, port, e.getMessage());
            return;
        }
        java.util.concurrent.atomic.AtomicBoolean done = new java.util.concurrent.atomic.AtomicBoolean(false);
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
    //  HTTP/1.1 request forwarding (ported from ProxyHandler)
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
        sendHttpRequest(out, method, uri, host, headers, bodyStream, contentLen, null);
    }

    // RFC 9112 §3 HTTP/1.1 request-line; connection reuse via "Connection: keep-alive"
    public void sendHttpRequest(
            OutputStream out,
            String method,
            String uri,
            String host,
            Map<String, String> headers,
            InputStream bodyStream,
            long contentLen,
            String connectionValue)
            throws IOException {
        boolean hasConnection = false;
        StringBuilder sb = new StringBuilder(512);
        sb.append(method)
                .append(' ')
                .append(uri)
                .append(" HTTP/1.1\r\n")
                .append("Host: ")
                .append(host)
                .append("\r\n");
        for (var h : headers.entrySet()) {
            if (!"Content-Length".equalsIgnoreCase(h.getKey())) {
                sb.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");
            }
            if ("Connection".equalsIgnoreCase(h.getKey())) hasConnection = true;
        }
        if (contentLen >= 0) sb.append("Content-Length: ").append(contentLen).append("\r\n");
        if (connectionValue != null) {
            sb.append("Connection: ").append(connectionValue).append("\r\n\r\n");
        } else if (!hasConnection) {
            sb.append("Connection: keep-alive\r\n\r\n");
        } else {
            sb.append("\r\n");
        }
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

    // RFC 9113 §8.1 body framing -- Content-Length, chunked (RFC 9112 §7), or read-until-close
    public InputStream decodeBody(InputStream in, Map<String, List<String>> headers) {
        long cl = parseContentLength(headers);
        if (cl >= 0) return new LimitedInputStream(in, cl);
        if (isChunked(headers)) return new ChunkedDecodingInputStream(in);
        return new ReadUntilCloseInputStream(in);
    }

    private static long parseContentLength(Map<String, List<String>> headers) {
        for (var e : headers.entrySet()) {
            if ("content-length".equalsIgnoreCase(e.getKey())) {
                try {
                    return Long.parseLong(e.getValue().get(0).trim());
                } catch (NumberFormatException ignored) {
                }
                break;
            }
        }
        return -1;
    }

    private static boolean isChunked(Map<String, List<String>> headers) {
        for (var e : headers.entrySet()) {
            if ("transfer-encoding".equalsIgnoreCase(e.getKey())) {
                return e.getValue().stream().anyMatch(v -> "chunked".equalsIgnoreCase(v.trim()));
            }
        }
        return false;
    }

    public static boolean isStatusWithoutBody(int status) {
        return (status >= 100 && status < 200) || status == 204 || status == 304;
    }

    // RFC 9112 §9.6 -- Connection: close terminates persistent connection
    public static boolean isConnectionClose(Map<String, List<String>> headers) {
        for (var e : headers.entrySet()) {
            if ("connection".equalsIgnoreCase(e.getKey())) {
                return e.getValue().stream().anyMatch(v -> "close".equalsIgnoreCase(v.trim()));
            }
        }
        return false;
    }

    // =====================================================================
    //  HTTP/1.1 MITM relay (ported from ProxyHandler.relayHttp1)
    // =====================================================================

    // RFC 9113 §8.6 upgrade not supported; WebSocket upgrade per RFC 8441 via Extended CONNECT
    // This method bridges HTTP/1.1 MITM tunnel to upstream via HTTP/1.1 proxying
    public boolean relayHttp1(InputStream innerIn, OutputStream innerOut, H2TunnelConnection tunnel, String host, int port)
            throws IOException {
        while (true) {
            String requestLine = readLine(innerIn);
            if (requestLine == null || requestLine.isEmpty()) return true;
            logger.Debug("MITM request: %s", requestLine);
            String[] reqParts = requestLine.split(" ", 3);
            if (reqParts.length < 3) return true;
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

            boolean isWebSocket = isWebSocketUpgrade(rawHeaders);
            logger.Debug("MITM request: %s %s ws=%b", method, uri, isWebSocket);

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
                String reqConnection = null;
                for (var e : rawHeaders.entrySet()) {
                    String name = e.getKey();
                    if (!"Host".equalsIgnoreCase(name)) {
                        if (isWebSocket && ("Upgrade".equalsIgnoreCase(name) || "Connection".equalsIgnoreCase(name))) {
                            reqHeaders.put(name, e.getValue().get(0));
                        } else if (!HOP_BY_HOP.contains(name)) {
                            reqHeaders.put(name, e.getValue().get(0));
                        }
                    }
                    if ("Connection".equalsIgnoreCase(name)) reqConnection = e.getValue().get(0);
                }
                if (isWebSocket && reqConnection == null) reqConnection = "Upgrade";
                String auth = authProvider.get();
                if (auth != null && !auth.isEmpty()) reqHeaders.put("Proxy-Authorization", auth);

                byte[] bodyBytes = null;
                if (bodyStream != null && isChunked) {
                    bodyBytes = readAllBytes(bodyStream);
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
                        bodyBytes != null ? bodyBytes.length : contentLen,
                        reqConnection);

                com.platypus.proxy.handler.http.HttpResponseParser parser =
                        new com.platypus.proxy.handler.http.HttpResponseParser(upIn, 65536);
                parser.parse();
                int statusCode = parser.getStatusCode();
                Map<String, List<String>> respHeaders = parser.getHeaders();
                InputStream respBody = parser.getBodyStream();

                if (isWebSocket && statusCode == 101) {
                    logger.Debug("MITM WS upgrade accepted to %s:%d", host, port);
                    StringBuilder wsResp = new StringBuilder(256);
                    wsResp.append("HTTP/1.1 101 Switching Protocols\r\n");
                    for (var e : respHeaders.entrySet()) {
                        if ("Transfer-Encoding".equalsIgnoreCase(e.getKey()) || "Content-Length".equalsIgnoreCase(e.getKey()))
                            continue;
                        for (String v : e.getValue())
                            wsResp.append(e.getKey()).append(": ").append(v).append("\r\n");
                    }
                    wsResp.append("\r\n");
                    innerOut.write(wsResp.toString().getBytes(StandardCharsets.UTF_8));
                    innerOut.flush();
                    relayBidirectional(innerIn, innerOut, upIn, upOut);
                    return false;
                }

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

                if (closeConnection) return false;
            } catch (Exception e) {
                logger.Error("MITM forward error: %s", e.getMessage());
                sendErrorLine(innerOut, 502, "Bad Gateway");
                return false;
            }
        }
    }

    private static boolean isWebSocketUpgrade(Map<String, List<String>> headers) {
        for (var e : headers.entrySet()) {
            if ("Upgrade".equalsIgnoreCase(e.getKey())) {
                for (String v : e.getValue()) if ("websocket".equalsIgnoreCase(v.trim())) return true;
            }
        }
        return false;
    }

    private static void relayBidirectional(InputStream clientIn, OutputStream clientOut,
                                            InputStream upstreamIn, OutputStream upstreamOut) {
        AtomicBoolean done = new AtomicBoolean(false);
        Thread upstreamToClient = new Thread(() -> {
            byte[] buf = new byte[RELAY_BUF_SIZE];
            try {
                int n;
                while (!done.get() && (n = upstreamIn.read(buf)) != -1) {
                    clientOut.write(buf, 0, n);
                    clientOut.flush();
                }
            } catch (IOException ignored) {
            } finally {
                done.set(true);
            }
        }, "mitm-ws-upstream-" + Thread.currentThread().getName());
        upstreamToClient.setDaemon(true);
        upstreamToClient.start();
        byte[] buf = new byte[RELAY_BUF_SIZE];
        try {
            int n;
            while (!done.get() && (n = clientIn.read(buf)) != -1) {
                upstreamOut.write(buf, 0, n);
                upstreamOut.flush();
            }
        } catch (IOException ignored) {
        } finally {
            done.set(true);
        }
    }

    // =====================================================================
    //  HTTP/1.1 line helpers (static, ported from ProxyHandler)
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

    public static byte[] readAllBytes(InputStream in) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
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
    //  Inner TLS handshake (static, ported from ProxyHandler)
    // =====================================================================

    // RFC 5246 §7.3 / RFC 8446 §4 -- full TLS handshake; collects stray app data for early decryption
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
            switch (engine.getHandshakeStatus()) {
                case NEED_WRAP: {
                    netOut.clear();
                    SSLEngineResult wr = engine.wrap(ByteBuffer.allocate(0), netOut);
                    netOut.flip();
                    switch (wr.getStatus()) {
                        case BUFFER_UNDERFLOW:
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

    // RFC 5246 §6.2.1 / RFC 8446 §5.1 -- TLS record layer: 5-byte header (type, version, length)
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
    //  Misc utilities (ported from ProxyHandler)
    // =====================================================================

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

    public static void closeQuietly(Socket s) {
        try {
            if (s != null) s.close();
        } catch (Exception ignored) {
        }
    }

    public static void closeQuietly(H2TunnelConnection tunnel) {
        try {
            if (tunnel != null) tunnel.close();
        } catch (Exception ignored) {
        }
    }

    // =====================================================================
    //  Lifecycle
    // =====================================================================

    public WarpTunnelPool warpPool() { return warpPool; }

    @Override
    public void close() {
        if (warpPool != null) warpPool.clear();
        pool.close();
    }
}
