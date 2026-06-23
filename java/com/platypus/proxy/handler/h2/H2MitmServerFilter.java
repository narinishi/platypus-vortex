package com.platypus.proxy.handler.h2;

import com.platypus.proxy.ProxyApplication;
// TunnelConnection import removed -- using H2TunnelConnection

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.Connection;
import org.glassfish.grizzly.filterchain.FilterChainContext;
import org.glassfish.grizzly.filterchain.NextAction;
import org.glassfish.grizzly.http.HttpContent;
import org.glassfish.grizzly.http.HttpRequestPacket;
import org.glassfish.grizzly.http2.Http2Configuration;
import org.glassfish.grizzly.http2.Http2ServerFilter;
import org.glassfish.grizzly.http2.Http2Session;
import org.glassfish.grizzly.http2.Http2Stream;
import org.glassfish.grizzly.http2.frames.ContinuationFrame;
import org.glassfish.grizzly.http2.frames.DataFrame;
import org.glassfish.grizzly.http2.frames.ErrorCode;
import org.glassfish.grizzly.http2.frames.HeaderBlockHead;
import org.glassfish.grizzly.http2.frames.HeadersFrame;
import org.glassfish.grizzly.http2.frames.RstStreamFrame;
import org.glassfish.grizzly.http2.frames.Http2Frame;
import org.glassfish.grizzly.http2.frames.WindowUpdateFrame;
import org.glassfish.grizzly.http2.hpack.Encoder;
import org.glassfish.grizzly.memory.MemoryManager;
import org.glassfish.grizzly.ssl.SSLUtils;

// RFC 9113 §3.2 starting H2 for https URIs -- ALPN h2 detection, session creation
// RFC 9113 §9.2 TLS features -- SNI logging; RFC 7301 ALPN negotiation
public class H2MitmServerFilter extends Http2ServerFilter {

    private static final String ATTR_TUNNEL = "mitm.tunnel";
    private static final String ATTR_SNI_LOGGED = "mitm.sniLogged";

    private final H2ProxyService proxyService;
    private final ExecutorService virtualThreadExecutor;

    public H2MitmServerFilter(Http2Configuration config, H2ProxyService proxyService) {
        super(config);
        this.proxyService = proxyService;
        ExecutorService exec = config.getExecutorService();
        this.virtualThreadExecutor =
                exec != null ? exec : java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor();
        ProxyApplication.getLogger().Info("[H2-FILTER] Created H2MitmServerFilter");
    }

    private byte[] toByteArray(Buffer buf) {
        byte[] data = new byte[buf.remaining()];
        buf.get(data);
        return data;
    }

    private void logTlsSniIfNeeded(Connection<?> connection, Buffer buffer) {
        if (Boolean.TRUE.equals(connection.getAttributes().getAttribute(ATTR_SNI_LOGGED))) {
            return;
        }
        String sni = TlsSniExtractor.extract(buffer);
        if (sni == null || sni.isEmpty()) {
            return;
        }
        connection.getAttributes().setAttribute(ATTR_SNI_LOGGED, Boolean.TRUE);
        ProxyApplication.getLogger().Info("[TLS-SNI] client SNI host=%s", sni);
    }

    // RFC 7301 §3.1 -- detect ALPN h2 via engine.getApplicationProtocol(); RFC 9113 §3.2
    @Override
    public NextAction handleRead(FilterChainContext ctx) throws IOException {
        Object message = ctx.getMessage();
        if (message instanceof Buffer buffer) {
            Connection<?> conn = ctx.getConnection();
            logTlsSniIfNeeded(conn, buffer);
            SSLEngine engine = SSLUtils.getSSLEngine(conn);
            if (engine != null && "h2".equals(engine.getApplicationProtocol())
                    && Http2Session.get(conn) == null) {
                ProxyApplication.getLogger().Info(
                        "[H2-FILTER] JDK ALPN=h2, creating H2 session on %s",
                        conn.getPeerAddress());
                Http2Session h2s = createHttp2Session(conn, true);
                ProxyApplication.getLogger().Info(
                        "[H2-FILTER] H2 session created, id=%s",
                        h2s.hashCode());
            }
            return ctx.getInvokeAction();
        }
        if (message instanceof HttpContent) {
            Http2Session existing = Http2Session.get(ctx.getConnection());
            ProxyApplication.getLogger().Info(
                    "[H2-FILTER] HttpContent recv, session=%s",
                    existing != null ? ("id=" + existing.hashCode()) : "null");
        }
        return super.handleRead(ctx);
    }

    @Override
    protected void onHttpHeadersParsed(
            org.glassfish.grizzly.http.HttpHeader httpHeader, FilterChainContext ctx) {
        super.onHttpHeadersParsed(httpHeader, ctx);
    }

    // RFC 9113 §8.3.1 request pseudo-headers -- route GET /h2health, CONNECT, or forward
    @Override
    protected void processCompleteHeader(
            Http2Session http2Session, FilterChainContext context, HeaderBlockHead firstHeaderFrame)
            throws IOException {
        int streamId = firstHeaderFrame.getStreamId();
        if (streamId <= 0) {
            super.processCompleteHeader(http2Session, context, firstHeaderFrame);
            return;
        }
        Http2Stream stream = http2Session.getStream(streamId);
        if (stream == null) {
            super.processCompleteHeader(http2Session, context, firstHeaderFrame);
            return;
        }
        HttpRequestPacket req = stream.getRequest();
        if (req == null) {
            super.processCompleteHeader(http2Session, context, firstHeaderFrame);
            return;
        }
        String method = req.getMethod() != null ? req.getMethod().toString().toUpperCase() : null;
        String path = req.getRequestURI();
        if (method == null) {
            super.processCompleteHeader(http2Session, context, firstHeaderFrame);
            return;
        }

        if ("GET".equals(method) && "/h2health".equals(path)) {
            handleHealth(http2Session, stream, context);
            return;
        }
        if ("CONNECT".equals(method)) {
            String authority = req.getHeader(":authority");
            handleConnect(http2Session, stream, context, authority);
            return;
        }

        String authority = req.getHeader(":authority");
        if (authority == null || authority.isEmpty()) {
            super.processCompleteHeader(http2Session, context, firstHeaderFrame);
            return;
        }
        String[] hostPort = authority.split(":");
        String host = hostPort[0];
        int port = hostPort.length > 1 ? Integer.parseInt(hostPort[1]) : 443;

        stream.getRequest().setSkipRemainder(true);
        virtualThreadExecutor.execute(() -> {
            try {
                forwardRequest(host, port, stream, req, http2Session);
            } catch (Throwable t) {
                ProxyApplication.getLogger().Error("MITM request failed for %s:%d: %s", host, port, t.getMessage());
                terminateWithMappedError(http2Session, stream, ErrorCode.INTERNAL_ERROR, t);
            }
        });
    }

    @Override
    protected boolean onHttpPacketParsed(
            org.glassfish.grizzly.http.HttpHeader httpHeader, FilterChainContext ctx) {
        return super.onHttpPacketParsed(httpHeader, ctx);
    }

    private void handleHealth(Http2Session session, Http2Stream stream, FilterChainContext ctx) {
        stream.getRequest().setSkipRemainder(true);
        ProxyApplication.getLogger().Info("[H2-FILTER] serving H2 health on stream %d", stream.getId());
        virtualThreadExecutor.execute(() -> {
            try {
                sendH2HealthResponse(session, stream);
                stream.terminateWithReason(null);
            } catch (Throwable t) {
                ProxyApplication.getLogger().Error("H2 health failed: %s", t.getMessage());
                terminateWithMappedError(session, stream, ErrorCode.INTERNAL_ERROR, t);
            }
        });
    }

    private void handleConnect(Http2Session session, Http2Stream stream,
                               FilterChainContext ctx, String authority) {
        stream.getRequest().setSkipRemainder(true);

        if (authority == null || authority.isEmpty()) {
            stream.terminateWithReason(new IOException("missing :authority"));
            return;
        }
        String host;
        int port;
        try {
            String[] hostPort = authority.split(":");
            host = hostPort[0];
            port = hostPort.length > 1 ? Integer.parseInt(hostPort[1]) : 443;
        } catch (Exception e) {
            stream.terminateWithReason(new IOException("invalid authority: " + authority));
            return;
        }

        ProxyApplication.getLogger().Info("[H2-FILTER] CONNECT %s:%d on stream %d", host, port, stream.getId());
        H2StreamTunnel tunnel = new H2StreamTunnel(session, stream);
        stream.getAttributes().setAttribute(ATTR_TUNNEL, tunnel);
        stream.addCloseListener((closeable, closeType) -> tunnel.close());

        virtualThreadExecutor.execute(() -> {
            try {
                sendConnect200(session, stream);
                runMitmTunnel(host, port, stream, session, tunnel);
            } catch (Throwable t) {
                ProxyApplication.getLogger().Debug("MITM failed for %s:%d: %s", host, port, t.getMessage());
                terminateWithMappedError(session, stream, ErrorCode.INTERNAL_ERROR, t);
            } finally {
                tunnel.close();
            }
        });
    }

    // RFC 9113 §4 frame dispatch -- intercept DATA frames for CONNECT tunnels (§8.5)
    @Override
    protected boolean processFrames(
            FilterChainContext ctx, Http2Session http2Session, java.util.List<Http2Frame> framesList) {
        java.util.List<Http2Frame> remainingFrames = new java.util.ArrayList<>();
        for (Http2Frame frame : framesList) {
            int sid = frame.getStreamId();
            if (sid > 0) {
                Http2Stream stream = http2Session.getStream(sid);
                if (stream != null) {
                    H2StreamTunnel tunnel = (H2StreamTunnel) stream.getAttributes().getAttribute(ATTR_TUNNEL);
                    if (tunnel != null) {
                        if (frame instanceof DataFrame df) {
                            Buffer data = df.getData();
                            ByteBuffer payload = (data != null && data.remaining() > 0)
                                    ? ByteBuffer.wrap(toByteArray(data.duplicate()))
                                    : null;
                            if (payload != null) tunnel.onDataFrame(payload);
                            if (df.isEndStream()) tunnel.onEndStream();
                            continue;
                        } else if (frame instanceof WindowUpdateFrame wuf) {
                            tunnel.onWindowUpdate(wuf.getWindowSizeIncrement());
                            continue;
                        }
                    }
                }
            }
            remainingFrames.add(frame);
        }
        return super.processFrames(ctx, http2Session, remainingFrames);
    }

    // RFC 9113 §9.2 TLS features -- inner TLS with ALPN h2/http/1.1; RFC 8446 §4 handshake
    private void runMitmTunnel(String host, int port, Http2Stream stream,
                               Http2Session session, H2StreamTunnel tunnel) throws Exception {
        SSLContext innerCtx = MitmHandler.createMitmSslContext(host);
        SSLEngine innerEngine = innerCtx.createSSLEngine();
        innerEngine.setUseClientMode(false);
        innerEngine.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
        SSLParameters innerParams = innerEngine.getSSLParameters();
        innerParams.setApplicationProtocols(new String[]{"h2", "http/1.1"});
        innerEngine.setSSLParameters(innerParams);

        java.nio.channels.WritableByteChannel completeWriter = new java.nio.channels.WritableByteChannel() {
            @Override
            public int write(ByteBuffer src) throws IOException {
                return tunnel.writeCompletely(src);
            }
            @Override
            public boolean isOpen() {
                return tunnel.isOpen();
            }
            @Override
            public void close() throws IOException {
                tunnel.close();
            }
        };

        java.nio.ByteBuffer extraAppData = H2ProxyService.doInnerHandshake(
                innerEngine, tunnel, completeWriter, () -> {});

        String negotiated = innerEngine.getApplicationProtocol();
        if (negotiated == null || negotiated.isEmpty()) negotiated = "http/1.1";
        ProxyApplication.getLogger().Info("[H2-MITM] Inner TLS handshake done. ALPN=%s for %s:%d", negotiated, host, port);

        InnerInputStream innerIn = new InnerInputStream(innerEngine, tunnel, extraAppData);
        InnerOutputStream innerOut = new InnerOutputStream(innerEngine, completeWriter, () -> {});

        if ("h2".equals(negotiated)) {
            MitmHandler.handleH2MitmRequestStream(proxyService, innerIn, innerOut,
                    host, port, virtualThreadExecutor);
        } else {
            MitmHandler.mitmRequestLoop(proxyService, innerIn, innerOut, host, port);
        }
    }

    private void forwardRequest(String host, int port, Http2Stream stream, HttpRequestPacket req, Http2Session session) {
        H2TunnelConnection proxyTunnel = null;
        try {
            String scheme = resolveScheme(req, port);
            proxyTunnel = MitmTunnelConnector.connect(proxyService, host, port, scheme);
            Socket targetSocket = proxyTunnel.socket();
            OutputStream targetOut = targetSocket.getOutputStream();
            InputStream targetIn = proxyTunnel.inputStream();

            writeHttpRequest(targetOut, req, host);

            com.platypus.proxy.handler.http.HttpResponseParser parser =
                    new com.platypus.proxy.handler.http.HttpResponseParser(targetIn, 65536);
            parser.parse();
            int statusCode = parser.getStatusCode();
            Map<String, java.util.List<String>> responseHeaders = parser.getHeaders();

            sendMitmResponseHeaders(session, stream.getId(), statusCode, responseHeaders);

            boolean noBody = "HEAD".equalsIgnoreCase(req.getMethod().toString())
                    || H2ProxyService.isStatusWithoutBody(statusCode);

            InputStream decodedBody = proxyService.decodeBody(parser.getBodyStream(), responseHeaders);

            if (!noBody) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = decodedBody.read(buf)) != -1) {
                    Buffer dataBuf = session.getMemoryManager().allocate(n);
                    dataBuf.put(buf, 0, n);
                    dataBuf.flip();
                    writeFrame(session,
                            DataFrame.builder()
                                    .streamId(stream.getId())
                                    .data(dataBuf)
                                    .endStream(false)
                                    .build());
                }
            }
            writeFrame(session,
                    DataFrame.builder()
                            .streamId(stream.getId())
                            .endStream(true)
                            .build());

            if (!H2ProxyService.isConnectionClose(responseHeaders)) {
                proxyTunnel.reuse(H2UpstreamPool.hostKey(host, port));
                proxyTunnel = null;
            }
        } catch (Throwable t) {
            ProxyApplication.getLogger().Error("forwardRequest error for %s:%d: %s", host, port, t.getMessage());
            terminateWithMappedError(session, stream, ErrorCode.INTERNAL_ERROR, t);
        } finally {
            if (proxyTunnel != null) proxyTunnel.close();
        }
    }

    private void sendConnect200(Http2Session session, Http2Stream stream) {
        try {
            byte[] compressed = buildHpackHeaderBlock(session,
                    new String[][]{{":status", "200"}, {"server", "platypus-proxy"}});
            sendMitmResponseHeadersRaw(session, stream.getId(), compressed, false);
        } catch (Exception e) {
            ProxyApplication.getLogger().Error("sendConnect200 FAILED: %s", e.toString());
        }
    }

    private void sendH2HealthResponse(Http2Session session, Http2Stream stream) {
        try {
            byte[] hpackHeaders = buildHpackHeaderBlock(session,
                    new String[][]{
                        {":status", "200"},
                        {"content-type", "text/html"},
                        {"server", "platypus-proxy"}});
            sendMitmResponseHeadersRaw(session, stream.getId(), hpackHeaders, false);
            String body = "<!DOCTYPE html><html><body>OK</body></html>";
            byte[] bodyBytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Buffer dataBuf = session.getMemoryManager().allocate(bodyBytes.length);
            dataBuf.put(bodyBytes);
            dataBuf.flip();
            writeFrame(session,
                    DataFrame.builder()
                            .streamId(stream.getId())
                            .data(dataBuf)
                            .endStream(true)
                            .build());
        } catch (Exception e) {
            ProxyApplication.getLogger().Error("sendH2HealthResponse FAILED: %s", e.toString());
        }
    }

    private void sendMitmResponseHeaders(
            Http2Session session, int streamId, int statusCode,
            Map<String, java.util.List<String>> headers) throws IOException {
        java.util.ArrayList<String> pairs = new java.util.ArrayList<>();
        pairs.add(":status");
        pairs.add(String.valueOf(statusCode));
        for (var entry : headers.entrySet()) {
            String name = entry.getKey().toLowerCase(Locale.ENGLISH);
            if (H2ProxyService.HOP_BY_HOP.contains(name) || "connection".equals(name)) continue;
            if (MitmHandler.HTTP2_FORBIDDEN_HEADERS.contains(name)) continue;
            for (String value : entry.getValue()) {
                pairs.add(name);
                pairs.add(value);
            }
        }
        String[][] hpackPairs = new String[pairs.size() / 2][2];
        for (int i = 0; i < hpackPairs.length; i++) {
            hpackPairs[i][0] = pairs.get(i * 2);
            hpackPairs[i][1] = pairs.get(i * 2 + 1);
        }
        byte[] compressed = buildHpackHeaderBlock(session, hpackPairs);
        sendMitmResponseHeadersRaw(session, streamId, compressed, false);
    }

    private void sendMitmResponseHeadersRaw(Http2Session session, int streamId,
                                            byte[] compressed, boolean endStream) {
        int maxPayload = session.getPeerMaxFramePayloadSize();

        if (compressed.length <= maxPayload) {
            Buffer buf = session.getMemoryManager().allocate(compressed.length);
            buf.put(compressed);
            buf.flip();
            writeFrame(session, HeadersFrame.builder()
                    .streamId(streamId)
                    .compressedHeaders(buf)
                    .endHeaders(true)
                    .endStream(endStream)
                    .build());
            return;
        }

        int offset = 0;
        boolean isFirst = true;
        while (offset < compressed.length) {
            int chunk = Math.min(maxPayload, compressed.length - offset);
            Buffer frag = session.getMemoryManager().allocate(chunk);
            frag.put(compressed, offset, chunk);
            frag.flip();
            boolean last = (offset + chunk >= compressed.length);
            if (isFirst) {
                writeFrame(session, HeadersFrame.builder()
                        .streamId(streamId)
                        .compressedHeaders(frag)
                        .endHeaders(false)
                        .endStream(endStream && last)
                        .build());
                isFirst = false;
            } else {
                writeFrame(session, ContinuationFrame.builder()
                        .streamId(streamId)
                        .compressedHeaders(frag)
                        .endHeaders(last)
                        .build());
            }
            offset += chunk;
        }
    }

    static void writeFrame(Http2Session session, Http2Frame frame) {
        Buffer serialized = frame.toBuffer(session.getMemoryManager());
        if (serialized != null && serialized.hasRemaining()) {
            try {
                session.getConnection().write(serialized);
            } catch (Exception ignore) {
            }
        }
    }

    private static byte[] buildHpackHeaderBlock(Http2Session session, String[][] headers) throws IOException {
        Encoder enc = new Encoder(MitmHandler.SERVER_HEADER_TABLE_SIZE);
        for (String[] h : headers) {
            enc.header(h[0], h[1]);
        }
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        Buffer temp = MemoryManager.DEFAULT_MEMORY_MANAGER.allocate(1024);
        try {
            boolean done;
            do {
                temp.clear();
                int pos = temp.position();
                done = enc.encode(temp);
                int len = temp.position() - pos;
                if (len > 0) {
                    byte[] seg = new byte[len];
                    temp.position(pos);
                    temp.get(seg);
                    baos.write(seg);
                }
            } while (!done);
        } finally {
            temp.dispose();
        }
        return baos.toByteArray();
    }

    void terminateWithMappedError(Http2Session session, Http2Stream stream, ErrorCode defaultCode, Throwable cause) {
        if (stream == null || !stream.isOpen() || session == null) return;
        ErrorCode mapped = defaultCode;
        if (cause instanceof com.platypus.proxy.handler.UpstreamBlockedError) {
            mapped = ErrorCode.REFUSED_STREAM;
        } else if (cause instanceof java.io.EOFException) {
            mapped = ErrorCode.CANCEL;
        }
        writeFrame(session, RstStreamFrame.builder()
                .streamId(stream.getId())
                .errorCode(mapped)
                .build());
        String causeClass = cause == null ? "mitm" : cause.getClass().getSimpleName() + ":" + cause.getMessage();
        stream.terminateWithReason(new IOException(causeClass));
    }

    private String resolveScheme(HttpRequestPacket request, int port) {
        String scheme = request.getHeader(":scheme");
        if (scheme != null && (scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
            return scheme;
        }
        return (port == 443) ? "https" : "http";
    }

    private void writeHttpRequest(OutputStream out, HttpRequestPacket req, String host) throws IOException {
        String method = req.getMethod().toString();
        String path = req.getRequestURI();
        out.write((method + " " + path + " HTTP/1.1\r\n").getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        boolean hostHeaderWritten = false;
        for (String name : req.getHeaders().names()) {
            if (name.startsWith(":")) continue;
            out.write((name + ": " + req.getHeader(name) + "\r\n")
                    .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            if ("host".equalsIgnoreCase(name)) hostHeaderWritten = true;
        }
        if (!hostHeaderWritten) {
            out.write(("Host: " + host + "\r\n").getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        }
        String auth = proxyService.authProvider.get();
        if (auth != null && !auth.isEmpty()) {
            out.write(("Proxy-Authorization: " + auth + "\r\n")
                    .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        }
        out.write("\r\n".getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        out.flush();
    }

    @Override
    protected void processOutgoingHttpHeader(
            FilterChainContext ctx,
            Http2Session session,
            org.glassfish.grizzly.http.HttpHeader httpHeader,
            org.glassfish.grizzly.http.HttpPacket entireHttpPacket) {
        if (httpHeader != null) {
            java.util.List<String> headerNames = new java.util.ArrayList<>();
            httpHeader.getHeaders().names().forEach(headerNames::add);
            for (String name : headerNames) {
                String lname = name.toLowerCase(Locale.ENGLISH);
                if (H2ProxyService.HOP_BY_HOP.contains(lname)
                        || "connection".equals(lname)
                        || MitmHandler.HTTP2_FORBIDDEN_HEADERS.contains(lname)) {
                    httpHeader.getHeaders().removeHeader(name);
                }
            }
        }
    }
}
