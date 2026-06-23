package com.platypus.proxy.handler.h2;

import com.platypus.proxy.ProxyApplication;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.SocketChannel;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingDeque;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.Connection;
import org.glassfish.grizzly.filterchain.FilterChainContext;
import org.glassfish.grizzly.filterchain.NextAction;
import org.glassfish.grizzly.http.HttpRequestPacket;
import org.glassfish.grizzly.http.HttpResponsePacket;
import org.glassfish.grizzly.http2.Http2Configuration;
import org.glassfish.grizzly.http2.Http2ServerFilter;
import org.glassfish.grizzly.http2.Http2Session;
import org.glassfish.grizzly.http2.Http2Stream;
import org.glassfish.grizzly.http2.frames.DataFrame;
import org.glassfish.grizzly.http2.frames.HeaderBlockHead;
import org.glassfish.grizzly.http2.frames.HeadersFrame;
import org.glassfish.grizzly.http2.frames.Http2Frame;
import org.glassfish.grizzly.http2.hpack.Encoder;
import org.glassfish.grizzly.nio.NIOConnection;

/**
 * Inner-h2 server filter for the h2c (cleartext) path.
 * All writes to the connection are sent via the raw-channel writer thread
 * to avoid recursion.
 *
 * <p>RFC 9113 §3.3 starting H2 with prior knowledge -- cleartext h2c path.
 * RFC 9113 §3.4 connection preface -- 24-octet magic detection.
 *
 * <p><b>Recursion fix:</b> uses {@link RawChannelHttp2Session}, which
 * replaces the output sink with {@link RawChannelOutputSink}.
 *
 * <p><b>ClassCastException fix:</b> {@link #handleRead} is overridden
 * to handle raw {@link Buffer} messages (HTTP/2 preface and frames)
 * without ever calling {@code super.handleRead()}.
 */
public class InnerH2MitmServerFilter extends Http2ServerFilter {

    private static final String ATTR_BODY_QUEUE = "mitm.bodyQueue";
    private static final String WRITER_KEY = "mitm.writerThread";
    private static final String ATTR_INTERCEPTED = "mitm.intercepted";

    private final H2ProxyService proxyService;
    private final ExecutorService virtualThreadExecutor;
    private final java.util.function.Supplier<H2ProxyService.TunnelSupplier> tunnelSupplier;

    public InnerH2MitmServerFilter(
            Http2Configuration config,
            H2ProxyService proxyService,
            ExecutorService virtualThreadExecutor,
            java.util.function.Supplier<H2ProxyService.TunnelSupplier> tunnelSupplier) {
        super(config);
        this.proxyService = proxyService;
        this.virtualThreadExecutor = virtualThreadExecutor;
        this.tunnelSupplier = tunnelSupplier;
    }

    @Override
    protected Http2Session createHttp2Session(Connection connection, boolean isServer) {
        return new RawChannelHttp2Session(connection, isServer, this);
    }

    // ---- Override handleRead to avoid ClassCastException ----
    @Override
    public NextAction handleRead(FilterChainContext ctx) throws IOException {
        Object message = ctx.getMessage();
        if (!(message instanceof Buffer)) {
            // Not a raw buffer - delegate to superclass.
            return super.handleRead(ctx);
        }

        Buffer buffer = (Buffer) message;
        Connection<?> connection = ctx.getConnection();

        Http2Session session = Http2Session.get(connection);
        if (session != null) {
            return processRawBuffer(ctx, session, buffer);
        }

        int remaining = buffer.remaining();
        if (remaining < 24) {
            return ctx.getStopAction();
        }

        int pos = buffer.position();
        byte[] preface = new byte[24];
        buffer.get(preface);
        buffer.position(pos);

        if (java.util.Arrays.equals(preface, H2cDetectionFilter.HTTP2_MAGIC)) {
            buffer.position(pos + 24);
            session = createHttp2Session(connection, true);
            return processRawBuffer(ctx, session, buffer);
        }

        // Not a preface; pass on to next filter.
        return ctx.getInvokeAction();
    }

    private NextAction processRawBuffer(FilterChainContext ctx,
                                        Http2Session session,
                                        Buffer buffer) throws IOException {
        ByteArrayInputStream bais = new ByteArrayInputStream(toByteArray(buffer));
        InputStreamFrameSource frameSource =
                new InputStreamFrameSource(bais, session.getPeerMaxFramePayloadSize());
        java.util.ArrayList<Http2Frame> frames = new java.util.ArrayList<>();
        try {
            while (true) {
                Http2Frame frame = frameSource.nextFrame();
                if (frame == null) break;
                frames.add(frame);
            }
        } catch (IOException e) {
            throw e;
        } finally {
            buffer.tryDispose();
        }
        if (!frames.isEmpty()) {
            processFrames(ctx, session, frames);
        }
        return ctx.getStopAction();
    }

    private byte[] toByteArray(Buffer buf) {
        byte[] data = new byte[buf.remaining()];
        buf.get(data);
        return data;
    }

    @Override
    protected boolean onHttpPacketParsed(
            org.glassfish.grizzly.http.HttpHeader httpHeader, FilterChainContext ctx) {
        Http2Stream stream = Http2Stream.getStreamFor(httpHeader);
        if (stream != null && Boolean.TRUE.equals(
                stream.getAttributes().getAttribute(ATTR_INTERCEPTED))) {
            return true;
        }
        return super.onHttpPacketParsed(httpHeader, ctx);
    }

    /**
     * Override the default write handling - identical to the outer filter.
     */
    @Override
    public NextAction handleWrite(FilterChainContext ctx) throws IOException {
        Object message = ctx.getMessage();
        Http2Session session = Http2Session.get(ctx.getConnection());

        if (message instanceof Http2Frame) {
            writeFrameAsync(session, (Http2Frame) message);
        } else if (message instanceof java.util.List) {
            for (Object obj : (java.util.List<?>) message) {
                if (obj instanceof Http2Frame) {
                    writeFrameAsync(session, (Http2Frame) obj);
                }
            }
        }
        return ctx.getStopAction();
    }

    @Override
    protected void processCompleteHeader(
            Http2Session http2Session, FilterChainContext context, HeaderBlockHead firstHeaderFrame)
            throws IOException {
        int streamId = firstHeaderFrame.getStreamId();
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

        String authority = req.getHeader(":authority");
        if (authority == null || authority.isEmpty()) {
            stream.terminateWithReason(new IOException("missing :authority"));
            return;
        }

        String[] hostPort = authority.split(":");
        final String host = hostPort[0];
        final int port = hostPort.length > 1 ? Integer.parseInt(hostPort[1]) : 443;

        stream.getAttributes().setAttribute(ATTR_INTERCEPTED, Boolean.TRUE);

        final Http2Session session = http2Session;
        BlockingDeque<byte[]> bodyQueue = new LinkedBlockingDeque<>();
        stream.getAttributes().setAttribute(ATTR_BODY_QUEUE, bodyQueue);
        virtualThreadExecutor.execute(() -> {
            try {
                relayUpstream(session, stream, host, port, req, bodyQueue);
            } catch (Throwable t) {
                ProxyApplication.getLogger().Error("[H2-MITM-INNER] stream %d error: %s", streamId, t.getMessage());
                stream.terminateWithReason(
                        new IOException(t.getMessage() != null ? t.getMessage() : "mitm inner error", t));
            }
        });
    }

    @Override
    protected boolean processFrames(
            FilterChainContext ctx, Http2Session http2Session, java.util.List<Http2Frame> framesList) {
        java.util.List<Http2Frame> remainingFrames = new java.util.ArrayList<>();
        for (Http2Frame frame : framesList) {
            int sid = frame.getStreamId();

            Http2Stream stream = http2Session.getStream(sid);
            BlockingDeque<byte[]> bodyQueue = (stream != null)
                    ? (BlockingDeque<byte[]>) stream.getAttributes().getAttribute(ATTR_BODY_QUEUE)
                    : null;

            if (bodyQueue != null && frame instanceof DataFrame df) {
                Buffer data = df.getData();
                if (data != null && data.remaining() > 0) {
                    byte[] bytes = new byte[data.remaining()];
                    data.duplicate().get(bytes);
                    bodyQueue.add(bytes);
                }
                if (df.isEndStream()) {
                    bodyQueue.add(new byte[0]);
                }
                continue;   // consumed by MITM
            }

            remainingFrames.add(frame);
        }
        return super.processFrames(ctx, http2Session, remainingFrames);
    }

    /** Runs on the VIRTUAL THREAD - uses raw-channel writer. */
    private void relayUpstream(
            Http2Session session,
            Http2Stream stream,
            String host,
            int port,
            HttpRequestPacket req,
            BlockingDeque<byte[]> bodyQueue)
            throws Exception {
        H2ProxyService.TunnelSupplier ts = tunnelSupplier.get();
        if (ts == null) {
            stream.terminateWithReason(new IOException("no tunnel supplier"));
            return;
        }
        H2TunnelConnection upstream = null;
        try {
            upstream = ts.open(host, port);
            OutputStream upOut = upstream.socket().getOutputStream();
            InputStream upIn = upstream.inputStream();
            Map<String, String> outHeaders = new java.util.LinkedHashMap<>();
            String method = req.getMethod().toString();
            String path = req.getRequestURI();
            for (String name : req.getHeaders().names()) {
                if (name.startsWith(":")) continue;
                if (H2ProxyService.HOP_BY_HOP.contains(name)) continue;
                if (MitmHandler.HTTP2_FORBIDDEN_HEADERS.contains(name)) continue;
                outHeaders.put(name, req.getHeader(name));
            }
            String auth = proxyService.authProvider.get();
            if (auth != null && !auth.isEmpty()) outHeaders.put("Proxy-Authorization", auth);

            InputStream body = new InputStream() {
                @Override
                public int read() throws IOException {
                    byte[] b = new byte[1];
                    int n = read(b, 0, 1);
                    return n <= 0 ? -1 : (b[0] & 0xff);
                }

                @Override
                public int read(byte[] buf, int off, int len) throws IOException {
                    try {
                        byte[] chunk = bodyQueue.take();
                        if (chunk.length == 0) return -1;
                        int n = Math.min(len, chunk.length);
                        System.arraycopy(chunk, 0, buf, off, n);
                        if (n < chunk.length) {
                            byte[] remainder = new byte[chunk.length - n];
                            System.arraycopy(chunk, n, remainder, 0, remainder.length);
                            bodyQueue.putFirst(remainder);
                        }
                        return n;
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted", e);
                    }
                }
            };

            long contentLen = req.getContentLength() > 0 ? req.getContentLength() : -1;
            proxyService.sendHttpRequest(upOut, method, path, host, outHeaders, body, contentLen);

            com.platypus.proxy.handler.http.HttpResponseParser parser =
                    new com.platypus.proxy.handler.http.HttpResponseParser(upIn, 65536);
            parser.parse();
            int statusCode = parser.getStatusCode();
            Map<String, java.util.List<String>> respHeaders = parser.getHeaders();
            InputStream respBody = parser.getBodyStream();
            InputStream decodedBody = proxyService.decodeBody(respBody, respHeaders);
            boolean noBody = "HEAD".equalsIgnoreCase(method) || H2ProxyService.isStatusWithoutBody(statusCode);

            HttpResponsePacket response = req.getResponse();
            response.setStatus(statusCode);
            for (var e : respHeaders.entrySet()) {
                String n = e.getKey().toLowerCase(Locale.ENGLISH);
                if (H2ProxyService.HOP_BY_HOP.contains(n) || "connection".equals(n)) continue;
                if (MitmHandler.HTTP2_FORBIDDEN_HEADERS.contains(n)) continue;
                for (String v : e.getValue()) response.addHeader(n, v);
            }

            HeadersFrame hf = buildHeadersFrame(session, stream.getId(), statusCode, respHeaders, noBody);
            writeFrameAsync(session, hf);

            if (!noBody && decodedBody != null) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = decodedBody.read(buf)) != -1) {
                    Buffer dataBuf = session.getMemoryManager().allocate(n);
                    dataBuf.put(buf, 0, n);
                    dataBuf.flip();
                    DataFrame df = DataFrame.builder()
                            .streamId(stream.getId())
                            .data(dataBuf)
                            .endStream(false)
                            .build();
                    writeFrameAsync(session, df);
                }
            }
            DataFrame endFrame = DataFrame.builder()
                    .streamId(stream.getId())
                    .endStream(true)
                    .build();
            writeFrameAsync(session, endFrame);

            if (!H2ProxyService.isConnectionClose(respHeaders)) {
                upstream.reuse(H2UpstreamPool.hostKey(host, port));
                upstream = null;
            }
        } finally {
            if (upstream != null) upstream.close();
        }
    }

    /** Builds a single HEADERS frame for the response (no splitting for simplicity). */
    private HeadersFrame buildHeadersFrame(
            Http2Session session,
            int streamId,
            int statusCode,
            Map<String, java.util.List<String>> headers,
            boolean endStream)
            throws IOException {
        Encoder enc = new Encoder(MitmHandler.SERVER_HEADER_TABLE_SIZE);
        enc.header(":status", String.valueOf(statusCode));
        for (var entry : headers.entrySet()) {
            String name = entry.getKey().toLowerCase(Locale.ENGLISH);
                if (H2ProxyService.HOP_BY_HOP.contains(name) || "connection".equals(name)) continue;
            if (MitmHandler.HTTP2_FORBIDDEN_HEADERS.contains(name)) continue;
            for (String value : entry.getValue()) {
                enc.header(name, value);
            }
        }
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        Buffer temp = session.getMemoryManager().allocate(1024);
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
        byte[] compressed = baos.toByteArray();
        Buffer headBuf = session.getMemoryManager().allocate(compressed.length);
        headBuf.put(compressed);
        headBuf.flip();
        return HeadersFrame.builder()
                .streamId(streamId)
                .compressedHeaders(headBuf)
                .endHeaders(true)
                .endStream(endStream)
                .build();
    }

    /* ---------- Raw-channel writer (shared across sessions) ---------- */
    private void writeFrameAsync(Http2Session session, Http2Frame frame) {
        H2FrameWriter writer = getWriterThread(session);
        writer.writeFrame(session, frame);
    }

    private H2FrameWriter getWriterThread(Http2Session session) {
        final NIOConnection nioConn = (NIOConnection) session.getConnection();
        final SocketChannel channel = (SocketChannel) nioConn.getChannel();
        synchronized (session.getConnection()) {
            H2FrameWriter writer =
                    (H2FrameWriter) session.getConnection().getAttributes().getAttribute(WRITER_KEY);
            if (writer == null) {
                writer = new H2FrameWriter("h2c-writer", channel);
                session.getConnection().getAttributes().setAttribute(WRITER_KEY, writer);
            }
            return writer;
        }
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
