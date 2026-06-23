package com.platypus.proxy.handler.h2;

import com.platypus.proxy.ProxyApplication;
import com.platypus.proxy.handler.http.HttpResponseParser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.http2.frames.ContinuationFrame;
import org.glassfish.grizzly.http2.frames.DataFrame;
import org.glassfish.grizzly.http2.frames.ErrorCode;
import org.glassfish.grizzly.http2.frames.GoAwayFrame;
import org.glassfish.grizzly.http2.frames.HeadersFrame;
import org.glassfish.grizzly.http2.frames.Http2Frame;
import org.glassfish.grizzly.http2.frames.PingFrame;
import org.glassfish.grizzly.http2.frames.RstStreamFrame;
import org.glassfish.grizzly.http2.frames.SettingsFrame;
import org.glassfish.grizzly.http2.frames.SettingsFrame.SettingsFrameBuilder;
import org.glassfish.grizzly.http2.frames.WindowUpdateFrame;
import org.glassfish.grizzly.http2.hpack.Decoder;
import org.glassfish.grizzly.http2.hpack.DecodingCallback;
import org.glassfish.grizzly.http2.hpack.Encoder;
import org.glassfish.grizzly.memory.MemoryManager;

/**
 * Inner HTTP/2 frame handler for the MITM path.  Reads frames from
 * the decrypted inner TLS stream (via {@link InputStreamFrameSource}),
 * dispatches per-stream work to virtual threads, and writes response
 * frames back via the inner output stream.
 *
 * <p>Used by both h2-over-CONNECT (via {@link H2StreamTunnel}) and
 * h1-over-CONNECT (via outer {@code SSLEngineInputStream}/
 * {@code SSLEngineOutputStream}) inner paths.
 *
 * <p><b>Downlink perspective (proxy -> browser):</b> after the MITM
 * inner TLS handshake this class is the HTTP/2 <i>server</i> talking
 * downlink to the browser.  The browser is the HTTP/2 client; it
 * sends the connection preface (RFC 9113 §3.4), request HEADERS
 * (§6.2 + §8.3.1) and request DATA (§6.1).  We reply with SETTINGS
 * (§6.5), response HEADERS (§6.2 + §8.3.2), response DATA (§6.1),
 * WINDOW_UPDATE (§6.9), PING ACK (§6.7), RST_STREAM (§6.4) and GOAWAY
 * (§6.8).  Header compression is HPACK per RFC 7541 (§2.3 dynamic
 * table, §6 binary representations).  Connection/error semantics per
 * RFC 9113 §5.4.  HTTP fields per §8.2 (connection-specific fields
 * forbidden per §8.2.2).
 *
 * <p><b>RFC 8740</b> forbids TLS 1.3 post-handshake authentication on
 * HTTP/2 connections.  <b>RFC 8441</b> / <b>RFC 9220</b> define Extended
 * CONNECT ({@code SETTINGS_ENABLE_CONNECT_PROTOCOL} +
 * {@code :protocol} pseudo-header) for WebSockets; this handler
 * processes standard HTTP request/response exchanges only.
 * <b>draft-ietf-masque-connect-ip-08</b> (IP proxying) and
 * <b>draft-ietf-masque-quic-proxy-08</b> (QUIC-aware proxying) use
 * Extended CONNECT with capsule protocols and are not handled here.
 */
class InnerH2MitmHandler {

    private static final MemoryManager<?> MEM_MGR = MemoryManager.DEFAULT_MEMORY_MANAGER;
    /** RFC 9113 §6.9.2: default initial flow-control window (2^16-1). */
    private static final int SERVER_INITIAL_WINDOW = 65535;
    /** RFC 9113 §6.9: emit WINDOW_UPDATE before draining below half the window. */
    private static final int WINDOW_UPDATE_THRESHOLD = SERVER_INITIAL_WINDOW / 2;
    /** RFC 9113 §3.4: client connection preface magic (24 octets). */
    private static final byte[] H2_MAGIC = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.UTF_8);

    private static final long FLOW_CONTROL_TIMEOUT_NS = 30_000_000_000L;

    private final H2ProxyService proxyService;
    private final InputStream innerIn;
    private final OutputStream innerOut;
    private final Runnable flusher;
    private final String host;
    private final int port;
    private final ExecutorService virtualThreadExecutor;

    private long connWindow = SERVER_INITIAL_WINDOW;
    private int maxFrameSize = 16384;
    private int headerTableSize = 4096;
    private int initialWindowSize = SERVER_INITIAL_WINDOW;

    private final Map<Integer, StreamState> streams = new ConcurrentHashMap<>();
    private long connReceiveConsumed = 0;

    private int pendingHeadersStreamId = -1;
    private boolean pendingHeadersEndStream;
    private Decoder headerDecoder;
    private Map<String, String> pendingHeaders;

    private final Object flowLock = new Object();

    InnerH2MitmHandler(
            H2ProxyService proxyService,
            InputStream innerIn,
            OutputStream innerOut,
            Runnable flusher,
            String host,
            int port,
            ExecutorService vte) {
        this.proxyService = proxyService;
        this.innerIn = innerIn;
        this.innerOut = innerOut;
        this.flusher = flusher;
        this.host = host;
        this.port = port;
        this.virtualThreadExecutor = vte;
    }

    /**
     * Downlink server loop: emit our SETTINGS (RFC 9113 §6.5), then
     * read the browser's connection preface (§3.4) - the 24-octet magic
     * followed by its client SETTINGS.  We then read frames until EOF
     * or GOAWAY.  Control frames (sid 0) per §6.5-§6.9; stream frames
     * per §6.1-§6.4, §6.10.
     */
    void run() throws IOException {
        sendServerSettings();

        byte[] magic = new byte[24];
        int off = 0;
        while (off < 24) {
            int n = innerIn.read(magic, off, 24 - off);
            if (n < 0) throw new IOException("EOF reading client preface");
            off += n;
        }
        if (!Arrays.equals(magic, H2_MAGIC)) throw new IOException("Invalid HTTP/2 connection preface");

        InputStreamFrameSource source = new InputStreamFrameSource(innerIn, maxFrameSize);

        while (true) {
            Http2Frame frame;
            try {
                frame = source.nextFrame();
            } catch (IOException e) {
                ProxyApplication.getLogger().Debug("[H2-MITM-INNER] Frame source EOF: %s", e.getMessage());
                return;
            }
            if (frame == null) return;
            int sid = frame.getStreamId();
            if (sid == 0) {
                handleControlFrame(frame);
            } else {
                handleStreamFrame(frame, sid);
            }
        }
    }

    /**
     * Send our server SETTINGS to the browser (RFC 9113 §6.5).
     * Settings IDs per §6.5.2: 0x1 HEADER_TABLE_SIZE, 0x2 ENABLE_PUSH,
     * 0x3 MAX_CONCURRENT_STREAMS, 0x4 INITIAL_WINDOW_SIZE, 0x5
     * MAX_FRAME_SIZE.  We do not send SETTINGS ACK here - that is sent
     * on receipt of the peer's SETTINGS below.
     */
    private void sendServerSettings() throws IOException {
        SettingsFrameBuilder sfb = SettingsFrame.builder();
        for (int[] s : MitmHandler.DEFAULT_SERVER_SETTINGS) sfb.setting(s[0], s[1]);
        writeFrame(sfb.build());
        runFlusher();
    }

    /**
     * Handle connection-level (stream id 0) frames from the browser
     * downlink: SETTINGS (§6.5), WINDOW_UPDATE (§6.9), PING (§6.7),
     * GOAWAY (§6.8).  Per §6.5 we MUST ACK the peer's SETTINGS.
     */
    private void handleControlFrame(Http2Frame frame) throws IOException {
        if (frame instanceof SettingsFrame sf && !sf.isAck()) {
            // RFC 9113 §6.5: apply peer SETTINGS then ACK.  §6.5.2
            // defines the setting identifiers processed below.
            for (int i = 0; i < sf.getNumberOfSettings(); i++) {
                SettingsFrame.Setting s = sf.getSettingByIndex(i);
                switch (s.getId()) {
                    case 0x1 -> headerTableSize = s.getValue();
                    case 0x4 -> {
                        // RFC 9113 §6.9.3: a change to
                        // SETTINGS_INITIAL_WINDOW_SIZE applies as a delta to
                        // all open streams' send windows.
                        int delta = s.getValue() - initialWindowSize;
                        initialWindowSize = s.getValue();
                        synchronized (flowLock) {
                            for (StreamState ss : streams.values()) ss.streamWindow += delta;
                        }
                    }
                    case 0x5 -> maxFrameSize = s.getValue();
                }
            }
            writeFrame(SettingsFrame.builder().setAck().build());
            runFlusher();
        } else if (frame instanceof WindowUpdateFrame wuf) {
            // RFC 9113 §6.9: peer opened flow-control credit on the
            // connection (sid 0) or a stream.
            synchronized (flowLock) {
                if (wuf.getStreamId() == 0) {
                    connWindow += wuf.getWindowSizeIncrement();
                } else {
                    StreamState ss = streams.get(wuf.getStreamId());
                    if (ss != null) ss.streamWindow += wuf.getWindowSizeIncrement();
                }
                flowLock.notifyAll();
            }
        } else if (frame instanceof PingFrame pf && !pf.isAckSet()) {
            // RFC 9113 §6.7: echo PING with ACK flag.
            writeFrame(
                    PingFrame.builder().opaqueData(pf.getOpaqueData()).ack(true).build());
            runFlusher();
        } else if (frame instanceof GoAwayFrame) {
            // RFC 9113 §6.8: peer initiated graceful shutdown.
            ProxyApplication.getLogger().Debug("[H2-MITM-INNER] Client sent GOAWAY");
        }
    }

    /**
     * Handle per-stream frames from the browser downlink: HEADERS
     * (§6.2), CONTINUATION (§6.10), DATA (§6.1), WINDOW_UPDATE (§6.9),
     * RST_STREAM (§6.4).  Per §6.10 a HEADERS frame with END_HEADERS
     * false MUST be followed by CONTINUATION on the same stream; a
     * non-CONTINUATION frame here is a PROTOCOL_ERROR (§5.4.1) and we
     * send GOAWAY (§6.8).
     */
    private void handleStreamFrame(Http2Frame frame, int sid) throws IOException {
        if (pendingHeadersStreamId > 0 && !(frame instanceof ContinuationFrame)) {
            writeFrame(GoAwayFrame.builder()
                    .lastStreamId(0)
                    .errorCode(ErrorCode.PROTOCOL_ERROR)
                    .build());
            throw new IOException("Expected CONTINUATION on stream " + pendingHeadersStreamId);
        }

        if (frame instanceof HeadersFrame hf) {
            handleHeadersFrame(hf, sid);
        } else if (frame instanceof ContinuationFrame cf) {
            handleContinuationFrame(cf, sid);
        } else if (frame instanceof DataFrame df) {
            handleDataFrame(df, sid);
        } else if (frame instanceof WindowUpdateFrame wuf) {
            synchronized (flowLock) {
                StreamState ss = streams.get(sid);
                if (ss != null) ss.streamWindow += wuf.getWindowSizeIncrement();
                flowLock.notifyAll();
            }
        } else if (frame instanceof RstStreamFrame) {
            StreamState ss = streams.remove(sid);
            if (ss != null) ss.bodyQueue.add(new byte[0]);
        }
    }

    /**
     * Decode a HEADERS frame (RFC 9113 §6.2) from the browser.  The
     * compressed header block is HPACK per RFC 7541 (§4 dynamic table,
     * §5 primitive types, §6 binary representations).  If END_HEADERS is
     * set the header section is complete (§6.10); otherwise expect
     * CONTINUATION frames.
     */
    private void handleHeadersFrame(HeadersFrame hf, int sid) throws IOException {
        byte[] fragment = toByteArray(hf.getCompressedHeaders());
        headerDecoder = new Decoder(headerTableSize);
        headerDecoder.setMaxCapacity(headerTableSize);
        pendingHeaders = new LinkedHashMap<>();

        boolean endHeaders = hf.isEndHeaders();
        decodeHeaderBlock(wrap(fragment), endHeaders, pendingHeaders);

        if (endHeaders) {
            completeHeaders(sid, pendingHeaders, hf.isEndStream());
            pendingHeaders = null;
            headerDecoder = null;
        } else {
            pendingHeadersStreamId = sid;
            pendingHeadersEndStream = hf.isEndStream();
        }
    }

    /**
     * CONTINUATION frame (RFC 9113 §6.10) carrying a further fragment
     * of a HEADERS block whose END_HEADERS was not set on the HEADERS
     * frame.  The final CONTINUATION sets END_HEADERS.
     */
    private void handleContinuationFrame(ContinuationFrame cf, int sid) throws IOException {
        byte[] fragment = toByteArray(cf.getCompressedHeaders());
        boolean endHeaders = cf.isEndHeaders();
        decodeHeaderBlock(wrap(fragment), endHeaders, pendingHeaders);
        if (endHeaders) {
            int streamId = pendingHeadersStreamId;
            boolean es = pendingHeadersEndStream;
            pendingHeadersStreamId = -1;
            Map<String, String> headers = pendingHeaders;
            pendingHeaders = null;
            headerDecoder = null;
            completeHeaders(streamId, headers, es);
        }
    }

    private void decodeHeaderBlock(Buffer compressed, boolean endHeaders, Map<String, String> target) {
        headerDecoder.decode(compressed, endHeaders, new DecodingCallback() {
            @Override
            public void onDecoded(CharSequence name, CharSequence value) {
                target.put(name.toString(), value.toString());
            }
        });
    }

    /**
     * A complete header section has been assembled.  Per RFC 9113
     * §8.3.1 the request pseudo-headers ({@code :method}, {@code :path},
     * {@code :scheme}, {@code :authority}) are validated in
     * {@link #processStream}.  If END_STREAM was set on the HEADERS
     * frame (§6.2) the request has no body and we dispatch immediately.
     */
    private void completeHeaders(int sid, Map<String, String> headers, boolean endStream) throws IOException {
        StreamState ss = new StreamState(sid);
        ss.headers = headers;
        streams.put(sid, ss);

        if (endStream) {
            ss.bodyQueue.add(new byte[0]);
            processStream(sid, headers, ss.bodyQueue);
        }
    }

    /**
     * DATA frame (RFC 9113 §6.1) from the browser carrying request body
     * bytes.  Per §6.9 we MUST send WINDOW_UPDATE on the connection
     * (sid 0) when the consumed credit crosses the threshold; per-stream
     * WINDOW_UPDATE is handled by the outer Grizzly flow-control path
     * for the h2-over-CONNECT case.
     */
    private void handleDataFrame(DataFrame df, int sid) throws IOException {
        StreamState ss = streams.get(sid);
        if (ss == null) return;

        if (df.getData() != null && df.getData().remaining() > 0) {
            byte[] chunk = toByteArray(df.getData());
            ss.bodyQueue.add(chunk);
            connReceiveConsumed += chunk.length;
        }

        if (df.isEndStream()) {
            ss.bodyQueue.add(new byte[0]);
            if (ss.headers != null) {
                processStream(sid, ss.headers, ss.bodyQueue);
            }
        }

        if (connReceiveConsumed >= WINDOW_UPDATE_THRESHOLD) {
            writeFrame(WindowUpdateFrame.builder()
                    .streamId(0)
                    .windowSizeIncrement((int) connReceiveConsumed)
                    .build());
            runFlusher();
            connReceiveConsumed = 0;
        }
    }

    /**
     * Dispatch a complete request to the upstream proxy and write the
     * response back downlink to the browser.  Request pseudo-headers
     * per RFC 9113 §8.3.1; response pseudo-header {@code :status} per
     * §8.3.2.  Hop-by-hop and connection-specific headers stripped per
     * §8.2.2.  Response HEADERS + DATA frames emitted per §6.2/§6.1.
     */
    private void processStream(int streamId, Map<String, String> headers, BlockingQueue<byte[]> bodyQueue) {
        virtualThreadExecutor.execute(() -> {
            H2TunnelConnection tunnel = null;
            try {
                String method = headers.get(":method");
                String path = headers.get(":path");
                String authority = headers.get(":authority");
                String scheme = headers.get(":scheme");
                if (method == null || path == null) {
                    writeRstStream(streamId, ErrorCode.PROTOCOL_ERROR);
                    return;
                }

                tunnel = MitmTunnelConnector.connect(proxyService, host, port, scheme != null ? scheme : "https");
                OutputStream upOut = tunnel.socket().getOutputStream();
                InputStream upIn = tunnel.inputStream();

                Map<String, String> reqHeaders = new LinkedHashMap<>();
                for (var e : headers.entrySet()) {
                    if (!e.getKey().startsWith(":")) reqHeaders.put(e.getKey(), e.getValue());
                }
                String auth = proxyService.authProvider.get();
                if (auth != null && !auth.isEmpty()) reqHeaders.put("Proxy-Authorization", auth);

                ByteArrayOutputStream bodyBuffer = new ByteArrayOutputStream();
                while (true) {
                    byte[] chunk = bodyQueue.take();
                    if (chunk.length == 0) break;
                    bodyBuffer.write(chunk);
                }
                byte[] bodyBytes = bodyBuffer.toByteArray();

                String targetHost = authority != null ? authority : host;
                if (bodyBytes.length > 0) {
                    proxyService.sendHttpRequest(
                            upOut,
                            method,
                            path,
                            targetHost,
                            reqHeaders,
                            new java.io.ByteArrayInputStream(bodyBytes),
                            bodyBytes.length);
                } else {
                    proxyService.sendHttpRequest(upOut, method, path, targetHost, reqHeaders, null, -1);
                }

                HttpResponseParser parser = new HttpResponseParser(upIn, 65536);
                parser.parse();
                int statusCode = parser.getStatusCode();
                Map<String, List<String>> respHeaders = parser.getHeaders();
                InputStream respBody = parser.getBodyStream();
                InputStream decodedBody = proxyService.decodeBody(respBody, respHeaders);
                boolean noBody = "HEAD".equalsIgnoreCase(method) || H2ProxyService.isStatusWithoutBody(statusCode);

                writeResponseHeaders(streamId, statusCode, respHeaders, noBody);

                if (!noBody && decodedBody != null) {
                    byte[] dataBuf = new byte[Math.min(maxFrameSize, 65536)];
                    int dlen;
                    while ((dlen = decodedBody.read(dataBuf)) != -1) {
                        writeDataWithFlowControl(streamId, dataBuf, dlen);
                    }
                }

                writeFrame(
                        DataFrame.builder().streamId(streamId).endStream(true).build());
                runFlusher();

                if (!H2ProxyService.isConnectionClose(respHeaders)) {
                    tunnel.reuse(H2UpstreamPool.hostKey(host, port));
                    tunnel = null;
                }
            } catch (Exception e) {
                ProxyApplication.getLogger().Error("[H2-MITM-INNER] Stream %d error: %s", streamId, e.getMessage());
                try {
                    writeRstStream(streamId, ErrorCode.INTERNAL_ERROR);
                } catch (IOException ignored) {
                }
            } finally {
                H2ProxyService.closeQuietly(tunnel);
                streams.remove(streamId);
            }
        });
    }

    /**
     * Encode and emit response HEADERS (RFC 9113 §6.2) downlink to the
     * browser.  HPACK encoding per RFC 7541 (§4 dynamic table, §6 binary
     * representations).  If the compressed block exceeds the peer's
     * SETTINGS_MAX_FRAME_SIZE (§6.5.2, default 16384 per §4.2) we split
     * into HEADERS + CONTINUATION (§6.10) with END_HEADERS on the last.
     */
    private void writeResponseHeaders(
            int streamId, int statusCode, Map<String, List<String>> respHeaders, boolean endStream) throws IOException {
        Encoder encoder = new Encoder(headerTableSize);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        encoder.header(":status", String.valueOf(statusCode));
        for (var e : respHeaders.entrySet()) {
            String name = e.getKey().toLowerCase(Locale.ENGLISH);
            if (H2ProxyService.HOP_BY_HOP.contains(name) || "connection".equals(name)) continue;
            if (MitmHandler.HTTP2_FORBIDDEN_HEADERS.contains(name)) continue;
            for (String v : e.getValue()) encoder.header(name, v);
        }
        Buffer tempBuf = MEM_MGR.allocate(1024);
        try {
            boolean done;
            do {
                tempBuf.clear();
                int posBefore = tempBuf.position();
                done = encoder.encode(tempBuf);
                int written = tempBuf.position() - posBefore;
                if (written > 0) {
                    byte[] seg = new byte[written];
                    tempBuf.position(posBefore);
                    tempBuf.get(seg);
                    baos.write(seg);
                }
            } while (!done);
        } finally {
            tempBuf.dispose();
        }
        byte[] compressed = baos.toByteArray();

        if (compressed.length <= maxFrameSize) {
            Buffer compressedBuffer = MEM_MGR.allocate(compressed.length);
            compressedBuffer.put(compressed);
            compressedBuffer.flip();
            writeFrame(HeadersFrame.builder()
                    .streamId(streamId)
                    .compressedHeaders(compressedBuffer)
                    .endHeaders(true)
                    .endStream(endStream)
                    .build());
        } else {
            int offset = 0;
            boolean first = true;
            while (offset < compressed.length) {
                int chunkLen = Math.min(maxFrameSize, compressed.length - offset);
                if (first) {
                    Buffer chunk = MEM_MGR.allocate(chunkLen);
                    chunk.put(compressed, offset, chunkLen);
                    chunk.flip();
                    writeFrame(HeadersFrame.builder()
                            .streamId(streamId)
                            .compressedHeaders(chunk)
                            .endHeaders(false)
                            .endStream(false)
                            .build());
                    first = false;
                } else {
                    boolean endHeaders = (offset + chunkLen >= compressed.length);
                    writeRawFrame(0x09, endHeaders ? 0x04 : 0x00, streamId, compressed, offset, chunkLen);
                }
                offset += chunkLen;
            }
        }
        runFlusher();
    }

    /**
     * Write response DATA frames (RFC 9113 §6.1) downlink to the
     * browser, respecting both the per-stream and connection-level
     * flow-control windows (§6.9).  Blocks until WINDOW_UPDATE (§6.9)
     * opens enough credit, or times out per FLOW_CONTROL_TIMEOUT_NS.
     * Each DATA frame payload is bounded by the peer's
     * SETTINGS_MAX_FRAME_SIZE (§6.5.2).
     */
    private void writeDataWithFlowControl(int streamId, byte[] data, int len) throws IOException {
        int offset = 0;
        while (offset < len) {
            int chunk;
            synchronized (flowLock) {
                long deadline = System.nanoTime() + FLOW_CONTROL_TIMEOUT_NS;
                while (true) {
                    StreamState ss = streams.get(streamId);
                    if (ss == null) throw new IOException("Stream " + streamId + " closed");
                    long allowed = Math.min(connWindow, ss.streamWindow);
                    if (allowed > 0) {
                        chunk = (int) Math.min(len - offset, Math.min(allowed, maxFrameSize));
                        connWindow -= chunk;
                        ss.streamWindow -= chunk;
                        break;
                    }
                    long remaining = deadline - System.nanoTime();
                    if (remaining <= 0) throw new IOException("Flow control timeout on stream " + streamId);
                    try {
                        flowLock.wait(remaining / 1_000_000, (int) (remaining % 1_000_000));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted", e);
                    }
                }
            }

            Buffer dataBuf = MEM_MGR.allocate(chunk);
            dataBuf.put(data, offset, chunk);
            dataBuf.flip();
            writeFrame(DataFrame.builder()
                    .streamId(streamId)
                    .data(dataBuf)
                    .endStream(false)
                    .build());
            runFlusher();
            offset += chunk;
        }
    }

    /**
     * Send RST_STREAM (RFC 9113 §6.4) to terminate a stream and remove
     * local state.  Error codes per §7 (e.g. PROTOCOL_ERROR,
     * INTERNAL_ERROR, REFUSED_STREAM, CANCEL).
     */
    private void writeRstStream(int streamId, ErrorCode error) throws IOException {
        writeFrame(RstStreamFrame.builder().streamId(streamId).errorCode(error).build());
        runFlusher();
        streams.remove(streamId);
    }

    private void writeFrame(Http2Frame frame) throws IOException {
        Buffer buf;
        try {
            buf = frame.toBuffer(MEM_MGR);
        } catch (Exception e) {
            writeRawFrame(frame.getType(), frame.getFlags(), frame.getStreamId(), new byte[0], 0, 0);
            return;
        }
        if (buf == null || buf.remaining() == 0) {
            writeRawFrame(frame.getType(), frame.getFlags(), frame.getStreamId(), new byte[0], 0, 0);
        } else {
            innerOut.write(toByteArray(buf));
        }
    }

    /**
     * Serialize a raw HTTP/2 frame (RFC 9113 §4.1 Frame Format): 3-byte
     * length, 1-byte type, 1-byte flags, 1-bit reserved + 31-bit stream
     * ID, then payload.
     */
    private void writeRawFrame(int type, int flags, int streamId, byte[] payload, int offset, int length)
            throws IOException {
        innerOut.write((length >> 16) & 0xFF);
        innerOut.write((length >> 8) & 0xFF);
        innerOut.write(length & 0xFF);
        innerOut.write(type);
        innerOut.write(flags);
        innerOut.write((streamId >> 24) & 0x7F);
        innerOut.write((streamId >> 16) & 0xFF);
        innerOut.write((streamId >> 8) & 0xFF);
        innerOut.write(streamId & 0xFF);
        if (length > 0) innerOut.write(payload, offset, length);
    }

    private void runFlusher() throws IOException {
        try {
            flusher.run();
        } catch (UncheckedIOException e) {
            throw e.getCause();
        } catch (RuntimeException e) {
            if (e.getCause() instanceof IOException) throw (IOException) e.getCause();
            throw e;
        }
    }

    private static byte[] toByteArray(Buffer buffer) {
        byte[] data = new byte[buffer.remaining()];
        buffer.get(data);
        return data;
    }

    private static Buffer wrap(byte[] data) {
        Buffer buffer = MEM_MGR.allocate(data.length);
        buffer.put(data);
        buffer.flip();
        return buffer;
    }

    private static class StreamState {
        @SuppressWarnings("unused")
        final int streamId;
        Map<String, String> headers;
        final BlockingQueue<byte[]> bodyQueue = new LinkedBlockingQueue<>();
        long streamWindow = SERVER_INITIAL_WINDOW;

        StreamState(int streamId) {
            this.streamId = streamId;
        }
    }
}
