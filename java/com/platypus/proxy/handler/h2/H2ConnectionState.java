package com.platypus.proxy.handler.h2;

import com.platypus.proxy.ProxyApplication;
import com.platypus.proxy.handler.http.HttpResponseParser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.http2.frames.*;
import org.glassfish.grizzly.http2.hpack.Decoder;
import org.glassfish.grizzly.http2.hpack.DecodingCallback;
import org.glassfish.grizzly.memory.MemoryManager;

public class H2ConnectionState {

    private static final MemoryManager<?> MEM_MGR = MemoryManager.DEFAULT_MEMORY_MANAGER;
    // RFC 9113 §6.9.2 -- default initial window 65,535 octets
    private static final int INITIAL_WINDOW = 65535;
    private static final int WINDOW_UPDATE_THRESHOLD = 16384;
    // RFC 9113 §6.9.1 -- boost connection window beyond default for throughput
    private static final int CONN_WINDOW_BOOST = 1048576;
    private static final int DEFAULT_MAX_CONCURRENT_STREAMS = 1000;

    private final H2ProxyService proxyService;
    private final InputStreamFrameSource source;
    private final OutputStream out;
    private final ExecutorService executor;
    private final int maxFrameSize;
    private final int headerTableSize;
    private final int peerStreamInitialWindow;
    // RFC 9113 §5.2 flow control -- separate stream + connection windows per direction
    private final Object windowLock = new Object();

    // peer = client -> proxy direction; we track what the client can receive
    private long peerConnWindow;
    private final Map<Integer, Long> peerStreamWindows = new HashMap<>();

    // local = proxy -> has consumed this much from client; triggers WINDOW_UPDATE
    private long localConnWindowConsumed = 0;
    private final Map<Integer, Long> localStreamWindowConsumed = new HashMap<>();

    private int pendingHeadersStreamId = -1;
    private boolean pendingHeadersEndStream;
    // RFC 7541 HPACK decoder/encoder -- §2.2 encoding and decoding contexts
    private final Decoder headerDecoder;
    private Map<String, String> pendingHeaders;

    private static final int MAX_CONCURRENT_CONNECTS = 512;
    private final java.util.concurrent.atomic.AtomicBoolean connectionClosed = new java.util.concurrent.atomic.AtomicBoolean(false);
    private final java.util.concurrent.atomic.AtomicInteger activeTunnelCount = new java.util.concurrent.atomic.AtomicInteger(0);
    private final java.util.concurrent.Semaphore connectSemaphore = new java.util.concurrent.Semaphore(MAX_CONCURRENT_CONNECTS, true);
    private java.util.concurrent.Semaphore streamSemaphore;
    private volatile boolean goAwayReceived = false;

    // RFC 9113 §5.1 stream states -- tracks each stream's lifecycle
    private final Map<Integer, StreamState> streams = new HashMap<>();
    private final org.glassfish.grizzly.http2.hpack.Encoder responseEncoder;

    private volatile Thread pingKeepaliveThread;
    private final AtomicBoolean pingKeepaliveRunning = new AtomicBoolean(false);
    private static final long PING_INTERVAL_MS = 5_000;

    public H2ConnectionState(H2ProxyService proxyService,
                             InputStreamFrameSource source,
                             OutputStream out,
                             SettingsFrame clientSettings) {
        this(proxyService, source, out, clientSettings, null);
    }

    public H2ConnectionState(H2ProxyService proxyService,
                             InputStreamFrameSource source,
                             OutputStream out,
                             SettingsFrame clientSettings,
                             ExecutorService executor) {
        this.proxyService = proxyService;
        this.source = source;
        this.out = out;
        this.executor = executor != null ? executor : java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor();
        int tmpMaxFrame = 16384;
        int tmpTableSize = 4096;
        int window = INITIAL_WINDOW;
        int maxConcurrent = DEFAULT_MAX_CONCURRENT_STREAMS;
        for (int i = 0; i < clientSettings.getNumberOfSettings(); i++) {
            SettingsFrame.Setting s = clientSettings.getSettingByIndex(i);
            switch (s.getId()) {
                case SettingsFrame.SETTINGS_HEADER_TABLE_SIZE -> tmpTableSize = s.getValue();
                case SettingsFrame.SETTINGS_INITIAL_WINDOW_SIZE -> window = s.getValue();
                case SettingsFrame.SETTINGS_MAX_FRAME_SIZE -> tmpMaxFrame = s.getValue();
                case SettingsFrame.SETTINGS_MAX_CONCURRENT_STREAMS -> maxConcurrent = s.getValue();
            }
        }
        this.maxFrameSize = tmpMaxFrame;
        this.headerTableSize = tmpTableSize;
        this.streamSemaphore = new java.util.concurrent.Semaphore(Math.max(1, maxConcurrent), true);
        this.peerConnWindow = INITIAL_WINDOW;
        this.peerStreamInitialWindow = window > 0 ? window : INITIAL_WINDOW;
        this.headerDecoder = new Decoder(headerTableSize);
        this.headerDecoder.setMaxCapacity(headerTableSize);
        this.responseEncoder = new org.glassfish.grizzly.http2.hpack.Encoder(headerTableSize);
    }

    // 2ms batch window — concurrent requests to the same host:port arriving
    // within this window proceed to tunnel creation simultaneously, reducing
    // serialization on WarpTunnelPool.creationSemaphore.
    private static final int BATCH_WINDOW_MS = 2;

    private static final class BatchGate {
        final CountDownLatch gate = new CountDownLatch(1);
        final AtomicBoolean opened = new AtomicBoolean(false);
    }

    private final ConcurrentHashMap<String, BatchGate> batchGates = new ConcurrentHashMap<>();

    private void batchBarrier(String host, int port) {
        String key = H2UpstreamPool.hostKey(host, port);
        BatchGate g = batchGates.computeIfAbsent(key, k -> new BatchGate());
        if (g.opened.compareAndSet(false, true)) {
            try {
                Thread.sleep(BATCH_WINDOW_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                g.gate.countDown();
                batchGates.remove(key);
            }
        }
        try {
            g.gate.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // RFC 9113 §3.4 -- connection preface: send SETTINGS, then read+dispatch frames
    public void mainLoop() throws IOException {
        try {
            writeFrame(WindowUpdateFrame.builder()
                    .streamId(0)
                    .windowSizeIncrement(CONN_WINDOW_BOOST)
                    .build());
            flushOut();
            startPingKeepalive();
            while (true) {
                Http2Frame frame = source.nextFrame();
                if (frame == null) return;
                int sid = frame.getStreamId();
                if (sid == 0) {
                    handleControlFrame(frame);
                } else {
                    handleStreamFrame(frame, sid);
                }
            }
        } finally {
            shutdown();
        }
    }

    // RFC 9113 §6.7 -- PING frames keep idle connection alive; §8.7 request reliability
    private void startPingKeepalive() {
        if (!pingKeepaliveRunning.compareAndSet(false, true)) return;
        pingKeepaliveThread = Thread.ofVirtual().start(() -> {
            while (pingKeepaliveRunning.get() && !connectionClosed.get()) {
                try {
                    Thread.sleep(PING_INTERVAL_MS);
                    if (!pingKeepaliveRunning.get() || connectionClosed.get()) break;
                    writeFrame(PingFrame.builder()
                            .opaqueData(System.nanoTime())
                            .ack(false)
                            .build());
                    flushOut();
                } catch (IOException e) {
                    break;
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
    }

    // RFC 9113 §5.4.3 connection termination -- drain active tunnels before closing
    private void shutdown() {
        pingKeepaliveRunning.set(false);
        if (pingKeepaliveThread != null) pingKeepaliveThread.interrupt();
        connectionClosed.set(true);
        // Evict all cached WARP tunnels — they belong to this browser
        // session and would otherwise hold QUIC streams indefinitely.
        if (proxyService.warpPool() != null) proxyService.warpPool().clear();
        for (StreamState st : streams.values()) {
            if (st.isTunnel && st.tunnelInput != null) {
                st.tunnelInput.close();
            }
        }
        int active = activeTunnelCount.get();
        ProxyApplication.getLogger().Debug("[H2] Connection shutdown, waiting for %d active tunnels", active);
        try {
            long deadline = System.currentTimeMillis() + 30000;
            while (activeTunnelCount.get() > 0 && System.currentTimeMillis() < deadline) {
                Thread.sleep(100);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        try { out.close(); } catch (IOException ignored) {}
        ProxyApplication.getLogger().Debug("[H2] Connection shutdown complete");
    }

    // RFC 9113 §6.5 SETTINGS, §6.9 WINDOW_UPDATE, §6.7 PING, §6.8 GOAWAY
    private void handleControlFrame(Http2Frame frame) throws IOException {
        if (frame instanceof SettingsFrame sf && !sf.isAck()) {
            writeFrame(SettingsFrame.builder().setAck().build());
            flushOut();
        } else if (frame instanceof WindowUpdateFrame wuf) {
            synchronized (windowLock) {
                if (wuf.getStreamId() == 0) {
                    peerConnWindow += wuf.getWindowSizeIncrement();
                } else {
                    Long current = peerStreamWindows.get(wuf.getStreamId());
                    long newVal = (current == null ? peerStreamInitialWindow : current) + wuf.getWindowSizeIncrement();
                    peerStreamWindows.put(wuf.getStreamId(), newVal);
                }
                windowLock.notify();
            }
        } else if (frame instanceof PingFrame pf && !pf.isAckSet()) {
            writeFrame(PingFrame.builder()
                    .opaqueData(pf.getOpaqueData()).ack(true).build());
            flushOut();
        } else if (frame instanceof GoAwayFrame gf) {
            ProxyApplication.getLogger().Debug("[H2] Client sent GOAWAY: %s", gf.getErrorCode());
            goAwayReceived = true;
            return;
        }
    }

    private void handleStreamFrame(Http2Frame frame, int sid) throws IOException {
        if (pendingHeadersStreamId > 0 && !(frame instanceof ContinuationFrame)) {
            writeFrame(GoAwayFrame.builder()
                    .lastStreamId(0)
                    .errorCode(ErrorCode.PROTOCOL_ERROR)
                    .build());
            throw new IOException("Expected CONTINUATION on stream " + pendingHeadersStreamId);
        }
        if (frame instanceof HeadersFrame hf) {
            handleHeaders(hf, sid);
        } else if (frame instanceof ContinuationFrame cf) {
            handleContinuation(cf, sid);
        } else if (frame instanceof DataFrame df) {
            handleData(df, sid);
        } else if (frame instanceof WindowUpdateFrame wuf) {
            synchronized (windowLock) {
                if (wuf.getStreamId() == 0) {
                    peerConnWindow += wuf.getWindowSizeIncrement();
                } else {
                    Long prev = peerStreamWindows.get(wuf.getStreamId());
                    long newVal = (prev == null ? peerStreamInitialWindow : prev) + wuf.getWindowSizeIncrement();
                    peerStreamWindows.put(wuf.getStreamId(), newVal);
                }
                windowLock.notify();
            }
        } else if (frame instanceof RstStreamFrame) {
            StreamState st = streams.remove(sid);
            if (st != null && st.isTunnel) {
                st.tunnelInput.close();
            }
        }
    }

    // RFC 9113 §6.2 HEADERS frame decoding; HPACK per RFC 7541 §3.2
    private void handleHeaders(HeadersFrame hf, int sid) throws IOException {
        byte[] frag = toByteArray(hf.getCompressedHeaders());
        pendingHeaders = new LinkedHashMap<>();
        boolean endHeaders = hf.isEndHeaders();
        decodeFragment(frag, endHeaders, pendingHeaders);
        if (endHeaders) {
            completeHeaders(sid, pendingHeaders, hf.isEndStream());
            pendingHeaders = null;
        } else {
            pendingHeadersStreamId = sid;
            pendingHeadersEndStream = hf.isEndStream();
        }
    }

    // RFC 9113 §6.10 CONTINUATION -- continues HEADERS block; final CONTINUATION sets END_HEADERS
    private void handleContinuation(ContinuationFrame cf, int sid) throws IOException {
        byte[] frag = toByteArray(cf.getCompressedHeaders());
        boolean endHeaders = cf.isEndHeaders();
        decodeFragment(frag, endHeaders, pendingHeaders);
        if (endHeaders) {
            int streamId = pendingHeadersStreamId;
            boolean es = pendingHeadersEndStream;
            pendingHeadersStreamId = -1;
            Map<String, String> headers = pendingHeaders;
            pendingHeaders = null;
            completeHeaders(streamId, headers, es);
        }
    }

    // RFC 7541 §3.2 header field representation processing -- indexed + literal decoding
    private void decodeFragment(byte[] fragment, boolean endHeaders, Map<String, String> target) {
        Buffer buf = MEM_MGR.allocate(fragment.length);
        buf.put(fragment);
        buf.flip();
        headerDecoder.decode(buf, endHeaders, new DecodingCallback() {
            @Override
            public void onDecoded(CharSequence name, CharSequence value) {
                target.put(name.toString(), value.toString());
            }
        });
        buf.tryDispose();
    }

    // RFC 9113 §8.3.1 request pseudo-headers -- :method/:path/:authority/:scheme validation; §8.5 CONNECT routing
    private void completeHeaders(int sid, Map<String, String> headers, boolean endStream) throws IOException {
        String method = headers.get(":method");
        String path = headers.get(":path");

        if ("GET".equalsIgnoreCase(method) && "/h2health".equals(path)) {
            handleHealth(sid);
            return;
        }

        if ("CONNECT".equalsIgnoreCase(method)) {
            String authority = headers.get(":authority");
            handleConnect(sid, authority);
            return;
        }

        if (goAwayReceived) {
            writeRstStream(sid, ErrorCode.REFUSED_STREAM);
            return;
        }

        StreamState st = new StreamState(sid);
        st.headers = headers;
        streams.put(sid, st);
        if (endStream) {
            st.bodyFinished = true;
            st.bodyQueue.add(new byte[0]);
            executor.execute(() -> processStream(st));
        }
    }

    // RFC 9113 §6.1 DATA frames -- deliver body/tunnel bytes; flow-control after each frame
    private void handleData(DataFrame df, int sid) throws IOException {
        StreamState st = streams.get(sid);
        if (st == null) return;

        int dataLen = 0;
        if (df.getData() != null && df.getData().remaining() > 0) {
            byte[] chunk = toByteArray(df.getData());
            dataLen = chunk.length;
            if (st.isTunnel) {
                st.tunnelInput.feed(chunk);
            } else {
                st.bodyQueue.add(chunk);
            }
        }
        if (df.isEndStream()) {
            if (st.isTunnel) {
                st.tunnelInput.feedEnd();
            } else {
                st.bodyQueue.add(new byte[0]);
                st.bodyFinished = true;
                if (st.headers != null) {
                    executor.execute(() -> processStream(st));
                }
            }
        }

        if (dataLen > 0) {
            maybeSendWindowUpdate(sid, dataLen);
        }
    }

    // RFC 9113 §6.9 WINDOW_UPDATE -- advertise consumed window space; threshold avoids tiny frames (§4.2.3.3 RFC 1122)
    private void maybeSendWindowUpdate(int streamId, int bytesConsumed) throws IOException {
        boolean needsFlush = false;
        synchronized (windowLock) {
            localConnWindowConsumed += bytesConsumed;
            long streamConsumed = localStreamWindowConsumed.merge(streamId, (long) bytesConsumed, Long::sum);

            if (localConnWindowConsumed >= WINDOW_UPDATE_THRESHOLD) {
                int inc = (int) localConnWindowConsumed;
                localConnWindowConsumed = 0;
                writeFrame(WindowUpdateFrame.builder()
                        .streamId(0)
                        .windowSizeIncrement(inc)
                        .build());
                needsFlush = true;
            }
            if (streamConsumed >= WINDOW_UPDATE_THRESHOLD) {
                int inc = (int) streamConsumed;
                localStreamWindowConsumed.put(streamId, 0L);
                writeFrame(WindowUpdateFrame.builder()
                        .streamId(streamId)
                        .windowSizeIncrement(inc)
                        .build());
                needsFlush = true;
            }
        }
        if (needsFlush) flushOut();
    }

    private void handleHealth(int streamId) {
        executor.execute(() -> {
            try {
                String body = "<!DOCTYPE html><html><body>OK</body></html>";
                byte[] bodyBytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);

                synchronized (responseEncoder) {
                    byte[] compressed = encodeHeaders(responseEncoder, new String[][]{
                            {":status", "200"},
                            {"content-type", "text/html"},
                            {"server", "platypus-proxy"}
                    });

                    Buffer headBuf = MEM_MGR.allocate(compressed.length);
                    headBuf.put(compressed);
                    headBuf.flip();
                    writeFrame(HeadersFrame.builder()
                            .streamId(streamId)
                            .compressedHeaders(headBuf)
                            .endHeaders(true)
                            .endStream(false)
                            .build());
                }

                Buffer dataBuf = MEM_MGR.allocate(bodyBytes.length);
                dataBuf.put(bodyBytes);
                dataBuf.flip();
                writeFrame(DataFrame.builder()
                        .streamId(streamId)
                        .data(dataBuf)
                        .endStream(true)
                        .build());

                flushOut();
                ProxyApplication.getLogger().Info("[H2] Served /h2health on stream %d", streamId);
            } catch (Exception e) {
                ProxyApplication.getLogger().Error("[H2] /h2health failed: %s", e.getMessage());
            }
        });
    }

    // RFC 9113 §8.5 CONNECT method -- establish tunnel over single H2 stream
    private void handleConnect(int streamId, String authority) {
        if (authority == null || authority.isEmpty()) {
            try {
                writeFrame(RstStreamFrame.builder().streamId(streamId).errorCode(ErrorCode.PROTOCOL_ERROR).build());
            } catch (IOException ignored) {}
            return;
        }

        ProxyApplication.getLogger().Debug("[H2] CONNECT authority='%s' on stream %d", authority, streamId);
        String host;
        int port;
        try {
            String[] hp = authority.split(":");
            host = hp[0];
            port = hp.length > 1 ? Integer.parseInt(hp[1]) : 443;
        } catch (Exception e) {
            ProxyApplication.getLogger().Error("[H2] Failed to parse authority '%s' on stream %d: %s", authority, streamId, e.getMessage());
            try {
                writeFrame(RstStreamFrame.builder().streamId(streamId).errorCode(ErrorCode.PROTOCOL_ERROR).build());
            } catch (IOException ignored) {}
            return;
        }

        StreamState st = new StreamState(streamId);
        st.isTunnel = true;
        st.tunnelInput = new StreamInputStream();
        st.tunnelOutput = new StreamOutputStream(streamId, this);
        streams.put(streamId, st);

        ProxyApplication.getLogger().Info("[H2] CONNECT %s:%d on stream %d (activeTunnels=%d)", host, port, streamId, activeTunnelCount.get());

        try {
            ProxyApplication.getLogger().Debug("[H2] stream %d: acquiring connectSemaphore (available=%d)", streamId, connectSemaphore.availablePermits());
            if (!connectSemaphore.tryAcquire(3000, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                ProxyApplication.getLogger().Error("[H2] stream %d: CONNECT backpressure timeout for %s:%d", streamId, host, port);
                try { writeRstStream(streamId, ErrorCode.REFUSED_STREAM); } catch (IOException ignored) {}
                return;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            ProxyApplication.getLogger().Error("[H2] stream %d: CONNECT backpressure interrupted for %s:%d", streamId, host, port);
            try { writeRstStream(streamId, ErrorCode.REFUSED_STREAM); } catch (IOException ignored) {}
            return;
        }

        activeTunnelCount.incrementAndGet();
        ProxyApplication.getLogger().Debug("[H2] stream %d: dispatching MITM task (activeTunnels=%d)", streamId, activeTunnelCount.get());
        executor.execute(() -> {
            try {
                ProxyApplication.getLogger().Debug("[H2] stream %d: sending CONNECT 200", streamId);
                sendConnect200(streamId);
                ProxyApplication.getLogger().Debug("[H2] stream %d: starting runMitmTunnel", streamId);
                runMitmTunnel(streamId, host, port, st);
                ProxyApplication.getLogger().Debug("[H2] stream %d: runMitmTunnel completed", streamId);
            } catch (Throwable t) {
                ProxyApplication.getLogger().Debug("[H2] MITM failed for %s:%d: %s", host, port,
                        t.toString());
                java.io.ByteArrayOutputStream sw = new java.io.ByteArrayOutputStream();
                t.printStackTrace(new java.io.PrintWriter(sw, true));
                ProxyApplication.getLogger().Debug("[H2] MITM stack: %s", sw.toString());
                try {
                    writeFrame(RstStreamFrame.builder().streamId(streamId).errorCode(ErrorCode.INTERNAL_ERROR).build());
                } catch (IOException ignored) {}
            } finally {
                // The browser closed this MITM tunnel's inner session
                // (e.g. navigating away from the page). Evict cached WARP
                // tunnels for this origin so they don't linger in the pool
                // holding QUIC stream slots on the new page load.
                MitmTunnelConnector.evictFromPool(proxyService, host, port);
                st.tunnelInput.close();
                streams.remove(streamId);
                activeTunnelCount.decrementAndGet();
                connectSemaphore.release();
            }
        });
    }

    // RFC 9113 §8.5 -- proxy sends 2xx HEADERS after TCP connection established
    private void sendConnect200(int streamId) throws IOException {
        synchronized (responseEncoder) {
            byte[] compressed = encodeHeaders(responseEncoder, new String[][]{
                    {":status", "200"},
                    {"server", "platypus-proxy"}
            });
            Buffer headBuf = MEM_MGR.allocate(compressed.length);
            headBuf.put(compressed);
            headBuf.flip();
            writeFrame(HeadersFrame.builder()
                    .streamId(streamId)
                    .compressedHeaders(headBuf)
                    .endHeaders(true)
                    .endStream(false)
                    .build());
        }
        flushOut();
    }

    // RFC 7301 ALPN negotiation; RFC 9113 §9.2 TLS features; TLS inner handshake for MITM
    private void runMitmTunnel(int streamId, String host, int port, StreamState st) throws Exception {
        SSLContext innerCtx = MitmHandler.createMitmSslContext(host);
        SSLEngine innerEngine = innerCtx.createSSLEngine();
        innerEngine.setUseClientMode(false);
        innerEngine.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
        SSLParameters innerParams = innerEngine.getSSLParameters();
        innerParams.setApplicationProtocols(new String[]{"h2", "http/1.1"});
        innerEngine.setSSLParameters(innerParams);

        ReadableByteChannel inCh = Channels.newChannel(st.tunnelInput);
        WritableByteChannel outCh = Channels.newChannel(st.tunnelOutput);

        java.nio.ByteBuffer extraAppData = H2ProxyService.doInnerHandshake(
                innerEngine, inCh, outCh, () -> st.tunnelOutput.flush());

        String negotiated = innerEngine.getApplicationProtocol();
        if (negotiated == null || negotiated.isEmpty()) negotiated = "http/1.1";
        ProxyApplication.getLogger().Info("[H2-MITM] Inner TLS handshake done. ALPN=%s for %s:%d", negotiated, host, port);

        InnerInputStream innerIn = new InnerInputStream(innerEngine, inCh, extraAppData);
        InnerOutputStream innerOut = new InnerOutputStream(innerEngine, outCh, () -> st.tunnelOutput.flush());

        ProxyApplication.getLogger().Debug("[H2-MITM] stream %d: dispatching inner %s handler for %s:%d", streamId, negotiated, host, port);
        if ("h2".equals(negotiated)) {
            MitmHandler.handleH2MitmRequestStream(proxyService, innerIn, innerOut, host, port, executor);
        } else {
            MitmHandler.mitmRequestLoop(proxyService, innerIn, innerOut, host, port);
        }
        ProxyApplication.getLogger().Debug("[H2-MITM] stream %d: inner handler returned for %s:%d", streamId, host, port);
    }

    // RFC 9113 §8.1 HTTP message framing -- HEADERS -> DATA sequence; §5.4.2 stream errors via RST_STREAM
    private void processStream(StreamState st) {
        try {
            streamSemaphore.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            streams.remove(st.id);
            return;
        }
        try {
            if (connectionClosed.get()) {
                return;
            }
            String method = st.headers.get(":method");
            String path = st.headers.get(":path");
            String authority = st.headers.get(":authority");
            String scheme = st.headers.get(":scheme");
            if (method == null || path == null) {
                writeRstStream(st.id, ErrorCode.PROTOCOL_ERROR);
                return;
            }
            String host;
            int port;
            if (authority != null) {
                String[] hp = authority.split(":");
                host = hp[0];
                port = hp.length > 1 ? Integer.parseInt(hp[1]) : ("https".equalsIgnoreCase(scheme) ? 443 : 80);
            } else {
                host = "unknown";
                port = "https".equalsIgnoreCase(scheme) ? 443 : 80;
            }

            // 2ms batch window — let concurrent requests to this host:port
            // accumulate before tunnel creation, so they hit the semaphore
            // simultaneously rather than serially via executor scheduling.
            batchBarrier(host, port);

            String targetHost = authority != null ? authority : host;
            Map<String, String> reqHeaders = new LinkedHashMap<>();
            for (Map.Entry<String, String> e : st.headers.entrySet()) {
                if (!e.getKey().startsWith(":")) reqHeaders.put(e.getKey(), e.getValue());
            }
            String auth = proxyService.authProvider != null ? proxyService.authProvider.get() : null;
            if (auth != null && !auth.isEmpty()) reqHeaders.put("Proxy-Authorization", auth);

            ByteArrayOutputStream bodyBuf = new ByteArrayOutputStream();
            while (true) {
                byte[] chunk = st.bodyQueue.take();
                if (chunk.length == 0) break;
                bodyBuf.write(chunk);
            }
            byte[] bodyBytes = bodyBuf.toByteArray();

            boolean noBody = "HEAD".equalsIgnoreCase(method);

            final int MAX_SSL_RETRIES = 2;
            for (int attempt = 0; attempt <= MAX_SSL_RETRIES; attempt++) {
                if (connectionClosed.get()) {
                    ProxyApplication.getLogger().Debug("[H2] stream %d: connection closed, aborting", st.id);
                    return;
                }
                ProxyApplication.getLogger().Debug("[H2] processStream stream=%d method=%s scheme=%s host=%s port=%d path=%s (attempt %d)",
                        st.id, method, scheme, host, port, path, attempt + 1);
                H2TunnelConnection tunnel = MitmTunnelConnector.connect(proxyService, host, port,
                        scheme != null ? scheme : "https");
                ProxyApplication.getLogger().Debug("[H2] processStream stream=%d: tunnel connected (socket=%s, in=%s)",
                        st.id, tunnel.socket() != null, tunnel.inputStream() != null);
                boolean bodyFullyReceived = false;
                Map<String, List<String>> upstreamRespHeaders = null;
                try {
                    if (connectionClosed.get()) {
                        ProxyApplication.getLogger().Debug("[H2] stream %d: connection closed before upstream request, aborting", st.id);
                        tunnel.close();
                        return;
                    }
                    OutputStream upOut = tunnel.socket().getOutputStream();
                    InputStream upIn = tunnel.inputStream();
                    ProxyApplication.getLogger().Debug("[H2] stream %d: got upOut/upIn, sending %s %s (attempt %d)", st.id, method, path, attempt + 1);

                    proxyService.sendHttpRequest(upOut, method, path, targetHost,
                            reqHeaders, new java.io.ByteArrayInputStream(bodyBytes), bodyBytes.length);
                    ProxyApplication.getLogger().Debug("[H2] stream %d: request sent, waiting for response", st.id);

                    HttpResponseParser parser = new HttpResponseParser(upIn, 65536);
                    parser.parse();
                    if (connectionClosed.get()) {
                        ProxyApplication.getLogger().Debug("[H2] stream %d: connection closed after response parsed, discarding", st.id);
                        tunnel.close();
                        return;
                    }
                    ProxyApplication.getLogger().Debug("[H2] stream %d: response parsed, status=%d", st.id, parser.getStatusCode());
                    int statusCode = parser.getStatusCode();
                    upstreamRespHeaders = parser.getHeaders();
                    InputStream respBody = parser.getBodyStream();
                    InputStream decodedBody = proxyService.decodeBody(respBody, upstreamRespHeaders);
                    noBody = noBody || H2ProxyService.isStatusWithoutBody(statusCode);

                    writeResponseHeaders(st.id, statusCode, upstreamRespHeaders, noBody);
                    ProxyApplication.getLogger().Debug("[H2] stream %d: response headers sent", st.id);
                    if (!noBody && decodedBody != null) {
                        long expectedLen = -1;
                        for (Map.Entry<String, List<String>> he : upstreamRespHeaders.entrySet()) {
                            if ("content-length".equalsIgnoreCase(he.getKey())) {
                                try { expectedLen = Long.parseLong(he.getValue().get(0).trim()); } catch (NumberFormatException nfe) {}
                                break;
                            }
                        }
                        final long TIER1_CAP = 1024L * 1024L;
                        boolean bufferable = expectedLen > 0 && expectedLen <= TIER1_CAP;
                        byte[] buf = new byte[Math.min(maxFrameSize, 262144)];
                        if (bufferable) {
                            java.io.ByteArrayOutputStream bodyAccum = new java.io.ByteArrayOutputStream((int) expectedLen);
                            int n;
                            while ((n = decodedBody.read(buf)) != -1) {
                                if (connectionClosed.get()) {
                                    ProxyApplication.getLogger().Debug("[H2] stream %d: connection closed during body streaming, aborting", st.id);
                                    tunnel.close();
                                    return;
                                }
                                bodyAccum.write(buf, 0, n);
                            }
                            long actualLen = bodyAccum.size();
                            if (actualLen < expectedLen) {
                                ProxyApplication.getLogger().Debug("[H2] stream %d: body truncated (%d/%d bytes), will retry on fresh connection",
                                        st.id, actualLen, expectedLen);
                                tunnel.close();
                                throw new java.io.EOFException("body truncated: got " + actualLen + "/" + expectedLen);
                            }
                            bodyFullyReceived = true;
                            byte[] fullBody = bodyAccum.toByteArray();
                            int offset = 0;
                            while (offset < fullBody.length) {
                                int chunkLen = Math.min(maxFrameSize, fullBody.length - offset);
                                byte[] chunk = new byte[chunkLen];
                                System.arraycopy(fullBody, offset, chunk, 0, chunkLen);
                                sendDataFrame(st.id, chunk, chunkLen, false);
                                offset += chunkLen;
                            }
                        } else {
                            int n;
                            while ((n = decodedBody.read(buf)) != -1) {
                                if (connectionClosed.get()) {
                                    ProxyApplication.getLogger().Debug("[H2] stream %d: connection closed during body streaming, aborting", st.id);
                                    tunnel.close();
                                    return;
                                }
                                byte[] chunk;
                                if (n == buf.length) {
                                    chunk = buf;
                                } else {
                                    chunk = new byte[n];
                                    System.arraycopy(buf, 0, chunk, 0, n);
                                }
                                sendDataFrame(st.id, chunk, n, false);
                            }
                            bodyFullyReceived = true;
                        }
                    }
                    sendDataFrame(st.id, new byte[0], 0, true);
                    ProxyApplication.getLogger().Debug("[H2] stream %d: response body sent, END_STREAM", st.id);

                    if (!H2ProxyService.isConnectionClose(upstreamRespHeaders)) {
                        tunnel.reuse(H2UpstreamPool.hostKey(host, port));
                    } else {
                        tunnel.close();
                    }
                    return;
                } catch (javax.net.ssl.SSLException | java.io.EOFException | java.net.SocketException e) {
                    tunnel.close();
                    if (attempt < MAX_SSL_RETRIES && !connectionClosed.get()) {
                        ProxyApplication.getLogger().Info("[H2] stream %d: IO error on attempt %d (%s), retrying with fresh connection",
                                st.id, attempt + 1, e.getMessage());
                        continue;
                    }
                    throw e;
                } catch (IOException e) {
                    if (bodyFullyReceived && upstreamRespHeaders != null
                            && !H2ProxyService.isConnectionClose(upstreamRespHeaders)) {
                        tunnel.reuse(H2UpstreamPool.hostKey(host, port));
                    } else {
                        tunnel.close();
                    }
                    throw e;
                } catch (Exception e) {
                    tunnel.close();
                    throw e;
                }
            }
        } catch (Exception e) {
            ProxyApplication.getLogger().Error("[H2] stream %d error: %s", st.id, e.getMessage());
            try { writeRstStream(st.id, ErrorCode.INTERNAL_ERROR); } catch (IOException ignored) {}
        } finally {
            streamSemaphore.release();
            streams.remove(st.id);
        }
    }

    // RFC 7541 §3.1 header block encoding -- produces HPACK-compressed byte sequence
    private byte[] encodeHeaders(org.glassfish.grizzly.http2.hpack.Encoder enc) throws IOException {
        throw new UnsupportedOperationException("use encodeHeaders(enc, headers) instead");
    }

    private byte[] encodeHeaders(org.glassfish.grizzly.http2.hpack.Encoder enc, String[][] headers) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Buffer temp = MEM_MGR.allocate(1024);
        try {
            for (String[] h : headers) {
                enc.header(h[0], h[1]);
                boolean done;
                do {
                    temp.clear();
                    int pos = temp.position();
                    done = enc.encode(temp);
                    int written = temp.position() - pos;
                    if (written > 0) {
                        byte[] seg = new byte[written];
                        temp.position(pos);
                        temp.get(seg);
                        baos.write(seg);
                    }
                } while (!done);
            }
        } finally {
            temp.dispose();
        }
        return baos.toByteArray();
    }

    private byte[] encodeHeadersFromMap(org.glassfish.grizzly.http2.hpack.Encoder enc, Map<String, List<String>> headers, int statusCode) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Buffer temp = MEM_MGR.allocate(1024);
        try {
            enc.header(":status", String.valueOf(statusCode));
            boolean done;
            do {
                temp.clear();
                int pos = temp.position();
                done = enc.encode(temp);
                int written = temp.position() - pos;
                if (written > 0) {
                    byte[] seg = new byte[written];
                    temp.position(pos);
                    temp.get(seg);
                    baos.write(seg);
                }
            } while (!done);

            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                String name = e.getKey().toLowerCase(Locale.ENGLISH);
                if (H2ProxyService.HOP_BY_HOP.contains(name) || "connection".equals(name)) continue;
                if (MitmHandler.HTTP2_FORBIDDEN_HEADERS.contains(name)) continue;
                for (String v : e.getValue()) {
                    enc.header(name, v);
                    do {
                        temp.clear();
                        int pos = temp.position();
                        done = enc.encode(temp);
                        int written = temp.position() - pos;
                        if (written > 0) {
                            byte[] seg = new byte[written];
                            temp.position(pos);
                            temp.get(seg);
                            baos.write(seg);
                        }
                    } while (!done);
                }
            }
        } finally {
            temp.dispose();
        }
        return baos.toByteArray();
    }

    // RFC 9113 §8.3.2 response pseudo-headers -- :status mandatory; HPACK-encoded HEADERS frame
    private void writeResponseHeaders(int streamId, int statusCode,
                                       Map<String, List<String>> headers, boolean endStream) throws IOException {
        synchronized (responseEncoder) {
            byte[] compressed = encodeHeadersFromMap(responseEncoder, headers, statusCode);

            if (compressed.length <= maxFrameSize) {
                Buffer headBuf = MEM_MGR.allocate(compressed.length);
                headBuf.put(compressed);
                headBuf.flip();
                writeFrame(HeadersFrame.builder()
                        .streamId(streamId)
                        .compressedHeaders(headBuf)
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
                        boolean endHdrs = (offset + chunkLen >= compressed.length);
                        Buffer data = MEM_MGR.allocate(chunkLen);
                        data.put(compressed, offset, chunkLen);
                        data.flip();
                        writeFrame(ContinuationFrame.builder()
                                .streamId(streamId)
                                .compressedHeaders(data)
                                .endHeaders(endHdrs)
                                .build());
                    }
                    offset += chunkLen;
                }
            }
        }
        flushOut();
    }

    // RFC 9113 §6.1 DATA -- flow-controlled per §5.2; blocks until peer window allows
    void sendDataFrame(int streamId, byte[] data, int len, boolean endStream) throws IOException {
        if (len == 0 && endStream) {
            Buffer buf = MEM_MGR.allocate(1);
            buf.flip();
            writeFrame(DataFrame.builder()
                    .streamId(streamId)
                    .data(buf)
                    .endStream(true)
                    .build());
            flushOut();
            return;
        }
        int offset = 0;
        while (offset < len) {
            int chunkSize = Math.min(maxFrameSize, len - offset);
            Http2Frame frameToSend;

            synchronized (windowLock) {
                while (true) {
                    long peerStreamWindow = peerStreamWindows.getOrDefault(streamId, (long) peerStreamInitialWindow);
                    long allowed = Math.min(peerConnWindow, peerStreamWindow);
                    if (allowed > 0) {
                        int toSend = (int) Math.min(chunkSize, allowed);
                        peerConnWindow -= toSend;
                        peerStreamWindows.put(streamId, peerStreamWindow - toSend);
                        Buffer buf = MEM_MGR.allocate(toSend);
                        buf.put(data, offset, toSend);
                        buf.flip();
                        boolean last = (offset + toSend >= len);
                        frameToSend = DataFrame.builder()
                                .streamId(streamId)
                                .data(buf)
                                .endStream(endStream && last)
                                .build();
                        offset += toSend;
                        break;
                    }
                    try {
                        windowLock.wait(1000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted waiting for window", e);
                    }
                }
            }
            writeFrame(frameToSend);
            flushOut();
        }
    }

    // RFC 9113 §6.4 RST_STREAM -- terminate stream; error codes per §7
    private void writeRstStream(int sid, ErrorCode code) throws IOException {
        writeFrame(RstStreamFrame.builder().streamId(sid).errorCode(code).build());
        flushOut();
        streams.remove(sid);
    }

    // RFC 9113 §4.1 frame format -- serialise frame to 9-octet header + payload bytes
    synchronized void writeFrame(Http2Frame frame) throws IOException {
        if (connectionClosed.get()) {
            throw new IOException("Connection closed");
        }
        Buffer buf = frame.toBuffer(MEM_MGR);
        byte[] bytes = new byte[buf.remaining()];
        buf.get(bytes);
        out.write(bytes);
        buf.tryDispose();
    }

    synchronized void flushOut() throws IOException {
        if (!connectionClosed.get()) {
            out.flush();
        }
    }

    private static byte[] toByteArray(Buffer buf) {
        byte[] data = new byte[buf.remaining()];
        buf.get(data);
        return data;
    }

    static class StreamState {
        final int id;
        Map<String, String> headers;
        final BlockingQueue<byte[]> bodyQueue = new LinkedBlockingQueue<>();
        volatile boolean bodyFinished;
        boolean isTunnel = false;
        StreamInputStream tunnelInput;
        StreamOutputStream tunnelOutput;

        StreamState(int id) { this.id = id; }
    }
}
