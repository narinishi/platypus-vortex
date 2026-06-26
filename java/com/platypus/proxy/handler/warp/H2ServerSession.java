package com.platypus.proxy.handler.warp;

import com.platypus.proxy.logging.CondLogger;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.http2.hpack.Decoder;
import org.glassfish.grizzly.http2.hpack.DecodingCallback;
import org.glassfish.grizzly.http2.hpack.Encoder;
import org.glassfish.grizzly.memory.MemoryManager;

final class H2ServerSession implements AutoCloseable {

    static final int FRAME_DATA = 0x0;
    static final int FRAME_HEADERS = 0x1;
    static final int FRAME_RST_STREAM = 0x3;
    static final int FRAME_SETTINGS = 0x4;
    static final int FRAME_PING = 0x6;
    static final int FRAME_GOAWAY = 0x7;
    static final int FRAME_WINDOW_UPDATE = 0x8;

    static final int FLAG_ACK = 0x1;
    static final int FLAG_END_STREAM = 0x1;
    static final int FLAG_END_HEADERS = 0x4;
    static final int FLAG_PADDED = 0x8;
    static final int FLAG_PRIORITY = 0x20;

    private static final byte[] CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.UTF_8);
    private static final int HEADER_TABLE_SIZE = 4096;
    private static final int MAX_FRAME_SIZE = 16384;
    private static final int DEFAULT_INITIAL_WINDOW = 65535;
    private static final int SETTINGS_INITIAL_WINDOW_SIZE = 0x4;

    @FunctionalInterface
    interface ConnectHandler {
        void onConnect(H2ServerSession session, int streamId, ServerStream stream, String authority, Map<String, String> headers) throws IOException;
    }

    @FunctionalInterface
    interface RequestHandler {
        void onRequest(H2ServerSession session, int streamId, ServerStream stream, String method, String authority, String path, Map<String, String> headers) throws IOException;
    }

    private final OutputStream out;
    private final InputStream in;
    private final ConcurrentHashMap<Integer, ServerStream> streams = new ConcurrentHashMap<>();
    private final Thread readerThread;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final Encoder encoder;
    private Decoder decoder;
    private final Object writeLock = new Object();
    private final ConnectHandler connectHandler;
    private final RequestHandler requestHandler;
    private final CondLogger logger;

    // H2 flow control state (peer → us direction: limits how much DATA we can send)
    private volatile int peerInitialWindowSize = DEFAULT_INITIAL_WINDOW;
    private int connWindow = DEFAULT_INITIAL_WINDOW;
    private final ConcurrentHashMap<Integer, Integer> streamWindows = new ConcurrentHashMap<>();

    H2ServerSession(InputStream in, OutputStream out, ConnectHandler connectHandler) throws IOException {
        this(in, out, connectHandler, null, null);
    }

    H2ServerSession(InputStream in, OutputStream out, ConnectHandler connectHandler, CondLogger logger) throws IOException {
        this(in, out, connectHandler, null, logger);
    }

    H2ServerSession(InputStream in, OutputStream out, ConnectHandler connectHandler, RequestHandler requestHandler) throws IOException {
        this(in, out, connectHandler, requestHandler, null);
    }

    H2ServerSession(InputStream in, OutputStream out, ConnectHandler connectHandler, RequestHandler requestHandler, CondLogger logger) throws IOException {
        this.in = in;
        this.out = out;
        this.connectHandler = connectHandler;
        this.requestHandler = requestHandler;
        this.logger = logger;
        this.encoder = new IndexingEncoder(HEADER_TABLE_SIZE);
        this.decoder = new Decoder(HEADER_TABLE_SIZE);

        // Read client preface
        byte[] preface = new byte[CLIENT_PREFACE.length];
        readFully(preface);

        // Read client SETTINGS, reply with ACK
        readClientSettings();

        // Send our SETTINGS
        synchronized (out) {
            sendSettingsFrame(out);
            out.flush();
        }

        this.readerThread = new Thread(this::readerLoop, "h2-server-reader");
        this.readerThread.setDaemon(true);
        this.readerThread.start();
    }

    ServerStream registerStream(int streamId) {
        ServerStream s = new ServerStream(streamId, this);
        streams.put(streamId, s);
        return s;
    }

    void sendHeaders(int streamId, Map<String, String> headers, int flags) throws IOException {
        byte[] hpacked = encodeHeaders(headers);
        writeFrame(FRAME_HEADERS, flags, streamId, hpacked);
    }

    void sendData(int streamId, byte[] data, int off, int len, int flags) throws IOException {
        if (len == 0) {
            if (logger != null) logger.Debug("H2 SEND DATA stream=%d size=0 endStream=%s", streamId, (flags & 0x01) != 0);
            writeFrame(FRAME_DATA, flags, streamId, data, off, 0);
            return;
        }
        int totalLen = len;
        while (len > 0) {
            int chunk = Math.min(MAX_FRAME_SIZE, len);
            consumeWindow(streamId, chunk);
            boolean last = chunk >= len;
            writeFrame(FRAME_DATA, last ? flags : 0, streamId, data, off, chunk);
            off += chunk;
            len -= chunk;
        }
        if (logger != null) logger.Debug("H2 SEND DATA stream=%d size=%d endStream=%s", streamId, totalLen, (flags & 0x01) != 0);
    }

    private void consumeWindow(int streamId, int size) throws IOException {
        synchronized (writeLock) {
            while (true) {
                int sw = streamWindows.getOrDefault(streamId, peerInitialWindowSize);
                if (connWindow >= size && sw >= size) {
                    connWindow -= size;
                    streamWindows.put(streamId, sw - size);
                    return;
                }
                try {
                    writeLock.wait(30000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Flow control wait interrupted");
                }
            }
        }
    }

    void sendData(int streamId, byte[] data, int flags) throws IOException {
        sendData(streamId, data, 0, data.length, flags);
    }

    void sendRstStream(int streamId, int errorCode) throws IOException {
        byte[] payload = new byte[4];
        payload[0] = (byte) (errorCode >> 24);
        payload[1] = (byte) (errorCode >> 16);
        payload[2] = (byte) (errorCode >> 8);
        payload[3] = (byte) errorCode;
        writeFrame(FRAME_RST_STREAM, 0, streamId, payload);
    }

    void removeStream(int streamId) {
        streams.remove(streamId);
    }

    void awaitTermination() throws InterruptedException {
        readerThread.join();
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) return;
        readerThread.interrupt();
    }

    void flushSocket() throws IOException {
        synchronized (writeLock) {
            out.flush();
        }
    }

    void sendPing() throws IOException {
        byte[] opaque = new byte[8];
        // Use nanoTime as opaque data so we can measure RTT from the ACK
        long ts = System.nanoTime();
        opaque[0] = (byte) (ts >> 56);
        opaque[1] = (byte) (ts >> 48);
        opaque[2] = (byte) (ts >> 40);
        opaque[3] = (byte) (ts >> 32);
        opaque[4] = (byte) (ts >> 24);
        opaque[5] = (byte) (ts >> 16);
        opaque[6] = (byte) (ts >> 8);
        opaque[7] = (byte) ts;
        writeFrame(FRAME_PING, 0, 0, opaque);
    }

    // ─── Frame writing ─────────────────────────────────────────────────────

    private void writeFrame(int type, int flags, int streamId, byte[] payload) throws IOException {
        writeFrame(type, flags, streamId, payload, 0, payload != null ? payload.length : 0);
    }

    private void writeFrame(int type, int flags, int streamId, byte[] payload, int off, int len) throws IOException {
        byte[] header = new byte[9];
        header[0] = (byte) (len >> 16);
        header[1] = (byte) (len >> 8);
        header[2] = (byte) len;
        header[3] = (byte) type;
        header[4] = (byte) flags;
        header[5] = (byte) (streamId >> 24);
        header[6] = (byte) (streamId >> 16);
        header[7] = (byte) (streamId >> 8);
        header[8] = (byte) streamId;

        synchronized (writeLock) {
            out.write(header);
            if (payload != null && len > 0) out.write(payload, off, len);
            if (type != FRAME_DATA || (flags & 0x01) != 0) out.flush();
        }
    }

    private void sendSettingsFrame(OutputStream os) throws IOException {
        // SETTINGS_HEADER_TABLE_SIZE = 0 disables the HPACK dynamic table,
        // working around Grizzly HeaderTable$Table.values NPE bug.
        //
        // SETTINGS_HEADER_TABLE_SIZE = 0 disables the HPACK dynamic table,
        // working around Grizzly HeaderTable$Table.values NPE bug.
        //
        // SETTINGS_MAX_CONCURRENT_STREAMS = 100 lets Chrome queue all 336
        // warmup CONNECTs across its H2 connections (6 × 100 = 600) so the
        // warmup completes in ~2s instead of ~10s.  If set too low, warmup
        // stalls and testing-phase AdGuard requests collide with remaining
        // warmup traffic → Chrome blocks them for 5s → AbortController fires.
        byte[] payload = new byte[12];
        // Entry 1: SETTINGS_HEADER_TABLE_SIZE = 0
        payload[0] = 0; payload[1] = 0x01;
        payload[2] = 0; payload[3] = 0; payload[4] = 0; payload[5] = 0;
        // Entry 2: SETTINGS_MAX_CONCURRENT_STREAMS = 100
        payload[6] = 0; payload[7] = 0x03;
        payload[8] = 0; payload[9] = 0; payload[10] = 0; payload[11] = 100;
        byte[] header = new byte[9];
        header[0] = (byte) (12 >> 16);
        header[1] = (byte) (12 >> 8);
        header[2] = (byte) 12;
        header[3] = FRAME_SETTINGS;
        os.write(header);
        os.write(payload);
    }

    private void sendSettingsAck() throws IOException {
        byte[] header = new byte[9];
        header[3] = FRAME_SETTINGS;
        header[4] = FLAG_ACK;
        synchronized (writeLock) {
            out.write(header);
            out.flush();
        }
    }

    // ─── HPACK ──────────────────────────────────────────────────────────────

    private synchronized byte[] encodeHeaders(Map<String, String> headers) throws IOException {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream(4096);
        for (Map.Entry<String, String> e : headers.entrySet()) {
            ((IndexingEncoder) encoder).headerIndexed(e.getKey(), e.getValue());
            Buffer buf = MemoryManager.DEFAULT_MEMORY_MANAGER.allocate(4096);
            try {
                boolean done;
                do {
                    buf.clear();
                    done = encoder.encode(buf);
                    buf.flip();
                    byte[] chunk = new byte[buf.remaining()];
                    buf.get(chunk);
                    baos.write(chunk);
                } while (!done);
            } finally {
                MemoryManager.DEFAULT_MEMORY_MANAGER.release(buf);
            }
        }
        return baos.toByteArray();
    }

    private Map<String, String> decodeHeaders(byte[] hpacked) {
        Buffer buf = MemoryManager.DEFAULT_MEMORY_MANAGER.allocate(hpacked.length);
        try {
            buf.put(hpacked);
            buf.flip();
            Map<String, String> result = new LinkedHashMap<>();
            try {
                decoder.decode(buf, true, new DecodingCallback() {
                    @Override public void onDecoded(CharSequence name, CharSequence value) {
                        result.put(name.toString(), value.toString());
                    }
                });
            } catch (RuntimeException e) {
                // Grizzly HeaderTable bug or stale dynamic ref after table clear.
                // Recreate decoder and fall back to literal-only decode.
                if (logger != null) logger.Debug("H2 HPACK decode error: %s, recreating decoder", e.getMessage());
                this.decoder = new Decoder(0);
                buf.position(0);
                this.decoder.decode(buf, true, new DecodingCallback() {
                    @Override public void onDecoded(CharSequence name, CharSequence value) {
                        result.put(name.toString(), value.toString());
                    }
                });
            }
            return result;
        } finally {
            MemoryManager.DEFAULT_MEMORY_MANAGER.release(buf);
        }
    }

    // ─── Frame reading (reader thread) ─────────────────────────────────────

    private void readerLoop() {
        byte[] headerBuf = new byte[9];
        try {
            while (!closed.get()) {
                readFully(headerBuf);
                int length = (headerBuf[0] & 0xff) << 16 | (headerBuf[1] & 0xff) << 8 | (headerBuf[2] & 0xff);
                int type = headerBuf[3] & 0xff;
                int flags = headerBuf[4] & 0xff;
                int sid = (headerBuf[5] & 0x7f) << 24 | (headerBuf[6] & 0xff) << 16
                        | (headerBuf[7] & 0xff) << 8 | (headerBuf[8] & 0xff);

                byte[] payload = length > 0 ? new byte[length] : new byte[0];
                if (length > 0) readFully(payload);

                switch (type) {
                    case FRAME_HEADERS -> handleHeaders(sid, payload, flags);
                    case FRAME_DATA -> handleData(sid, payload, (flags & FLAG_END_STREAM) != 0);
                    case FRAME_RST_STREAM -> handleRstStream(sid, payload);
                    case FRAME_SETTINGS -> {} // client settings already read; ACKs ignored
                    case FRAME_PING -> handlePing(payload, (flags & FLAG_ACK) != 0);
                    case FRAME_GOAWAY -> {
                        if (logger != null) logger.Debug("H2 GOAWAY received from browser");
                        handleGoaway();
                        return;
                    }
                    case FRAME_WINDOW_UPDATE -> handleWindowUpdate(sid, payload);
                }
            }
        } catch (IOException e) {
            if (logger != null) logger.Debug("H2 reader loop error: %s", e.getMessage());
            failAllStreams();
        }
    }

    private void handleHeaders(int streamId, byte[] payload, int flags) {
        int offset = 0;
        int padLen = 0;
        if ((flags & FLAG_PADDED) != 0) {
            padLen = payload[0] & 0xff;
            offset = 1;
        }
        if ((flags & FLAG_PRIORITY) != 0) {
            offset += 5;
        }
        int hpackLen = payload.length - offset - padLen;
        if (hpackLen <= 0) return;
        byte[] hpacked = new byte[hpackLen];
        System.arraycopy(payload, offset, hpacked, 0, hpackLen);

        Map<String, String> headers = decodeHeaders(hpacked);
        String method = headers.get(":method");
        String authority = headers.get(":authority");
        if (authority == null) return;
        ServerStream s = registerStream(streamId);
        s.clientEndStream = (flags & FLAG_END_STREAM) != 0;
        if ("CONNECT".equals(method)) {
            if (logger != null) logger.Debug("H2 RECV CONNECT stream=%d authority=%s", streamId, authority);
            final long t0 = System.nanoTime();
            Thread.startVirtualThread(() -> {
                if (logger != null) logger.Debug("H2 PROC CONNECT stream=%d authority=%s (queued %.1fms)", streamId, authority, (System.nanoTime() - t0) / 1e6);
                try {
                    connectHandler.onConnect(this, streamId, s, authority, headers);
                } catch (IOException e) {
                    if (logger != null) logger.Debug("H2 CONNECT stream=%d authority=%s exception: %s", streamId, authority, e.getMessage());
                    removeStream(streamId);
                }
            });
        } else if (requestHandler != null) {
            String path = headers.get(":path");
            Thread.startVirtualThread(() -> {
                try {
                    requestHandler.onRequest(this, streamId, s, method, authority, path, headers);
                } catch (IOException e) {
                    removeStream(streamId);
                }
            });
        }
    }

    private void handleData(int streamId, byte[] payload, boolean endStream) {
        ServerStream s = streams.get(streamId);
        if (s != null) {
            if (logger != null) logger.Debug("H2 DATA stream=%d size=%d endStream=%s", streamId, payload.length, endStream);
            s.enqueueData(payload, endStream);
            // NOTE: ABSOLUTELY CRUCICAL
            // Replenish Chrome's send window so it can continue sending
            // HEADERS/DATA on this and other streams. Without this, Chrome's
            // connection-level send window exhausts after ~65KB of outgoing data
            // and all new streams stall permanently.
            sendWindowUpdate(0, payload.length);
            sendWindowUpdate(streamId, payload.length);
        }
    }

    private void sendWindowUpdate(int streamId, int increment) {
        try {
            byte[] incBytes = new byte[4];
            incBytes[0] = (byte) (increment >> 24);
            incBytes[1] = (byte) (increment >> 16);
            incBytes[2] = (byte) (increment >> 8);
            incBytes[3] = (byte) increment;
            writeFrame(FRAME_WINDOW_UPDATE, 0, streamId, incBytes);
        } catch (IOException e) {
            if (logger != null) logger.Debug("H2 WINDOW_UPDATE stream=%d error: %s", streamId, e.getMessage());
        }
    }

    private void handleRstStream(int streamId, byte[] payload) {
        ServerStream s = streams.remove(streamId);
        int errorCode = payload != null && payload.length >= 4
            ? ((payload[0] & 0xFF) << 24) | ((payload[1] & 0xFF) << 16) | ((payload[2] & 0xFF) << 8) | (payload[3] & 0xFF)
            : -1;
        String codeName = switch (errorCode) {
            case 0x1 -> "PROTOCOL_ERROR";
            case 0x2 -> "INTERNAL_ERROR";
            case 0x3 -> "FLOW_CONTROL_ERROR";
            case 0x4 -> "SETTINGS_TIMEOUT";
            case 0x5 -> "STREAM_CLOSED";
            case 0x6 -> "FRAME_SIZE_ERROR";
            case 0x7 -> "REFUSED_STREAM";
            case 0x8 -> "CANCEL";
            case 0x9 -> "COMPRESSION_ERROR";
            case 0xA -> "CONNECT_ERROR";
            case 0xB -> "ENHANCE_YOUR_CALM";
            case 0xC -> "INADEQUATE_SECURITY";
            case 0xD -> "HTTP_1_1_REQUIRED";
            default -> "UNKNOWN(" + errorCode + ")";
        };
        if (s != null) {
            if (logger != null) logger.Debug("H2 RST_STREAM stream=%d error=%s", streamId, codeName);
            s.enqueueRst();
        } else {
            if (logger != null) logger.Debug("H2 RST_STREAM stream=%d error=%s (already removed)", streamId, codeName);
        }
    }

    private void handlePing(byte[] payload, boolean ack) throws IOException {
        if (ack) return;
        byte[] header = new byte[9];
        header[3] = FRAME_PING;
        header[4] = FLAG_ACK;
        synchronized (writeLock) {
            out.write(header);
            out.write(payload);
            out.flush();
        }
    }

    private void handleGoaway() {
        closed.set(true);
        failAllStreams();
    }

    private void handleWindowUpdate(int streamId, byte[] payload) {
        if (payload.length < 4) return;
        int increment = (payload[0] & 0xff) << 24 | (payload[1] & 0xff) << 16
                | (payload[2] & 0xff) << 8 | (payload[3] & 0xff);
        if (increment == 0) return;
        synchronized (writeLock) {
            if (streamId == 0) {
                connWindow += increment;
            } else {
                streamWindows.merge(streamId, increment, Integer::sum);
            }
            writeLock.notifyAll();
        }
        if (logger != null) logger.Debug("H2 WINDOW_UPDATE stream=%d increment=%d", streamId, increment);
    }

    private void failAllStreams() {
        for (ServerStream s : streams.values()) {
            s.enqueueRst();
        }
        streams.clear();
    }

    private void readClientSettings() throws IOException {
        byte[] header = new byte[9];
        while (true) {
            readFully(header);
            int length = (header[0] & 0xff) << 16 | (header[1] & 0xff) << 8 | (header[2] & 0xff);
            int type = header[3] & 0xff;
            int flags = header[4] & 0xff;
            byte[] payload = length > 0 ? new byte[length] : new byte[0];
            if (length > 0) readFully(payload);
            if (type == FRAME_SETTINGS) {
                if ((flags & FLAG_ACK) == 0) {
                    parseSettings(payload);
                    sendSettingsAck();
                }
                return;
            }
        }
    }

    private void parseSettings(byte[] payload) {
        // Settings format: repeated (16-bit id, 32-bit value)
        for (int i = 0; i + 6 <= payload.length; i += 6) {
            int id = (payload[i] & 0xff) << 8 | (payload[i + 1] & 0xff);
            int value = (payload[i + 2] & 0xff) << 24 | (payload[i + 3] & 0xff) << 16
                    | (payload[i + 4] & 0xff) << 8 | (payload[i + 5] & 0xff);
            if (id == SETTINGS_INITIAL_WINDOW_SIZE) {
                peerInitialWindowSize = value;
                synchronized (writeLock) {
                    connWindow = value;
                }
                if (logger != null) logger.Debug("H2 SETTINGS_INITIAL_WINDOW_SIZE = %d", value);
            }
        }
    }

    // ─── I/O helpers ───────────────────────────────────────────────────────

    private void readFully(byte[] dst) throws IOException {
        int off = 0;
        while (off < dst.length) {
            int n = in.read(dst, off, dst.length - off);
            if (n < 0) throw new IOException("Unexpected EOF reading H2 frame");
            off += n;
        }
    }

    // ─── ServerStream (per-stream state) ────────────────────────────────────

    static final class ServerStream {
        final int streamId;
        private final H2ServerSession session;
        private final BlockingQueue<StreamEvent> eventQueue = new LinkedBlockingQueue<>();
        private volatile boolean clientEndStream;
        private volatile boolean rstReceived;

        ServerStream(int streamId, H2ServerSession session) {
            this.streamId = streamId;
            this.session = session;
        }

        void enqueueData(byte[] data, boolean endStream) {
            eventQueue.offer(new StreamEvent(data));
            if (endStream) {
                eventQueue.offer(new StreamEvent(StreamEventType.END_STREAM));
            }
        }

        void enqueueRst() {
            rstReceived = true;
            eventQueue.offer(new StreamEvent(StreamEventType.RST_STREAM));
        }

        InputStream inputStream() {
            return new InputStream() {
                private byte[] buf;
                private int bufPos;

                @Override public int read() throws IOException {
                    byte[] one = new byte[1];
                    int n = read(one, 0, 1);
                    return n == -1 ? -1 : (one[0] & 0xff);
                }

                @Override
                public int read(byte[] dst, int off, int len) throws IOException {
                    if (buf != null) {
                        int remaining = buf.length - bufPos;
                        if (remaining > 0) {
                            int toCopy = Math.min(len, remaining);
                            System.arraycopy(buf, bufPos, dst, off, toCopy);
                            bufPos += toCopy;
                            if (bufPos >= buf.length) buf = null;
                            return toCopy;
                        }
                        buf = null;
                    }
                    while (true) {
                        StreamEvent ev;
                        try {
                            ev = eventQueue.poll(30, TimeUnit.SECONDS);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            throw new IOException("Interrupted");
                        }
                        if (ev == null) throw new IOException("Timeout");
                        switch (ev.type) {
                            case DATA:
                                if (ev.data == null || ev.data.length == 0) continue;
                                int toCopy = Math.min(len, ev.data.length);
                                System.arraycopy(ev.data, 0, dst, off, toCopy);
                                if (toCopy < ev.data.length) {
                                    buf = ev.data;
                                    bufPos = toCopy;
                                }
                                return toCopy;
                            case END_STREAM:
                            case RST_STREAM:
                                return -1;
                        }
                    }
                }

                @Override public void close() {}
            };
        }

        byte[] readChunk() throws IOException {
            while (true) {
                StreamEvent ev;
                try {
                    ev = eventQueue.poll(30, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted");
                }
                if (ev == null) throw new IOException("Timeout");
                switch (ev.type) {
                    case DATA:
                        if (ev.data == null || ev.data.length == 0) continue;
                        return ev.data;
                    case END_STREAM:
                    case RST_STREAM:
                        return null;
                }
            }
        }

        OutputStream outputStream() {
            return new OutputStream() {
                @Override public void write(int b) throws IOException {
                    write(new byte[]{(byte) b}, 0, 1);
                }

                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    if (len > 0) {
                        session.sendData(streamId, b, off, len, 0);
                        session.flushSocket();
                    }
                }

                @Override
                public void close() throws IOException {
                    session.sendData(streamId, new byte[0], FLAG_END_STREAM);
                    session.flushSocket();
                }

                @Override
                public void flush() throws IOException {
                    session.flushSocket();
                }
            };
        }
    }

    enum StreamEventType { DATA, END_STREAM, RST_STREAM }

    static final class StreamEvent {
        final StreamEventType type;
        final byte[] data;

        StreamEvent(byte[] data) {
            this.type = StreamEventType.DATA;
            this.data = data;
        }

        StreamEvent(StreamEventType type) {
            this.type = type;
            this.data = null;
        }
    }

    // ─── HPACK encoder wrapper ─────────────────────────────────────────────

    private static final class IndexingEncoder extends Encoder {
        IndexingEncoder(int maxCapacity) { super(maxCapacity); }
        void headerIndexed(CharSequence name, CharSequence value) { header(name, value); }
    }
}
