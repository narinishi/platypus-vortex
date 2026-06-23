package com.platypus.proxy.handler.warp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.http2.hpack.Decoder;
import org.glassfish.grizzly.http2.hpack.DecodingCallback;
import org.glassfish.grizzly.http2.hpack.Encoder;

import org.glassfish.grizzly.memory.MemoryManager;

/**
 * NON-LEAK: Only instantiated inside WarpOriginSession, which opens a WARP
 * H3 CONNECT tunnel first. The streams here are always tunnel-backed.
 */
final class H2ClientSession implements AutoCloseable {

    // H2 frame types
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

    private static final byte[] PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.UTF_8);

    private static final int HEADER_TABLE_SIZE = 4096;
    private static final int MAX_FRAME_SIZE = 16384;

    private final OutputStream out;
    private final InputStream in;
    private final AtomicInteger nextStreamId = new AtomicInteger(1);
    private final ConcurrentHashMap<Integer, H2ClientStream> streams = new ConcurrentHashMap<>();
    private final Thread readerThread;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final Encoder encoder;
    private final Decoder decoder;
    private final Object writeLock = new Object();

    H2ClientSession(InputStream in, OutputStream out) throws IOException {
        this(in, out, false);
    }

    H2ClientSession(InputStream in, OutputStream out, boolean priorKnowledge) throws IOException {
        this.in = in;
        this.out = out;
        this.encoder = new IndexingEncoder(HEADER_TABLE_SIZE);
        this.decoder = new Decoder(HEADER_TABLE_SIZE);

        synchronized (out) {
            out.write(PREFACE);
            sendSettingsFrame(out);
            out.flush();
        }

        readSettingsFrame();

        this.readerThread = new Thread(this::readerLoop, "h2-session-reader");
        this.readerThread.setDaemon(true);
        this.readerThread.start();
    }

    // ─── Public API ─────────────────────────────────────────────────────────

    H2ClientStream newStream() throws IOException {
        checkClosed();
        int streamId = nextStreamId.getAndAdd(2);
        H2ClientStream stream = new H2ClientStream(streamId, this);
        streams.put(streamId, stream);
        return stream;
    }

    void sendHeaders(int streamId, Map<String, String> headers, int flags) throws IOException {
        byte[] hpacked = encodeHeaders(headers);
        writeFrame(FRAME_HEADERS, flags, streamId, hpacked);
    }

    void sendConnectHeaders(int streamId, String host, int port) throws IOException {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(":method", "CONNECT");
        headers.put(":authority", host + ":" + port);
        // RFC 7540 §8.3: :scheme and :path MUST be omitted for CONNECT
        sendHeaders(streamId, headers, FLAG_END_HEADERS);
    }

    void sendData(int streamId, byte[] data, int flags) throws IOException {
        sendData(streamId, data, 0, data.length, flags);
    }

    void sendData(int streamId, byte[] data, int off, int len, int flags) throws IOException {
        if (len == 0) {
            writeFrame(FRAME_DATA, flags, streamId, data, off, 0);
            return;
        }
        while (len > 0) {
            int chunk = Math.min(MAX_FRAME_SIZE, len);
            boolean last = chunk >= len;
            writeFrame(FRAME_DATA, last ? flags : 0, streamId, data, off, chunk);
            off += chunk;
            len -= chunk;
        }
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

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) return;
        readerThread.interrupt();
        try {
            byte[] payload = new byte[8];
            writeFrame(FRAME_GOAWAY, 0, 0, payload);
        } catch (IOException ignored) {}
    }

    // ─── Frame writing ─────────────────────────────────────────────────────

    void flushSocket() throws IOException {
        synchronized (writeLock) {
            out.flush();
        }
    }

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
        // Empty SETTINGS (accept all defaults)
        byte[] header = new byte[9];
        // length=0, type=SETTINGS(4), flags=0, streamId=0
        header[3] = FRAME_SETTINGS;
        os.write(header);
    }

    // ─── HPACK ──────────────────────────────────────────────────────────────

    private byte[] encodeHeaders(Map<String, String> headers) throws IOException {
        Buffer buf = MemoryManager.DEFAULT_MEMORY_MANAGER.allocate(4096);
        try {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                ((IndexingEncoder) encoder).headerIndexed(e.getKey(), e.getValue());
                boolean done;
                do {
                    buf.clear();
                    done = encoder.encode(buf);
                    buf.flip();
                } while (!done);
            }
            // Read the encoded bytes
            byte[] result = new byte[buf.remaining()];
            buf.get(result);
            return result;
        } finally {
            MemoryManager.DEFAULT_MEMORY_MANAGER.release(buf);
        }
    }

    private Map<String, String> decodeHeaders(byte[] hpacked) {
        Buffer buf = MemoryManager.DEFAULT_MEMORY_MANAGER.allocate(hpacked.length);
        try {
            buf.put(hpacked);
            buf.flip();
            Map<String, String> result = new LinkedHashMap<>();
            decoder.decode(buf, true, new DecodingCallback() {
                @Override public void onDecoded(CharSequence name, CharSequence value) {
                    result.put(name.toString(), value.toString());
                }
            });
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
                    case FRAME_HEADERS -> handleHeaders(sid, payload, (flags & FLAG_END_STREAM) != 0);
                    case FRAME_DATA -> handleData(sid, payload, (flags & FLAG_END_STREAM) != 0);
                    case FRAME_RST_STREAM -> handleRstStream(sid, payload);
                    case FRAME_SETTINGS -> handleSettings(payload, (flags & FLAG_ACK) != 0);
                    case FRAME_PING -> handlePing(payload, (flags & FLAG_ACK) != 0);
                    case FRAME_GOAWAY -> { handleGoaway(payload); return; }
                    case FRAME_WINDOW_UPDATE -> handleWindowUpdate(payload);
                }
            }
        } catch (IOException e) {
            failAllStreams();
        }
    }

    private void handleHeaders(int streamId, byte[] payload, boolean endStream) {
        Map<String, String> headers = decodeHeaders(payload);
        H2ClientStream stream = streams.get(streamId);
        if (stream != null) {
            boolean alive = stream.onHeaders(headers, endStream);
            if (!alive) streams.remove(streamId);
        }
    }

    private void handleData(int streamId, byte[] payload, boolean endStream) {
        H2ClientStream stream = streams.get(streamId);
        if (stream != null) {
            boolean alive = stream.onData(payload, endStream);
            if (!alive) streams.remove(streamId);
        }
    }

    private void handleRstStream(int streamId, byte[] payload) {
        int errorCode = 0;
        if (payload.length >= 4) {
            errorCode = (payload[0] & 0xff) << 24 | (payload[1] & 0xff) << 16
                      | (payload[2] & 0xff) << 8 | (payload[3] & 0xff);
        }
        H2ClientStream stream = streams.get(streamId);
        if (stream != null) {
            stream.onRstStream(errorCode);
            streams.remove(streamId);
        }
    }

    private void handleSettings(byte[] payload, boolean ack) throws IOException {
        if (ack) return;
        // Respond with empty ACK
        byte[] header = new byte[9];
        header[3] = FRAME_SETTINGS;
        header[4] = FLAG_ACK;
        synchronized (writeLock) {
            out.write(header);
            out.flush();
        }
    }

    private void handlePing(byte[] payload, boolean ack) throws IOException {
        if (ack) return;
        // Echo back with ACK flag
        byte[] header = new byte[9];
        header[3] = FRAME_PING;
        header[4] = FLAG_ACK;
        synchronized (writeLock) {
            out.write(header);
            out.write(payload);
            out.flush();
        }
    }

    private void handleGoaway(byte[] payload) {
        closed.set(true);
        failAllStreams();
    }

    private void handleWindowUpdate(byte[] payload) {
        // Track connection-level flow control increment from peer
        if (payload.length >= 4) {
            int increment = (payload[0] & 0xff) << 24 | (payload[1] & 0xff) << 16
                          | (payload[2] & 0xff) << 8 | (payload[3] & 0xff);
            // streamId == 0 means connection-level
        }
    }

    private void failAllStreams() {
        for (H2ClientStream s : streams.values()) {
            s.deliverEvent(new H2ClientStream.StreamEvent(H2ClientStream.StreamEventType.RST_STREAM, 0));
        }
        streams.clear();
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

    private void readSettingsFrame() throws IOException {
        byte[] header = new byte[9];
        while (true) {
            readFully(header);
            int length = (header[0] & 0xff) << 16 | (header[1] & 0xff) << 8 | (header[2] & 0xff);
            int type = header[3] & 0xff;
            int flags = header[4] & 0xff;
            byte[] payload = length > 0 ? new byte[length] : new byte[0];
            if (length > 0) readFully(payload);
            if (type == FRAME_SETTINGS && (flags & FLAG_ACK) == 0) return;
            if (type == FRAME_SETTINGS && (flags & FLAG_ACK) != 0) continue;
            // Ignore other frame types during initial handshake
        }
    }

    private void checkClosed() throws IOException {
        if (closed.get()) throw new IOException("H2 session closed");
    }

    // ─── HPACK encoder wrapper ─────────────────────────────────────────────
    // Grizzly's Encoder.header() uses no dynamic table. For optimal compression
    // we'd need HeaderTable which is package-private. Instead we use the
    // default header() path — works correctly, just slightly larger frames.

    private static final class IndexingEncoder extends Encoder {
        IndexingEncoder(int maxCapacity) {
            super(maxCapacity);
        }

        void headerIndexed(CharSequence name, CharSequence value) {
            header(name, value);
        }
    }
}
