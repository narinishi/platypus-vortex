package com.platypus.proxy.handler.warp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/** NON-LEAK: Backed by H2ClientSession which is always tunneled through WARP. */
class H2ClientStream {

    static final int FLAG_END_STREAM = 0x1;
    static final int FLAG_END_HEADERS = 0x4;

    private final int streamId;
    private final H2ClientSession session;

    private final BlockingQueue<StreamEvent> eventQueue = new LinkedBlockingQueue<>();

    private volatile int statusCode = -1;
    private volatile Map<String, String> responseHeaders;
    private volatile boolean headersReceived;
    private volatile boolean responseDone;
    private volatile boolean rstReceived;

    // CONNECT tunnel mode
    private volatile boolean tunnelMode;
    private final Object tunnelLock = new Object();
    private boolean tunnelClosed;
    private int totalDataIn;
    private int totalDataOut;

    H2ClientStream(int streamId, H2ClientSession session) {
        this.streamId = streamId;
        this.session = session;
    }

    int streamId() { return streamId; }
    boolean isTunnelMode() { return tunnelMode; }

    void sendHeaders(Map<String, String> headers, boolean endStream) throws IOException {
        session.sendHeaders(streamId, headers, endStream ? FLAG_END_STREAM | FLAG_END_HEADERS : FLAG_END_HEADERS);
    }

    void sendBody(byte[] data, boolean endStream) throws IOException {
        session.sendData(streamId, data, endStream ? FLAG_END_STREAM : 0);
    }

    void sendConnectHeaders(String host, int port) throws IOException {
        session.sendConnectHeaders(streamId, host, port);
        tunnelMode = true;
    }

    int waitForResponse() throws IOException {
        if (headersReceived) return statusCode;
        while (true) {
            StreamEvent ev;
            try {
                ev = eventQueue.poll(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted waiting for response headers");
            }
            if (ev == null) throw new IOException("Timeout waiting for response headers");
            if (ev.type == StreamEventType.HEADERS) {
                statusCode = parseStatus(ev.headers);
                responseHeaders = ev.headers;
                headersReceived = true;
                return statusCode;
            }
            if (ev.type == StreamEventType.RST_STREAM) {
                rstReceived = true;
                responseDone = true;
                throw new IOException("Stream reset: error=" + ev.errorCode);
            }
        }
    }

    Map<String, String> responseHeaders() { return responseHeaders; }

    InputStream inputStream() {
        return new InputStream() {
            private byte[] buf;
            private int bufPos;

            @Override
            public int read() throws IOException {
                byte[] one = new byte[1];
                int n = read(one, 0, 1);
                return n == -1 ? -1 : (one[0] & 0xff);
            }

            @Override
            public int read(byte[] dst, int off, int len) throws IOException {
                if (responseDone) return -1;
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
                        throw new IOException("Interrupted reading response body");
                    }
                    if (ev == null) throw new IOException("Timeout reading response body");
                    switch (ev.type) {
                        case DATA:
                            if (ev.data == null || ev.data.length == 0) continue;
                            int toCopy = Math.min(len, ev.data.length);
                            totalDataIn += toCopy;
                            if (tunnelMode && System.err != null) {
                                System.err.println("[H2S] stream " + streamId + " DATA in: " + toCopy + " bytes (total: " + totalDataIn + ") endStream=" + false);
                            }
                            System.arraycopy(ev.data, 0, dst, off, toCopy);
                            if (toCopy < ev.data.length) {
                                buf = ev.data;
                                bufPos = toCopy;
                            }
                            return toCopy;
                        case END_STREAM:
                        case RST_STREAM:
                            responseDone = true;
                            return -1;
                        case HEADERS:
                            // Trailers — ignore for now
                            continue;
                    }
                }
            }

            @Override
            public void close() {}
        };
    }

    OutputStream outputStream() {
        return new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                write(new byte[]{(byte) b}, 0, 1);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                if (tunnelMode) {
                    totalDataOut += len;
                    if (System.err != null) {
                        System.err.println("[H2S] stream " + streamId + " DATA out: " + len + " bytes (total: " + totalDataOut + ")");
                    }
                    session.sendData(streamId, b, off, len, 0);
                    session.flushSocket();
                } else {
                    sendBody(b, false);
                }
            }

            @Override
            public void close() throws IOException {
                if (tunnelMode) {
                    synchronized (tunnelLock) {
                        tunnelClosed = true;
                        tunnelLock.notifyAll();
                    }
                    session.sendData(streamId, new byte[0], FLAG_END_STREAM);
                }
            }
        };
    }

    InputStream rawInput() { return inputStream(); }
    OutputStream rawOutput() { return outputStream(); }

    void close() {
        try {
            session.sendRstStream(streamId, 0x8); // CANCEL
        } catch (IOException ignored) {}
        session.removeStream(streamId);
    }

    void deliverEvent(StreamEvent ev) {
        eventQueue.offer(ev);
        if (ev.type == StreamEventType.END_STREAM || ev.type == StreamEventType.RST_STREAM) {
            responseDone = true;
        }
    }

    private static int parseStatus(Map<String, String> headers) {
        String s = headers.get(":status");
        if (s != null) {
            try { return Integer.parseInt(s); } catch (NumberFormatException e) { /* fall through */ }
        }
        return 0;
    }

    // Called by the reader thread when it receives a DATA frame for this stream.
    // Returns false if the stream is done and should be removed.
    boolean onData(byte[] data, boolean endStream) {
        deliverEvent(new StreamEvent(StreamEventType.DATA, data));
        if (endStream) {
            deliverEvent(new StreamEvent(StreamEventType.END_STREAM));
            return false; // stream done, remove from session
        }
        return true;
    }

    boolean onHeaders(Map<String, String> headers, boolean endStream) {
        deliverEvent(new StreamEvent(headers));
        if (endStream) {
            deliverEvent(new StreamEvent(StreamEventType.END_STREAM));
            return false;
        }
        return true;
    }

    void onRstStream(int errorCode) {
        deliverEvent(new StreamEvent(StreamEventType.RST_STREAM, errorCode));
    }

    // ─── Stream event types ────────────────────────────────────────────────

    enum StreamEventType { HEADERS, DATA, END_STREAM, RST_STREAM }

    static final class StreamEvent {
        final StreamEventType type;
        final Map<String, String> headers;
        final byte[] data;
        final int errorCode;

        StreamEvent(Map<String, String> headers) {
            this.type = StreamEventType.HEADERS;
            this.headers = headers;
            this.data = null;
            this.errorCode = 0;
        }

        StreamEvent(StreamEventType type, byte[] data) {
            this.type = type;
            this.headers = null;
            this.data = data;
            this.errorCode = 0;
        }

        StreamEvent(StreamEventType type) {
            this.type = type;
            this.headers = null;
            this.data = null;
            this.errorCode = 0;
        }

        StreamEvent(StreamEventType type, int errorCode) {
            this.type = type;
            this.headers = null;
            this.data = null;
            this.errorCode = errorCode;
        }
    }
}
