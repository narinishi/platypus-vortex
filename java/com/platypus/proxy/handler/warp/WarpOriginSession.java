package com.platypus.proxy.handler.warp;

import com.platypus.proxy.io.warp.TunnelConnection;
import com.platypus.proxy.io.warp.TunnelOpener;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/**
 * NON-LEAK: Always tunneled through WARP. Every constructor path opens an H3
 * CONNECT tunnel via warpOpener.open() before any TLS or H2 layer is applied.
 * There is no direct-socket fallback to the origin.
 */
final class WarpOriginSession implements Closeable {

    private static final SSLContext CLIENT_SSL = createClientSslContext();

    private static SSLContext createClientSslContext() {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, null, new java.security.SecureRandom());
            return ctx;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create client SSLContext", e);
        }
    }

    private final TunnelConnection h3Tunnel;
    private H2ClientSession h2Session;
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile long lastUsedNanos;

    // H1 fallback mode
    private final boolean h1Fallback;
    private final Object h1Lock = new Object();
    private InputStream h1In;
    private OutputStream h1Out;

    /** NON-LEAK: All I/O below goes through h3Tunnel (a WARP H3 CONNECT stream). */
    WarpOriginSession(String host, int port, TunnelOpener warpOpener) throws IOException {
        boolean secure = port == 443;
        this.h3Tunnel = warpOpener.open(host, port);
        this.lastUsedNanos = System.nanoTime();

        if (secure) {
            SSLSocket sslSocket = (SSLSocket) CLIENT_SSL.getSocketFactory()
                    .createSocket(wrapAsSocket(h3Tunnel), host, port, true);
            SSLParameters params = sslSocket.getSSLParameters();
            params.setApplicationProtocols(new String[]{"h2", "http/1.1"});
            sslSocket.setSSLParameters(params);
            sslSocket.startHandshake();
            String alpn = sslSocket.getApplicationProtocol();
            if ("h2".equals(alpn)) {
                this.h2Session = new H2ClientSession(sslSocket.getInputStream(), sslSocket.getOutputStream());
                this.h1Fallback = false;
            } else {
                this.h2Session = null;
                this.h1Fallback = true;
                this.h1In = sslSocket.getInputStream();
                this.h1Out = sslSocket.getOutputStream();
            }
        } else {
            // Cleartext — try H2 prior knowledge
            H2ClientSession h2 = null;
            try {
                h2 = new H2ClientSession(h3Tunnel.inputStream(), h3Tunnel.outputStream(), true);
            } catch (IOException e) {
                // H2 prior knowledge failed
            }
            if (h2 != null) {
                this.h2Session = h2;
                this.h1Fallback = false;
            } else {
                this.h2Session = null;
                this.h1Fallback = true;
                this.h1In = h3Tunnel.inputStream();
                this.h1Out = h3Tunnel.outputStream();
            }
        }
    }

    H2ClientStream newStream() throws IOException {
        if (h1Fallback) {
            return new H1Stream(h1In, h1Out, h1Lock);
        }
        if (closed.get()) throw new IOException("Session closed");
        lastUsedNanos = System.nanoTime();
        return h2Session.newStream();
    }

    H2ClientStream openTunnel() throws IOException {
        H2ClientStream stream = newStream();
        return stream;
    }

    boolean isClosed() { return closed.get(); }
    boolean isIdle(long deadlineNanos) { return lastUsedNanos < deadlineNanos; }
    boolean isH1Fallback() { return h1Fallback; }
    boolean hasH2Session() { return h2Session != null; }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            if (h2Session != null) h2Session.close();
            h3Tunnel.close();
        }
    }

    private static Socket wrapAsSocket(TunnelConnection tunnel) {
        return new Socket() {
            @Override public InputStream getInputStream() { return tunnel.inputStream(); }
            @Override public OutputStream getOutputStream() { return tunnel.outputStream(); }
            @Override public void close() { tunnel.close(); }
            @Override public boolean isClosed() { return false; }
            @Override public boolean isConnected() { return true; }
            @Override public java.net.InetAddress getInetAddress() { return null; }
            @Override public int getPort() { return 0; }
            @Override public void setSoTimeout(int timeout) {}
            @Override public int getSoTimeout() { return 0; }
        };
    }

    // ─── H1 serialized stream (fallback for non-H2 origins) ────────────────

    static final class H1Stream extends H2ClientStream {
        private final InputStream in;
        private final OutputStream out;
        private final Object lock;
        private int statusCode;
        private Map<String, String> responseHeaders;
        private byte[] bodyBuf;
        private boolean done;

        H1Stream(InputStream in, OutputStream out, Object lock) {
            super(0, null);
            this.in = in;
            this.out = out;
            this.lock = lock;
        }

        @Override
        void sendHeaders(Map<String, String> headers, boolean endStream) throws IOException {
            String method = headers.get(":method");
            String path = headers.get(":path");
            String authority = headers.get(":authority");
            if (method == null) method = "GET";
            if (path == null) path = "/";

            synchronized (lock) {
                // Request line
                out.write((method + " " + path + " HTTP/1.1\r\n").getBytes(StandardCharsets.UTF_8));
                out.write(("Host: " + authority + "\r\n").getBytes(StandardCharsets.UTF_8));
                for (Map.Entry<String, String> e : headers.entrySet()) {
                    String k = e.getKey();
                    if (k.startsWith(":")) continue;
                    if ("host".equalsIgnoreCase(k)) continue;
                    out.write((k + ": " + e.getValue() + "\r\n").getBytes(StandardCharsets.UTF_8));
                }
                if (endStream) {
                    out.write("\r\n".getBytes(StandardCharsets.UTF_8));
                    out.flush();
                }
            }
        }

        @Override
        void sendBody(byte[] data, boolean endStream) throws IOException {
            synchronized (lock) {
                out.write(data);
                if (endStream) {
                    out.write("\r\n".getBytes(StandardCharsets.UTF_8));
                    out.flush();
                }
            }
        }

        @Override
        void sendConnectHeaders(String host, int port) throws IOException {
            synchronized (lock) {
                String req = "CONNECT " + host + ":" + port + " HTTP/1.1\r\nHost: " + host + ":" + port + "\r\n\r\n";
                out.write(req.getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        }

        @Override
        int waitForResponse() throws IOException {
            if (done) return statusCode;
            synchronized (lock) {
                // Parse status line
                String statusLine = readLine(in);
                if (statusLine == null || statusLine.isEmpty()) throw new IOException("Empty response");
                String[] parts = statusLine.split(" ", 3);
                int code = parts.length >= 2 ? Integer.parseInt(parts[1]) : 0;

                // Parse headers
                Map<String, String> hdrs = new LinkedHashMap<>();
                String line;
                while ((line = readLine(in)) != null && !line.isEmpty()) {
                    int colon = line.indexOf(":");
                    if (colon > 0) {
                        hdrs.put(line.substring(0, colon).trim().toLowerCase(),
                                 line.substring(colon + 1).trim());
                    }
                }

                // Body
                String contentLenStr = hdrs.get("content-length");
                if (contentLenStr != null) {
                    int len = Integer.parseInt(contentLenStr);
                    bodyBuf = new byte[len];
                    readFully(in, bodyBuf);
                } else if ("chunked".equalsIgnoreCase(hdrs.get("transfer-encoding"))) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    while (true) {
                        String chunkSizeLine = readLine(in);
                        if (chunkSizeLine == null) break;
                        int chunkSize = Integer.parseInt(chunkSizeLine.trim(), 16);
                        if (chunkSize == 0) break;
                        byte[] chunk = new byte[chunkSize];
                        readFully(in, chunk);
                        baos.write(chunk);
                        readLine(in); // trailing CRLF
                    }
                    bodyBuf = baos.toByteArray();
                } else {
                    bodyBuf = new byte[0];
                }

                this.statusCode = code;
                this.responseHeaders = hdrs;
                this.done = true;
                return code;
            }
        }

        @Override
        Map<String, String> responseHeaders() { return responseHeaders; }

        @Override
        InputStream inputStream() {
            return new java.io.ByteArrayInputStream(bodyBuf != null ? bodyBuf : new byte[0]);
        }

        @Override
        OutputStream outputStream() { return out; }

        @Override
        void close() {}

        // Per-thread scratch buffer for readLine
        private static final ThreadLocal<byte[]> LINE_SCRATCH = ThreadLocal.withInitial(() -> new byte[4096]);

        private static String readLine(InputStream in) throws IOException {
            byte[] scratch = LINE_SCRATCH.get();
            int pos = 0;
            boolean eof = false;
            while (pos < scratch.length) {
                int b = in.read();
                if (b == -1) { eof = true; break; }
                if (b == '\r') continue;
                if (b == '\n') break;
                scratch[pos++] = (byte) b;
            }
            return pos > 0 ? new String(scratch, 0, pos, "ISO-8859-1") : (eof ? null : "");
        }

        private static void readFully(InputStream in, byte[] dst) throws IOException {
            int off = 0;
            while (off < dst.length) {
                int n = in.read(dst, off, dst.length - off);
                if (n < 0) throw new IOException("Unexpected EOF");
                off += n;
            }
        }

        @Override
        int streamId() { return 0; }
        @Override InputStream rawInput() { return inputStream(); }
        @Override OutputStream rawOutput() { return outputStream(); }
    }
}
