package com.platypus.proxy.handler.h2;

import com.platypus.proxy.ProxyApplication;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

/**
 * A blocking InputStream that uses an existing {@link SSLEngine} to
 * unwrap data read from an underlying {@link SocketChannel}.  Access
 * to the SSLEngine is synchronised with a given {@link ReentrantLock}.
 *
 * <p>When the connection has ALPN-selected {@code h2} (per
 * <b>RFC 7301 §3.1</b> and <b>RFC 9113 §3.2</b>), the plaintext bytes
 * produced here are HTTP/2 frame bytes per <b>RFC 9113 §4.1 (Frame
 * Format)</b>.  The framing is invisible to this class - it just
 * decrypts TLS records and yields plaintext octets.  The TLS protocol
 * version is at least 1.2 per <b>RFC 9113 §9.2</b>.
 *
 * <p>TODO/known issue: we read one TLS record at a time via
 * {@code channel.read(netIn)}; the netIn buffer is sized to one packet
 * worth of ciphertext.  HTTP/2 has no opinion on TLS record size, but
 * for performance it is usually desirable to size the netIn to the
 * kernel TCP receive buffer (typically 64-256 KB).  Fix: enlarge netIn
 * to {@code engine.getSession().getPacketBufferSize()} (currently
 * honoured) or to a fixed larger value (e.g., 64 KB) - the latter is
 * what the kernel actually delivers.
 *
 * <p><b>RFC 8740</b> forbids TLS 1.3 post-handshake
 * CertificateRequest on HTTP/2 connections; the only TLS handshake
 * occurs before the HTTP/2 connection preface (§3.4).  The ALPN
 * protocol ID registry is maintained per <b>RFC 8447</b> (which updates
 * RFC 7301).  <b>RFC 8164</b> describes opportunistic security for
 * {@code http} URIs over HTTP/2 (not applicable to this MITM path).
 */
public class SSLEngineInputStream extends InputStream {
    private final SSLEngine engine;
    private final ReadableByteChannel channel;
    private final WritableByteChannel writeChannel;
    private final ReentrantLock lock;
    private final ByteBuffer netIn; // encrypted data from channel
    private ByteBuffer appOut; // decrypted data for application
    private boolean closed = false;

    public SSLEngineInputStream(SSLEngine engine, ReadableByteChannel channel, WritableByteChannel writeChannel, ReentrantLock lock) throws IOException {
        this(engine, channel, writeChannel, lock, null);
    }

    public SSLEngineInputStream(SSLEngine engine, ReadableByteChannel channel, WritableByteChannel writeChannel, ReentrantLock lock, ByteBuffer initialAppData) throws IOException {
        this.engine = engine;
        this.channel = channel;
        this.writeChannel = writeChannel;
        this.lock = lock;
        int netSize = Math.max(engine.getSession().getPacketBufferSize(), 131072);
        int appSize = engine.getSession().getApplicationBufferSize();
        netIn = ByteBuffer.allocate(netSize);
        if (initialAppData != null && initialAppData.hasRemaining()) {
            appOut = initialAppData;
            ProxyApplication.getLogger().Debug("[SSL-IN] Preserving %d leftover TLS handshake bytes", appOut.remaining());
        } else {
            appOut = ByteBuffer.allocate(appSize);
            appOut.flip();
        }
        netIn.flip();
    }

    @Override
    public int read() throws IOException {
        if (closed) return -1;
        if (!appOut.hasRemaining()) {
            int n = fillAppBuffer();
            if (n < 0) {
                closed = true;
                return -1;
            }
        }
        return appOut.get() & 0xFF;
    }

    /**
     * Read up to {@code len} plaintext bytes from the {@link SSLEngine}.
     *
     * <p>Per <b>RFC 9113 §3.2</b> when ALPN negotiates {@code h2}
     * (wire bytes {@code 0x68 0x32}, per <b>RFC 7301 §3.1</b>) the
     * plaintext bytes are HTTP/2 frame bytes per §4.1.  This class
     * does not parse the framing - it only decrypts TLS records and
     * yields plaintext octets.
     *
     * <p>TODO/known issue: per <b>RFC 9113 §9.2</b> "HTTP/2 over TLS
     * MUST use TLS 1.2 or higher."  We rely on the caller to set the
     * {@link SSLEngine}'s enabled protocols; we do not double-check
     * here.  Fix: assert {@code engine.getSession().getProtocol()}
     * returns a TLS 1.2+ identifier before yielding the first
     * plaintext byte.
     */
    @Override
    public int read(byte[] buf, int off, int len) throws IOException {
        if (closed) return -1;
        if (len == 0) return 0;
        if (!appOut.hasRemaining()) {
            int n = fillAppBuffer();
            if (n < 0) {
                closed = true;
                return -1;
            }
        }
        int count = Math.min(appOut.remaining(), len);
        appOut.get(buf, off, count);
        return count;
    }

    private int fillAppBuffer() throws IOException {
        appOut.compact();
        try {
            while (true) {
                if (appOut.position() > 0) {
                    appOut.flip();
                    return appOut.remaining();
                }
                if (!netIn.hasRemaining()) {
                    netIn.clear();
                    int n = channel.read(netIn);
                    if (n == -1) return handleEof();
                    netIn.flip();
                }
                SSLEngineResult result;
                lock.lock();
                try {
                    result = engine.unwrap(netIn, appOut);
                } finally {
                    lock.unlock();
                }
                switch (result.getStatus()) {
                    case BUFFER_OVERFLOW:
                        appOut.flip();
                        ByteBuffer larger = ByteBuffer.allocate(appOut.capacity() * 2);
                        larger.put(appOut);
                        appOut = larger;
                        continue;
                    case BUFFER_UNDERFLOW:
                        netIn.compact();
                        int underflowRead = channel.read(netIn);
                        if (underflowRead == -1) return handleEof();
                        netIn.flip();
                        continue;
                    case CLOSED:
                        appOut.flip();
                        return appOut.hasRemaining() ? appOut.remaining() : -1;
                    case OK:
                        break;
                }
                driveHandshake(result);
            }
        } catch (IOException e) {
            lock.lock();
            try {
                engine.closeInbound();
            } catch (Exception ignored) {
            } finally {
                lock.unlock();
            }
            throw e;
        }
    }

    private int handleEof() throws IOException {
        if (netIn.position() > 0) {
            netIn.flip();
            SSLEngineResult result;
            lock.lock();
            try {
                result = engine.unwrap(netIn, appOut);
            } finally {
                lock.unlock();
            }
            if (appOut.position() > 0) {
                appOut.flip();
                return appOut.remaining();
            }
            if (result.getStatus() == SSLEngineResult.Status.CLOSED) {
                appOut.flip();
                return appOut.hasRemaining() ? appOut.remaining() : -1;
            }
        }
        lock.lock();
        try {
            engine.closeInbound();
        } catch (SSLException ignored) {
        } finally {
            lock.unlock();
        }
        return -1;
    }

    private void driveHandshake(SSLEngineResult result) throws IOException {
        SSLEngineResult.HandshakeStatus status = result.getHandshakeStatus();
        ByteBuffer netOut = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
        ByteBuffer empty = ByteBuffer.allocate(0);
        while (status == SSLEngineResult.HandshakeStatus.NEED_TASK
                || status == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            if (status == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                Runnable task;
                lock.lock();
                try {
                    task = engine.getDelegatedTask();
                } finally {
                    lock.unlock();
                }
                if (task != null) task.run();
            } else {
                lock.lock();
                try {
                    netOut.clear();
                    engine.wrap(empty, netOut);
                    netOut.flip();
                } finally {
                    lock.unlock();
                }
                while (netOut.hasRemaining()) writeChannel.write(netOut);
            }
            lock.lock();
            try {
                status = engine.getHandshakeStatus();
            } finally {
                lock.unlock();
            }
        }
    }

    @Override
    public void close() throws IOException {
        closed = true;
    }
}
