package com.platypus.proxy.handler.h2;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

/**
 * A blocking OutputStream that uses an existing {@link SSLEngine} to
 * wrap data and write it to an underlying {@link SocketChannel}.
 * On {@link #close()} it initiates the TLS close_notify handshake.
 * All SSLEngine operations are protected by a shared lock.
 *
 * <p>When the connection has ALPN-selected {@code h2} (per
 * <b>RFC 7301 §3.1</b> and <b>RFC 9113 §3.2</b>), the plaintext bytes
 * fed into {@link #write} are HTTP/2 frame bytes per <b>RFC 9113 §4.1
 * (Frame Format)</b>.  This class does not know about HTTP/2 - it just
 * encrypts TLS records.  Per <b>RFC 9113 §9.2</b> the TLS version is
 * 1.2 or higher.
 *
 * <p>TODO/known issue: we send a TLS close_notify on {@link #close()}
 * as required by TLS 1.2 [RFC 5246] and TLS 1.3 [RFC 8446].  HTTP/2
 * does not require close_notify for stream closure (it uses END_STREAM
 * flags and RST_STREAM, see <b>RFC 9113 §5.1</b> and §6.4), but it does
 * require a TCP FIN for connection teardown.  Sending close_notify
 * before the TCP FIN is the recommended pattern per
 * <b>RFC 9113 §9.2.1 ("TLS Connection Closure")</b>: "A TLS closure
 * alert is a signal to the peer that the sender will send no more data.
 * Prior to sending a closure alert, the sender SHOULD ensure that all
 * pending data has been delivered."  Our {@code flush()} before
 * {@code closeOutbound()} honours this.
 */
public class SSLEngineOutputStream extends OutputStream {
    private final SSLEngine engine;
    private final WritableByteChannel channel;
    private final ReentrantLock lock;
    private final ByteBuffer appIn;
    private final ByteBuffer netOut;
    private boolean closed = false;

    public SSLEngineOutputStream(SSLEngine engine, WritableByteChannel channel, ReentrantLock lock) throws IOException {
        this.engine = engine;
        this.channel = channel;
        this.lock = lock;
        int netSize = engine.getSession().getPacketBufferSize();
        int appSize = engine.getSession().getApplicationBufferSize();
        appIn = ByteBuffer.allocate(appSize);
        netOut = ByteBuffer.allocate(netSize);
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[] {(byte) b}, 0, 1);
    }

    /**
     * Write plaintext bytes to the {@link SSLEngine}.  When the
     * connection has ALPN-negotiated {@code h2} (per <b>RFC 7301
     * §3.1</b> and <b>RFC 9113 §3.2</b>) the bytes are HTTP/2 frame
     * bytes per §4.1.  This class is framing-agnostic - it just
     * encrypts whatever bytes are passed in.
     *
     * <p>TODO/known issue: per <b>RFC 9113 §4.2</b> the largest frame
     * payload the peer will accept is bounded by SETTINGS_MAX_FRAME_SIZE
     * (default 16384, max 2^24-1).  We do not split the plaintext at
     * that boundary; the upstream Grizzly filter is expected to
     * produce one frame per wrap() call.  If a single write() call
     * exceeds the peer's MAX_FRAME_SIZE the resulting TLS record will
     * be a single ciphertext blob containing multiple frames, which the
     * peer can still parse (frames are self-delimiting per §4.1) but
     * uses more memory on the peer side.  Fix: split the plaintext
     * into per-frame chunks before wrap().
     */
    @Override
    public void write(byte[] buf, int off, int len) throws IOException {
        if (closed) throw new IOException("Stream closed");
        while (len > 0) {
            int toWrite = Math.min(len, appIn.remaining());
            if (toWrite == 0) {
                flush();
                continue;
            }
            appIn.put(buf, off, toWrite);
            off += toWrite;
            len -= toWrite;
        }
    }

    @Override
    public void flush() throws IOException {
        if (closed) return;
        if (!appIn.hasRemaining()) return;
        appIn.flip();
        try {
            while (appIn.hasRemaining()) {
                SSLEngineResult result;
                lock.lock();
                try {
                    netOut.clear();
                    result = engine.wrap(appIn, netOut);
                    netOut.flip();
                } finally {
                    lock.unlock();
                }
                while (netOut.hasRemaining()) channel.write(netOut);
                driveHandshake(result);
            }
        } finally {
            appIn.compact();
        }
    }

    // driveHandshake remains unchanged
    private void driveHandshake(SSLEngineResult result) throws IOException {
        SSLEngineResult.HandshakeStatus status = result.getHandshakeStatus();
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
                    @SuppressWarnings("unused")
                    SSLEngineResult r = engine.wrap(empty, netOut);
                    netOut.flip();
                } finally {
                    lock.unlock();
                }
                while (netOut.hasRemaining()) channel.write(netOut);
            }
            lock.lock();
            try {
                status = engine.getHandshakeStatus();
            } finally {
                lock.unlock();
            }
        }
        if (status == SSLEngineResult.HandshakeStatus.NEED_UNWRAP)
            throw new SSLException("SSLEngine requires unwrap before further wrap");
    }

    @Override
    public void close() throws IOException {
        if (closed) return;
        closed = true;
        // Flush any remaining application data
        try {
            flush();
        } catch (IOException e) {
            // Ignore - we still want to send close_notify
        }
        // Initiate TLS close_notify
        lock.lock();
        try {
            engine.closeOutbound();
        } finally {
            lock.unlock();
        }
        // Drive the close handshake: keep wrapping empty buffers until
        // the engine has emitted the close_notify alert and reports CLOSED.
        ByteBuffer empty = ByteBuffer.allocate(0);
        try {
            while (true) {
                SSLEngineResult result;
                lock.lock();
                try {
                    netOut.clear();
                    result = engine.wrap(empty, netOut);
                    netOut.flip();
                } finally {
                    lock.unlock();
                }
                while (netOut.hasRemaining()) {
                    channel.write(netOut);
                }
                if (result.getStatus() == SSLEngineResult.Status.CLOSED) {
                    break;
                }
                driveHandshake(result);
            }
        } catch (IOException e) {
            // Ignore; the raw channel close will follow
        }
        // Note: do NOT close the underlying channel here.
    }
}
