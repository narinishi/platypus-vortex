package com.platypus.proxy.handler.h2;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;

/**
 * OutputStream that encrypts plaintext via an {@link SSLEngine} and
 * writes the encrypted bytes to a {@link WritableByteChannel}.  Used
 * for the inner TLS tunnel in the MITM path.
 *
 * <p>The {@code flusher} callback is invoked after each encrypted
 * write to flush the underlying transport (e.g. the outer
 * {@code SSLEngineOutputStream} for h1-over-CONNECT, or a no-op for
 * h2-over-CONNECT where {@link H2StreamTunnel} writes are
 * immediate).
 *
 * <p>When ALPN (<b>RFC 7301 §3.1</b>) selected {@code h2} on the inner
 * TLS connection, the plaintext bytes fed into {@link #write} are
 * HTTP/2 frame bytes per <b>RFC 9113 §4.1</b>.  On {@link #close()} a
 * TLS close_notify is emitted; per <b>RFC 9113 §9.2.1</b> a TLS
 * closure alert signals that no more data will be sent, and SHOULD be
 * preceded by flushing pending data (honoured by {@link #flush()}).
 * HTTP/2 stream closure uses END_STREAM / RST_STREAM (§6.1 / §6.4)
 * rather than close_notify, but close_notify before TCP FIN is the
 * recommended pattern.
 */
class InnerOutputStream extends OutputStream {
    private final SSLEngine engine;
    private final WritableByteChannel out;
    private final Runnable flusher;
    private ByteBuffer appBuf;

    InnerOutputStream(SSLEngine engine, WritableByteChannel out, Runnable flusher) {
        this.engine = engine;
        this.out = out;
        this.flusher = flusher;
        appBuf = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[] {(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] buf, int off, int len) throws IOException {
        while (len > 0) {
            if (!appBuf.hasRemaining()) flush();
            int space = Math.min(len, appBuf.remaining());
            appBuf.put(buf, off, space);
            off += space;
            len -= space;
        }
    }

    @Override
    public void flush() throws IOException {
        if (appBuf.position() == 0) return;
        appBuf.flip();
        ByteBuffer netBuf = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
        while (appBuf.hasRemaining()) {
            netBuf.clear();
            SSLEngineResult r = engine.wrap(appBuf, netBuf);
            netBuf.flip();
            H2ProxyService.writeAll(out, netBuf);
            runFlusher();
            if (r.getStatus() == SSLEngineResult.Status.CLOSED) break;
            H2ProxyService.runDelegatedTasks(engine);
        }
        appBuf.compact();
    }

    @Override
    public void close() throws IOException {
        if (engine.isOutboundDone()) return;
        flush();
        engine.closeOutbound();
        ByteBuffer netBuf = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
        while (!engine.isOutboundDone()) {
            netBuf.clear();
            SSLEngineResult r = engine.wrap(ByteBuffer.allocate(0), netBuf);
            netBuf.flip();
            H2ProxyService.writeAll(out, netBuf);
            runFlusher();
            if (r.getStatus() == SSLEngineResult.Status.CLOSED) break;
            H2ProxyService.runDelegatedTasks(engine);
        }
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
}
