package com.platypus.proxy.handler.h2;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;

/**
 * InputStream that reads decrypted plaintext from an {@link SSLEngine}
 * fed by a {@link ReadableByteChannel}.  Used for the inner TLS tunnel
 * in the MITM path (both h2-over-CONNECT and h1-over-CONNECT).
 *
 * <p>Any stray application data collected during the handshake
 * (via {@link H2ProxyService#doInnerHandshake}) is consumed first so
 * early HTTP/2 preface or HTTP/1.1 request bytes are not lost.
 *
 * <p>When ALPN (<b>RFC 7301 §3.1</b>) selected {@code h2} on the inner
 * TLS connection, the plaintext bytes produced here are HTTP/2 frame
 * bytes per <b>RFC 9113 §4.1</b>; this class is framing-agnostic and
 * just yields decrypted octets.  TLS version is 1.2+ per
 * <b>RFC 9113 §9.2</b>; <b>RFC 8740</b> forbids TLS 1.3 post-handshake
 * authentication on HTTP/2 connections.
 */
class InnerInputStream extends InputStream {
    private final SSLEngine engine;
    private final ReadableByteChannel in;
    private ByteBuffer appBuf;
    private boolean eof;
    private ByteBuffer initialData;

    InnerInputStream(SSLEngine engine, ReadableByteChannel in, ByteBuffer initialData) {
        this.engine = engine;
        this.in = in;
        this.initialData = initialData != null ? initialData.asReadOnlyBuffer() : null;
        appBuf = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());
        appBuf.flip();
    }

    InnerInputStream(SSLEngine engine, ReadableByteChannel in) {
        this(engine, in, null);
    }

    @Override
    public int read() throws IOException {
        byte[] b = new byte[1];
        int n = read(b, 0, 1);
        return n == -1 ? -1 : b[0] & 0xFF;
    }

    @Override
    public int read(byte[] buf, int off, int len) throws IOException {
        if (eof) return -1;
        if (len == 0) return 0;

        if (initialData != null && initialData.hasRemaining()) {
            int n = Math.min(len, initialData.remaining());
            initialData.get(buf, off, n);
            return n;
        }

        while (!appBuf.hasRemaining()) {
            ByteBuffer netBuf;
            try {
                netBuf = H2ProxyService.readFullTlsRecord(in);
            } catch (EOFException e) {
                eof = true;
                return -1;
            }
            appBuf.compact();
            SSLEngineResult r = engine.unwrap(netBuf, appBuf);
            appBuf.flip();
            if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                eof = true;
                if (!appBuf.hasRemaining()) return -1;
            }
        }
        int toRead = Math.min(len, appBuf.remaining());
        appBuf.get(buf, off, toRead);
        return toRead;
    }

    @Override
    public void close() {}
}
