package com.platypus.proxy.handler.h2;

import com.platypus.proxy.ProxyApplication;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.channels.SocketChannel;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.SSLEngine;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.Connection;
import org.glassfish.grizzly.filterchain.BaseFilter;
import org.glassfish.grizzly.filterchain.FilterChainBuilder;
import org.glassfish.grizzly.filterchain.FilterChainContext;
import org.glassfish.grizzly.filterchain.NextAction;
import org.glassfish.grizzly.http.server.AddOn;
import org.glassfish.grizzly.http.server.NetworkListener;
import org.glassfish.grizzly.http.HttpServerFilter;
import org.glassfish.grizzly.nio.NIOConnection;
import org.glassfish.grizzly.ssl.SSLUtils;

/**
 * AddOn + Filter that detects ALPN-negotiated h2 on TLS connections
 * and detaches the socket for raw HTTP/2 handling, bypassing Grizzly's
 * broken AlpnSupport (which fails on JDK 21+).
 *
 * <p>RFC 7301 §3.1 ALPN -- detects h2 via engine.getApplicationProtocol().
 * RFC 9113 §3.4 connection preface -- validates 24-octet H2 magic.
 *
 * <p>For non-h2 connections (http/1.1), passes through to the standard
 * HttpServerFilter unchanged.
 */
public class H2AlpnDetectionFilter extends BaseFilter implements AddOn {

    private static final int PREFACE_LENGTH = 24;
    private static final String ATTR_ACCUMULATOR = H2AlpnDetectionFilter.class.getName() + ".accumulator";
    private static final String ATTR_ALPN_CHECKED = H2AlpnDetectionFilter.class.getName() + ".alpnChecked";

    private final H2ProxyService proxyService;
    private final ExecutorService executor;

    public H2AlpnDetectionFilter(H2ProxyService proxyService, ExecutorService executor) {
        this.proxyService = proxyService;
        this.executor = executor;
    }

    @Override
    public void setup(NetworkListener networkListener, FilterChainBuilder builder) {
        int codecIdx = builder.indexOfType(HttpServerFilter.class);
        if (codecIdx >= 0) {
            builder.add(codecIdx, this);
            ProxyApplication.getLogger().Info("[H2-ALPN] Filter inserted at index %d", codecIdx);
        } else {
            builder.add(this);
            ProxyApplication.getLogger().Info("[H2-ALPN] Filter appended (HttpServerFilter not found)");
        }
    }

    @Override
    public NextAction handleRead(FilterChainContext ctx) throws IOException {
        Connection<?> conn = ctx.getConnection();

        if (Boolean.TRUE.equals(conn.getAttributes().getAttribute(ATTR_ALPN_CHECKED))) {
            return ctx.getInvokeAction();
        }

        SSLEngine engine = SSLUtils.getSSLEngine(conn);
        if (engine == null) {
            conn.getAttributes().setAttribute(ATTR_ALPN_CHECKED, true);
            return ctx.getInvokeAction();
        }

        String alpn = engine.getApplicationProtocol();
        if (alpn == null || alpn.isEmpty() || !"h2".equals(alpn)) {
            conn.getAttributes().setAttribute(ATTR_ALPN_CHECKED, true);
            return ctx.getInvokeAction();
        }

        Object message = ctx.getMessage();
        if (!(message instanceof Buffer)) {
            return ctx.getInvokeAction();
        }

        Buffer buffer = (Buffer) message;
        if (buffer == null || !buffer.hasRemaining()) {
            return ctx.getStopAction();
        }

        ByteArrayOutputStream accumulator =
                (ByteArrayOutputStream) conn.getAttributes().getAttribute(ATTR_ACCUMULATOR);
        if (accumulator == null) {
            accumulator = new ByteArrayOutputStream();
            conn.getAttributes().setAttribute(ATTR_ACCUMULATOR, accumulator);
            ProxyApplication.getLogger().Info("[H2-ALPN] ALPN=h2 detected, accumulating preface on %s",
                    conn.getPeerAddress());
        }

        byte[] chunk = new byte[buffer.remaining()];
        buffer.get(chunk);
        buffer.tryDispose();
        accumulator.write(chunk, 0, chunk.length);

        if (accumulator.size() < PREFACE_LENGTH) {
            return ctx.getStopAction();
        }

        byte[] fullData = accumulator.toByteArray();
        conn.getAttributes().removeAttribute(ATTR_ACCUMULATOR);
        conn.getAttributes().setAttribute(ATTR_ALPN_CHECKED, true);

        if (!isH2Preface(fullData)) {
            ProxyApplication.getLogger().Error("[H2-ALPN] Invalid preface after ALPN h2");
            conn.closeSilently();
            return ctx.getStopAction();
        }

        detachAndHandleH2(ctx, conn, engine, fullData);
        return ctx.getStopAction();
    }

    private void detachAndHandleH2(FilterChainContext ctx, Connection<?> conn,
                                   SSLEngine engine, byte[] accumulatedPlaintext) throws IOException {
        NIOConnection nioConn = (NIOConnection) conn;
        SocketChannel channel = (SocketChannel) nioConn.getChannel();

        if (nioConn.getSelectionKey() != null) {
            nioConn.getSelectionKey().cancel();
        }
        channel.configureBlocking(true);

        ReentrantLock lock = new ReentrantLock();
        SSLEngineInputStream sslIn = new SSLEngineInputStream(engine, channel, channel, lock);
        SSLEngineOutputStream sslOut = new SSLEngineOutputStream(engine, channel, lock);

        ProxyApplication.getLogger().Info("[H2-ALPN] Socket detached, handing off to H2 handler (accumulated=%d bytes)",
                accumulatedPlaintext.length);

        executor.execute(() -> {
            try {
                MitmHandlerH2c.handleH2cConnection(proxyService, sslIn, sslOut,
                        accumulatedPlaintext, executor);
            } catch (IOException e) {
                ProxyApplication.getLogger().Error("[H2-ALPN] Connection failed: %s", e.toString());
            } finally {
                try { sslIn.close(); } catch (IOException ignored) {}
                try { channel.close(); } catch (IOException ignored) {}
            }
        });
    }

    @Override
    public NextAction handleClose(FilterChainContext ctx) {
        ctx.getConnection().getAttributes().removeAttribute(ATTR_ACCUMULATOR);
        return ctx.getInvokeAction();
    }

    private static boolean isH2Preface(byte[] data) {
        if (data.length < PREFACE_LENGTH) return false;
        for (int i = 0; i < PREFACE_LENGTH; i++) {
            if (data[i] != H2cDetectionFilter.HTTP2_MAGIC[i]) return false;
        }
        return true;
    }
}
