package com.platypus.proxy.handler.h2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.Connection;
import org.glassfish.grizzly.filterchain.BaseFilter;
import org.glassfish.grizzly.filterchain.FilterChainBuilder;
import org.glassfish.grizzly.filterchain.FilterChainContext;
import org.glassfish.grizzly.filterchain.NextAction;
import org.glassfish.grizzly.http.server.AddOn;
import org.glassfish.grizzly.http.server.NetworkListener;
import org.glassfish.grizzly.nio.NIOConnection;

/**
 * Detects h2c magic and hands off the raw socket to {@link MitmHandlerH2c}.
 *
 * <p>RFC 9113 §3.3 starting H2 with prior knowledge -- detects cleartext
 * H2 connection preface (24-octet magic "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").
 */
public class H2cDetectionFilter extends BaseFilter implements AddOn {

    private final H2ProxyService proxyService;
    private static final int H2C_MAGIC_LENGTH = 24;
    public static final byte[] HTTP2_MAGIC = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            .getBytes(StandardCharsets.UTF_8);

    public H2cDetectionFilter(H2ProxyService proxyService) {
        this.proxyService = proxyService;
    }

    private static String accumulatorKey() {
        return H2cDetectionFilter.class.getName() + ".buffer";
    }

    @Override
    public void setup(NetworkListener networkListener, FilterChainBuilder builder) {
        builder.addFirst(this);
    }

    @Override
    public NextAction handleRead(FilterChainContext ctx) throws IOException {
        Buffer message = ctx.getMessage();
        if (message == null) return ctx.getInvokeAction();

        Connection<?> connection = ctx.getConnection();

        if (org.glassfish.grizzly.ssl.SSLUtils.getSSLEngine(connection) != null) {
            return ctx.getInvokeAction();
        }

        ByteArrayOutputStream accumulator =
                (ByteArrayOutputStream) connection.getAttributes().getAttribute(accumulatorKey());
        if (accumulator == null) {
            accumulator = new ByteArrayOutputStream();
            connection.getAttributes().setAttribute(accumulatorKey(), accumulator);
        }
        byte[] chunk = new byte[message.remaining()];
        message.get(chunk);
        message.tryDispose();
        accumulator.write(chunk, 0, chunk.length);

        if (accumulator.size() < H2C_MAGIC_LENGTH) {
            return ctx.getStopAction();
        }

        byte[] fullData = accumulator.toByteArray();
        connection.getAttributes().removeAttribute(accumulatorKey());

        if (isH2cMagic(fullData)) {
            handleH2c(ctx, fullData);
            return ctx.getStopAction();
        }

        Buffer replay = org.glassfish.grizzly.memory.MemoryManager.DEFAULT_MEMORY_MANAGER
                .allocate(fullData.length);
        replay.put(fullData);
        replay.flip();
        ctx.setMessage(replay);
        return ctx.getInvokeAction();
    }

    @Override
    public NextAction handleClose(FilterChainContext ctx) {
        ctx.getConnection().getAttributes().removeAttribute(accumulatorKey());
        return ctx.getInvokeAction();
    }

    private static boolean isH2cMagic(byte[] data) {
        if (data.length < H2C_MAGIC_LENGTH) return false;
        for (int i = 0; i < H2C_MAGIC_LENGTH; i++) {
            if (data[i] != HTTP2_MAGIC[i]) return false;
        }
        return true;
    }

    private void handleH2c(FilterChainContext ctx, byte[] soFar) throws IOException {
        NIOConnection nioConn = (NIOConnection) ctx.getConnection();
        SocketChannel channel = (SocketChannel) nioConn.getChannel();
        if (nioConn.getSelectionKey() != null) nioConn.getSelectionKey().cancel();

        // Switch to blocking mode for raw I/O
        channel.configureBlocking(true);
        InputStream rawIn = channel.socket().getInputStream();
        OutputStream rawOut = channel.socket().getOutputStream();

        MitmHandlerH2c.handleH2cConnection(proxyService, rawIn, rawOut, soFar);
    }
}
