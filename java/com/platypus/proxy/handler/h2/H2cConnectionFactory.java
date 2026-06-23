package com.platypus.proxy.handler.h2;

import com.platypus.proxy.ProxyApplication;
import java.io.IOException;
import java.nio.channels.SocketChannel;
import java.util.concurrent.ExecutorService;
import java.util.function.Supplier;
import org.glassfish.grizzly.Connection;
import org.glassfish.grizzly.filterchain.FilterChain;
import org.glassfish.grizzly.nio.transport.TCPNIOConnection;
import org.glassfish.grizzly.nio.transport.TCPNIOTransport;
import org.glassfish.grizzly.nio.transport.TCPNIOTransportBuilder;
import org.glassfish.grizzly.strategies.WorkerThreadIOStrategy;

// RFC 9113 §3.3 -- cleartext H2; builds a Grizzly transport with InnerH2MitmServerFilter
public final class H2cConnectionFactory {

    private H2cConnectionFactory() {}

    public static Connection<?> open(
            H2ProxyService proxyService,
            SocketChannel channel,
            ExecutorService virtualThreadExecutor,
            Supplier<H2ProxyService.TunnelSupplier> tunnelSupplier)
            throws IOException {
        try {
            channel.configureBlocking(false);

            // Use WorkerThreadIOStrategy to avoid write-side recursion
            TCPNIOTransport transport = TCPNIOTransportBuilder.newInstance()
                    .setIOStrategy(WorkerThreadIOStrategy.getInstance())
                    .build();
            transport.start();

            TCPNIOConnection connection = new TCPNIOConnection(transport, channel);
            org.glassfish.grizzly.http2.Http2Configuration h2Config =
                    InnerH2ConnectionFactory.buildH2Config(virtualThreadExecutor);
            FilterChain chain = InnerH2ConnectionFactory.buildFilterChain(
                    null, h2Config, proxyService, virtualThreadExecutor, tunnelSupplier);
            connection.setProcessor(chain);

            connection.configureBlocking(false);
            transport.fireIOEvent(org.glassfish.grizzly.IOEvent.READ, connection, null);

            ProxyApplication.getLogger().Info("[H2C] Inner h2c connection opened");
            return connection;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("h2c connection open failed: " + e.getMessage(), e);
        }
    }
}
