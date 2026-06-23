package com.platypus.proxy.handler.h2;

import java.util.concurrent.ExecutorService;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import org.glassfish.grizzly.filterchain.FilterChain;
import org.glassfish.grizzly.filterchain.FilterChainBuilder;
import org.glassfish.grizzly.filterchain.TransportFilter;
import org.glassfish.grizzly.http2.Http2Configuration;
import org.glassfish.grizzly.ssl.SSLBaseFilter;
import org.glassfish.grizzly.ssl.SSLEngineConfigurator;

/**
 * Factory for building the inner-h2 filter chain used by the h2c
 * (cleartext) path.  The h2-over-CONNECT and h1-over-CONNECT paths
 * use {@link InnerInputStream}/{@link InnerOutputStream} +
 * {@link InnerH2MitmHandler} / {@link H2ProxyService#relayHttp1}
 * instead, because their inner connection is a TLS tunnel over
 * the outer HTTP/2 stream (via {@link H2StreamTunnel}) or outer
 * SSLEngine streams, not a raw socket that Grizzly can manage.
 *
 * <p><b>RFC 9113 §3.4</b> requires both endpoints to send a connection
 * preface; for h2c (§3.3) the client preface is the 24-octet magic +
 * SETTINGS and the server preface is a SETTINGS frame (§6.5).
 * <b>RFC 9113 §6.5.2</b> defines the settings configured here:
 * {@code SETTINGS_HEADER_TABLE_SIZE} (0x1, HPACK dynamic table per
 * <b>RFC 7541 §4.2</b>), {@code SETTINGS_ENABLE_PUSH} (0x2),
 * {@code SETTINGS_MAX_CONCURRENT_STREAMS} (0x3, §5.1.2),
 * {@code SETTINGS_INITIAL_WINDOW_SIZE} (0x4, §6.9.2), and
 * {@code SETTINGS_MAX_FRAME_SIZE} (0x5, §4.2).  ALPN offering
 * {@code h2}/{@code http/1.1} per <b>RFC 7301 §3.1</b> and
 * <b>RFC 9113 §3.2</b>; TLS version per <b>RFC 9113 §9.2</b>.
 */
public final class InnerH2ConnectionFactory {

    private InnerH2ConnectionFactory() {}

    public static SSLEngineConfigurator buildSslConfigurator(String host, int port) throws Exception {
        SSLContext ctx = MitmHandler.createMitmSslContext(host);
        SSLEngineConfigurator cfg = new SSLEngineConfigurator(ctx, false, false, false) {
            @Override
            public SSLEngine createSSLEngine(String peerHost, int peerPort) {
                SSLEngine engine = super.createSSLEngine(peerHost, peerPort);
                engine.setUseClientMode(false);
                engine.setEnabledProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
                SSLParameters p = engine.getSSLParameters();
                p.setApplicationProtocols(new String[] {"h2", "http/1.1"});
                engine.setSSLParameters(p);
                return engine;
            }
        };
        return cfg;
    }

    public static Http2Configuration buildH2Config(ExecutorService virtualThreadExecutor) {
        return Http2Configuration.builder()
                .priorKnowledge(true)
                .initialWindowSize(65535)
                .maxFramePayloadSize(16384)
                .maxConcurrentStreams(100)
                .maxHeaderListSize(8192)
                .executorService(virtualThreadExecutor)
                .build();
    }

    public static FilterChain buildFilterChain(
            SSLEngineConfigurator sslConfig,
            Http2Configuration h2Config,
            H2ProxyService proxyService,
            ExecutorService virtualThreadExecutor,
            Supplier<H2ProxyService.TunnelSupplier> tunnelSupplier) {
        FilterChainBuilder builder = FilterChainBuilder.stateless();
        builder.add(new TransportFilter());
        if (sslConfig != null) {
            builder.add(new SSLBaseFilter(sslConfig));
        }
        builder.add(new InnerH2MitmServerFilter(h2Config, proxyService, virtualThreadExecutor, tunnelSupplier));
        return builder.build();
    }
}
