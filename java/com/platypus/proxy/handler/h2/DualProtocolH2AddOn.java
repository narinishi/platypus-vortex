package com.platypus.proxy.handler.h2;

import org.glassfish.grizzly.filterchain.FilterChainBuilder;
import org.glassfish.grizzly.http.HttpServerFilter;
import org.glassfish.grizzly.http.server.AddOn;
import org.glassfish.grizzly.http.server.NetworkListener;
import org.glassfish.grizzly.http2.Http2AddOn;
import org.glassfish.grizzly.http2.Http2Configuration;
import org.glassfish.grizzly.http2.Http2ServerFilter;
import org.glassfish.grizzly.nio.transport.TCPNIOTransport;
import org.glassfish.grizzly.strategies.WorkerThreadIOStrategy;

// RFC 9113 §3.2 starting H2 for https URIs -- installs H2MitmServerFilter for
// dual-protocol (h2+http/1.1) on the same port; RFC 7301 ALPN for negotiation
public class DualProtocolH2AddOn implements AddOn {

    private final Http2Configuration http2Config;
    private final H2ProxyService proxyService;

    public DualProtocolH2AddOn(Http2Configuration http2Config, H2ProxyService proxyService) {
        this.http2Config = http2Config;
        this.proxyService = proxyService;
    }

    @Override
    public void setup(NetworkListener networkListener, FilterChainBuilder builder) {
        if (networkListener.getTransport() instanceof TCPNIOTransport t) {
            t.setIOStrategy(WorkerThreadIOStrategy.getInstance());
        }

        Http2AddOn standardAddOn = new Http2AddOn(http2Config);
        standardAddOn.setup(networkListener, builder);

        int codecIdx = builder.indexOfType(HttpServerFilter.class);
        if (codecIdx < 0) return;

        H2MitmServerFilter sessionFilter = new H2MitmServerFilter(http2Config, proxyService);
        sessionFilter.setLocalMaxFramePayloadSize(http2Config.getMaxFramePayloadSize());
        builder.add(codecIdx, sessionFilter);
        com.platypus.proxy.ProxyApplication.getLogger()
                .Info("[DualProtocolH2AddOn] Session filter at index %d", codecIdx);

        int existingH2Idx = builder.indexOfType(Http2ServerFilter.class);
        H2MitmServerFilter mitmFilter = new H2MitmServerFilter(http2Config, proxyService);
        mitmFilter.setLocalMaxFramePayloadSize(http2Config.getMaxFramePayloadSize());
        if (existingH2Idx >= 0) {
            builder.set(existingH2Idx, mitmFilter);
            com.platypus.proxy.ProxyApplication.getLogger()
                .Info("[DualProtocolH2AddOn] Replaced H2 filter at index %d", existingH2Idx);
        } else {
            builder.add(codecIdx + 2, mitmFilter);
            com.platypus.proxy.ProxyApplication.getLogger()
                .Info("[DualProtocolH2AddOn] Inserted H2 filter at index %d", codecIdx + 2);
        }
    }

}
