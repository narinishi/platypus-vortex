package com.platypus.proxy.provider;

import com.platypus.proxy.handler.Endpoint;
import com.platypus.proxy.handler.protocol.BaselineProtocol;
import com.platypus.proxy.io.TunnelOpener;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Consumer;
import java.util.function.Supplier;

public class ProviderSession {
    public final Endpoint endpoint;
    public final Supplier<String> authProvider;
    public final long refreshIntervalMs;
    public final Consumer<ScheduledExecutorService> refreshStarter;
    public final BaselineProtocol baselineProtocol;
    public final boolean tlsToBaseline;
    public final ProviderProxyIntercept handshake;
    public final TunnelOpener tunnelOpener;

    public ProviderSession(
            Endpoint endpoint,
            BaselineProtocol baselineProtocol,
            boolean tlsToBaseline,
            Supplier<String> authProvider,
            long refreshIntervalMs,
            Consumer<ScheduledExecutorService> refreshStarter) {
        this(endpoint, baselineProtocol, tlsToBaseline, authProvider, refreshIntervalMs, refreshStarter, null, null);
    }

    public ProviderSession(
            Endpoint endpoint,
            Supplier<String> authProvider,
            long refreshIntervalMs,
            Consumer<ScheduledExecutorService> refreshStarter) {
        this(
                endpoint,
                BaselineProtocol.HTTP_CONNECT,
                endpoint.tlsName() != null && !"".equals(endpoint.tlsName()),
                authProvider,
                refreshIntervalMs,
                refreshStarter,
                null,
                null);
    }

    public ProviderSession(
            Endpoint endpoint,
            BaselineProtocol baselineProtocol,
            boolean tlsToBaseline,
            Supplier<String> authProvider,
            long refreshIntervalMs,
            Consumer<ScheduledExecutorService> refreshStarter,
            ProviderProxyIntercept handshake) {
        this(endpoint, baselineProtocol, tlsToBaseline, authProvider, refreshIntervalMs, refreshStarter, handshake, null);
    }

    public ProviderSession(
            Endpoint endpoint,
            BaselineProtocol baselineProtocol,
            boolean tlsToBaseline,
            Supplier<String> authProvider,
            long refreshIntervalMs,
            Consumer<ScheduledExecutorService> refreshStarter,
            ProviderProxyIntercept handshake,
            TunnelOpener tunnelOpener) {
        this.endpoint = endpoint;
        this.baselineProtocol = baselineProtocol;
        this.tlsToBaseline = tlsToBaseline;
        this.authProvider = authProvider;
        this.refreshIntervalMs = refreshIntervalMs;
        this.refreshStarter = refreshStarter;
        this.handshake = handshake;
        this.tunnelOpener = tunnelOpener;
    }
}
