package com.platypus.proxy.handler.h2;

import com.platypus.proxy.ProxyApplication;
import com.platypus.proxy.handler.cert.SSLContextProvider;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import org.glassfish.grizzly.http.server.NetworkListener;
import org.glassfish.grizzly.ssl.SSLEngineConfigurator;

public class H2Enabler {

    // the prior OldDualProtocolHttp2AddOn
    // (~64 lines) was a complete alternative implementation of the
    // dual-protocol h2 add-on.  The current main() only constructs
    // DualProtocolHttp2AddOn (the live, walk-based replacement) and
    // registers that.  OldDualProtocolHttp2AddOn is therefore dead
    // code in the runtime path; its ALPN handling is replaced by the
    // SSLEngineConfigurator.setApplicationProtocols call in
    // enableH2WithTls (line below).  The class has been removed.
    //
    // dumpFilterChain (used by both paths' debug logging) is kept.
    private static void enableH2WithTls(NetworkListener listener, ExecutorService vtExecutor, H2ProxyService proxyService)
            throws Exception {
        // SSLContext sslContext = createSSLContextFromPKCS12("certs/localhost.p12", "changeit");

        SSLContext sslContext = SSLContextProvider.createSSLContext("localhost", "inmemory");
        ProxyApplication.logger.Debug("Using fresh cert");

        SSLEngineConfigurator engineConfig = new SSLEngineConfigurator(sslContext, false, false, false);
        engineConfig.setEnabledProtocols(new String[] {"TLSv1.3", "TLSv1.2"});

        // RFC 7301 §3.1: advertise ALPN h2/h1 on the outer SSLEngine so the
        // JDK's SSLEngine populates engine.getApplicationProtocol() after
        // the handshake. The AlpnServerNegotiator in OldDualProtocolHttp2AddOn
        // selects the protocol; the engine must agree on the offering or
        // the negotiated value is null and MitmHandler falls back to http/1.1.
        String[] alpnProtocols = new String[] {"h2", "http/1.1"};
        SSLParameters sslParams = new SSLParameters();
        sslParams.setApplicationProtocols(alpnProtocols);
        engineConfig.setSSLParameters(sslParams);

        engineConfig.setEnabledCipherSuites(new String[] {
            // TLS 1.3 (key-type agnostic)
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",

            // TLS 1.2 - ECDSA certificate
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",

            // TLS 1.2 - RSA certificate
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        });

        ProxyApplication.logger.Debug(
                "[ALPN-CONFIG] SSLEngineConfigurator application protocols: %s, enabled protocols: %s",
                Arrays.toString(alpnProtocols), Arrays.toString(engineConfig.getEnabledProtocols()));

        listener.setSecure(true);
        listener.setSSLEngineConfig(engineConfig);
    }

    public static void setH2cfg(
            NetworkListener listener, java.util.concurrent.ExecutorService vtExecutor, H2ProxyService proxyService)
            throws Exception {
        listener.registerAddOn(new H2cDetectionFilter(proxyService));
        enableH2WithTls(listener, vtExecutor, proxyService);

        listener.registerAddOn(new H2AlpnDetectionFilter(proxyService, vtExecutor));
    }


}
