package com.platypus.proxy;

import com.platypus.proxy.handler.Endpoint;
import com.platypus.proxy.handler.HealthHandler;
import com.platypus.proxy.handler.ProxyHandler;
import com.platypus.proxy.handler.h2.H2Enabler;
import com.platypus.proxy.handler.h2.H2ProxyService;
import com.platypus.proxy.handler.warp.WarpServe;
import com.platypus.proxy.io.TcpConnector;
import com.platypus.proxy.io.TunnelOpener;
import com.platypus.proxy.logging.CondLogger;
import com.platypus.proxy.provider.ProviderRegistry;
import com.platypus.proxy.provider.ProviderSession;
import com.platypus.proxy.provider.ProxyProvider;
import com.platypus.proxy.provider.warp.WarpProvider;
import com.platypus.proxy.resolver.FastResolver;
import com.platypus.proxy.resolver.LookupNetIP;
import com.platypus.proxy.resolver.advanced.AdvancedResolver;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.LogManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.glassfish.grizzly.filterchain.FilterChainBuilder;
import org.glassfish.grizzly.http.server.HttpHandler;
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.grizzly.http.server.NetworkListener;
import org.glassfish.grizzly.http.server.ServerConfiguration;

public class ProxyApplication {

    private static final int DEFAULT_PORT = 8080;
    private static final int SHUTDOWN_TIMEOUT_SECONDS = 5;

    private static final int LISTEN_BACKLOG_SIZE = 4096;
    private static final int SELECTOR_RUNNER_COUNT = 2;
    private static final int MAX_REQUESTS_PER_CONN = -1;

    private static final int RECV_BUF_SIZE = 512 * 1024;
    private static final int SEND_BUF_SIZE = 512 * 1024;

    public static void dumpFilterChain(CondLogger logger, FilterChainBuilder builder) {
        for (int i = 0; i < 32; i++) {
            try {
                logger.Debug("  %d: %s", i, builder.get(i).getClass().getName());
            } catch (Exception e) {
                break;
            }
        }
    }

    @SuppressWarnings("unused")
    private static SSLContext createSSLContextFromPKCS12(String p12Path, String password) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream is = Files.newInputStream(Paths.get(p12Path))) {
                keyStore.load(is, password.toCharArray());
            }

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, password.toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
            return sslContext;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create SSLContext from PKCS12 keystore: " + p12Path, e);
        }
    }

    public static CondLogger logger;

    public static CondLogger getLogger() {
        return logger;
    }

    public static void main(String[] args) throws Exception {
        CLIArgs cliArgs = CLIArgs.parse(args);
        if (cliArgs == null) System.exit(0);

        logger = new CondLogger("platypus-proxy", cliArgs.getVerbosity());

        logger.Info("platypus-proxy client version 1.0-SNAPSHOT is starting...");

        LogManager manager = LogManager.getLogManager();
        manager.addLogger(logger.subdivide(HttpServer.class.getName()));
        manager.addLogger(logger.subdivide(NetworkListener.class.getName()));

        String bindAddress = cliArgs.getBindAddress();
        String host;
        int port;
        int colonIdx = bindAddress.lastIndexOf(':');
        if (colonIdx > 0) {
            host = bindAddress.substring(0, colonIdx);
            try {
                port = Integer.parseInt(bindAddress.substring(colonIdx + 1));
            } catch (NumberFormatException e) {
                logger.Error("Invalid bind address: %s", bindAddress);
                System.exit(1);
                return;
            }
        } else {
            host = bindAddress;
            port = DEFAULT_PORT;
        }

        NetworkListener listener = new NetworkListener("proxy", host, port);
        ExecutorService vtExecutor = Executors.newVirtualThreadPerTaskExecutor();

        boolean warpMode = cliArgs.useWarp();

        if (warpMode) {
            if (cliArgs.useHttp2()) {
                logger.Warning("Both --warp and --http2 specified; --warp takes precedence, ignoring --http2");
            }
            logger.Info("Starting WARP forward proxy on %s", bindAddress);
            var tunnelOpener = new WarpProvider().initialize(cliArgs, logger);
            WarpServe warpServe = new WarpServe(bindAddress, tunnelOpener, vtExecutor);

            CountDownLatch latch = new CountDownLatch(1);
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                logger.Info("Shutting down WARP proxy...");
                try { warpServe.close(); } catch (Exception ignored) {}
                logger.shutdown();
            }));
            latch.await();
            return;
        }

        String outboundProxyUrl = cliArgs.getOutboundProxy();

        Endpoint bootstrapEndpoint = new Endpoint("127.0.0.1", 0, null);
        ProxyHandler bootstrapHandler = new ProxyHandler(
                bootstrapEndpoint, null, false, outboundProxyUrl, logger, false, null, null, null, null, false);
        TcpConnector bootstrapConnector = (network, address) -> {
            int lastColon = address.lastIndexOf(':');
            String bootstrapHost = address.substring(0, lastColon);
            int bootstrapPort = Integer.parseInt(address.substring(lastColon + 1));
            return bootstrapHandler.openTcpConnectionTo(bootstrapHost, bootstrapPort);
        };

        String providerName = cliArgs.getProvider().toLowerCase();
        ProviderRegistry registryEntry = ProviderRegistry.fromConfigName(providerName);
        if (registryEntry == null) {
            logger.Critical("Unknown provider '%s'. Use --warp for standalone WARP mode.", providerName);
            bootstrapHandler.close();
            System.exit(1);
            return;
        }
        ProxyProvider provider = registryEntry.create();

        ProviderSession session;
        try {
            session = provider.initialize(cliArgs, bootstrapConnector, logger);
        } catch (Exception e) {
            logger.Critical("Provider initialization failed: %s", e.getMessage());
            bootstrapHandler.close();
            System.exit(1);
            return;
        } finally {
            bootstrapHandler.close();
        }

        if (session == null) return;

        Endpoint endpoint = session.endpoint;
        boolean hideSNI = "opera".equals(providerName)
                ? (cliArgs.getFakeSNI() == null || cliArgs.getFakeSNI().isEmpty())
                : cliArgs.isHideSNI();

        boolean directDns = cliArgs.isDirectDns();
        LookupNetIP resolver = directDns ? new AdvancedResolver(logger) : new FastResolver();

        ProxyHandler proxyHandler = new ProxyHandler(
                endpoint,
                session.authProvider,
                hideSNI,
                outboundProxyUrl,
                logger,
                directDns,
                resolver,
                session.baselineProtocol,
                session.handshake,
                resolver,
                cliArgs.useHttp2());

        H2ProxyService h2ProxyService = new H2ProxyService(
                endpoint,
                session.authProvider,
                hideSNI,
                outboundProxyUrl,
                logger,
                directDns,
                resolver,
                cliArgs.useHttp2());

        boolean directMode = endpoint.isDirect();
        proxyHandler.setDirectMode(directMode);
        proxyHandler.setH2ProxyService(h2ProxyService);

        if (session.tunnelOpener != null) {
            proxyHandler.setWarpTunnelOpener(session.tunnelOpener);
            h2ProxyService.setWarpTunnelOpener(session.tunnelOpener);
            logger.Info("WARP MASQUE tunnel opener configured (HTTP/1.1 + h2 subsystems)");
        }

        boolean http2Mode = cliArgs.useHttp2();

        HttpHandler rootHandler = proxyHandler;

        // NOTE: very experimental
        if (http2Mode) {
            H2Enabler.setH2cfg(listener, vtExecutor, h2ProxyService);
        }

        ScheduledExecutorService refreshScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "refresher");
            t.setDaemon(true);
            return t;
        });

        if (session.refreshIntervalMs > 0) {
            session.refreshStarter.accept(refreshScheduler);
            logger.Info("Credential refresh scheduled every %d ms", session.refreshIntervalMs);
        }

        HttpServer server = new HttpServer();

        listener.getTransport().setTcpNoDelay(true);
        listener.getTransport().setWriteBufferSize(SEND_BUF_SIZE);
        listener.getTransport().setReadBufferSize(RECV_BUF_SIZE);
        listener.getTransport().setServerConnectionBackLog(LISTEN_BACKLOG_SIZE);
        listener.getTransport().setSelectorRunnersCount(SELECTOR_RUNNER_COUNT);
        listener.getKeepAlive().setMaxRequestsCount(MAX_REQUESTS_PER_CONN);
        listener.getKeepAlive().setIdleTimeoutInSeconds(60);
        listener.getTransport().setWorkerThreadPool(vtExecutor);

        server.addListener(listener);

        logger.Info(
                "%s listener started on %s:%d (backlog=%d, selectors=%d, maxRequests=%d)",
                http2Mode ? "HTTPS (h2/1.1)" : "HTTP/1.1",
                host,
                port,
                LISTEN_BACKLOG_SIZE,
                SELECTOR_RUNNER_COUNT,
                MAX_REQUESTS_PER_CONN);

        ServerConfiguration config = server.getServerConfiguration();
        config.addHttpHandler(rootHandler, "/");
        config.addHttpHandler(new HealthHandler(), "/health");

        AtomicReference<HttpServer> serverRef = new AtomicReference<>(server);
        AtomicBoolean shuttingDown = new AtomicBoolean(false);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (!shuttingDown.compareAndSet(false, true)) return;
            logger.Info("Shutting down...");
            HttpServer srv = serverRef.get();
            if (srv != null) srv.shutdown(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            refreshScheduler.shutdown();
            logger.shutdown();
        }));

        try {
            server.start();
            logger.Info("Proxy server running");

            CountDownLatch latch = new CountDownLatch(1);
            Runtime.getRuntime().addShutdownHook(new Thread(latch::countDown));
            latch.await();
        } catch (InterruptedException e) {
            logger.Info("Server interrupted, shutting down...");
        } catch (Exception e) {
            logger.Critical("Failed to start server: %s", e.getMessage());
            System.exit(6);
        } finally {
            if (!shuttingDown.getAndSet(true)) {
                server.shutdownNow();
                refreshScheduler.shutdown();
                vtExecutor.shutdown();
                logger.shutdown();
            }
        }
    }
}
