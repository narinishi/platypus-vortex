package com.platypus.proxy.provider.warp;

import com.platypus.proxy.CLIArgs;
import com.platypus.proxy.io.warp.TunnelConnection;
import com.platypus.proxy.io.warp.TunnelOpener;
import com.platypus.proxy.logging.CondLogger;
import com.platypus.proxy.provider.RetryStrategy;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicReference;

// DIVERGENCE: usque uses separate Cobra subcommands (register, enroll, nativetun,
//             socks, http-proxy, l4-socks, l4-http-proxy, portfw). Each command
//             independently sets up TLS, QUIC, and either TUN or L4 proxy.
//             No shared Provider abstraction. Java uses ProxyProvider interface
//             + TunnelOpener functional interface for clean separation of concerns.
//
// DIVERGENCE: usque cmd/l4_helpers.go:35-163 (buildL4Proxy) has extensive
//             CLI flag parsing: bind, port, username/password, connect-port,
//             DNS servers, DNS timeout, IPv6 toggle, keepalive period,
//             initial packet size, insecure toggle, local DNS, system DNS,
//             on-connect/on-disconnect hooks. Java's WarpProvider delegates
//             most of these to the existing Platypus CLI infrastructure.
//
// DIVERGENCE: usque has NO automatic enrollment. user must run
//             "usque register" then "usque enroll" separately. Java auto-enrolls
//             when no config file exists (WarpProvider.initialize lines 40-55).
public class WarpProvider {

    private static final String CONFIG_FILE = "warp-config.json";
    private static final String DEFAULT_MODEL = "PC";
    private static final String DEFAULT_LOCALE = "en_US";
    private static final String DEFAULT_NAME = "platypus";

    private volatile AtomicReference<AutoCloseable> delegateRef;

    public Runnable getConnectionCloser() {
        AtomicReference<AutoCloseable> ref = delegateRef;
        return () -> {
            Object current = ref != null ? ref.get() : null;
            if (current instanceof AutoCloseable c) {
                try { c.close(); } catch (Exception ignored) {}
            }
        };
    }

    /**
     * NON-LEAK: Always tunneled through WARP H3 CONNECT. Returns a TunnelOpener
     * that delegates to WarpConnection (Flupke), falling back to WarpConnectionKiche
     * on 403. No direct-socket fallback to the origin.
     */
    public TunnelOpener initialize(CLIArgs args, CondLogger logger) throws Exception {
        Path configPath = Paths.get(CONFIG_FILE);

        WarpConfig config = WarpConfig.loadOrDefault(configPath);

        // DIVERGENCE: usque CLI is Cobra-based (cmd/root.go). Java uses colon-syntax
        //             parsing on a single -provider string (-provider warp:enroll=model).
        String[] colonParts = parseColonCommand(args.getProvider());
        String command = colonParts[0];
        String argValue = colonParts[1];

        if (("enroll".equals(command) || config == null) && !args.isAcceptTos()) {
            promptAcceptTos(logger);
        }

        if ("enroll".equals(command) || config == null) {
            String model = argValue.isEmpty() ? DEFAULT_MODEL : argValue;
            String outboundProxy = args.getOutboundProxy();
            final String fModel = model;
            RetryStrategy.execute("warp-enroll", args.getInitRetries(), args.getInitRetryIntervalMillis(), logger, () -> {
                try {
                    WarpConfig newConfig = WarpEnroller.enroll(logger, fModel, DEFAULT_LOCALE, DEFAULT_NAME, null, outboundProxy);
                    newConfig.save(configPath);
                    logger.Info("WARP config saved to %s", CONFIG_FILE);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            config = WarpConfig.load(configPath);
            if (config == null) throw new RuntimeException("Failed to load WARP config after enrollment");
        }

        String outboundProxy = args.getOutboundProxy();

        if (outboundProxy != null && !outboundProxy.isEmpty()) {
            String lower = outboundProxy.toLowerCase();
            if (!lower.startsWith("socks5://") && !lower.startsWith("socks5h://")) {
                throw new IllegalArgumentException("WARP provider requires SOCKS5 outbound proxy (HTTP won't work - WARP needs UDP). Use socks5:// or socks5h://");
            }
            config.socks5Proxy = outboundProxy;
        }

        String socks5Url = config.hasSocks5Proxy() ? config.socks5Proxy : null;

        final WarpConfig finalConfig = config;
        final String finalSocks5Url = socks5Url;

        logger.Info("Establishing WARP MASQUE connection to %s...", finalConfig.getEndpoint());
        WarpConnection primaryConnection = connectWithRetry(finalConfig, finalSocks5Url, logger, args);
        this.delegateRef = new AtomicReference<>(primaryConnection);
        AtomicReference<WarpConnectionKiche> kicheRef = new AtomicReference<>(null);

        return (host, port, initialData) -> {
            Object current = delegateRef.get();
            if (current instanceof WarpConnection flupkeConn) {
                try {
                    return flupkeConn.openTunnel(host, port, initialData);
                } catch (IOException e) {
                    String msg = e.getMessage();
                    if (msg != null && msg.contains("403")) {
                        logger.Warning("Flupke CONNECT returned 403 for %s:%d, falling back to Kiche", host, port);
                        logger.Warning("  Flupke error: %s", msg);
                        try { flupkeConn.close(); } catch (Exception ignored) {}
                        logger.Info("Establishing Kiche fallback WARP connection...");
                        try {
                            WarpConnectionKiche kicheConn = new WarpConnectionKiche(finalConfig, finalSocks5Url, logger);
                            kicheRef.set(kicheConn);
                            delegateRef.set(kicheConn);
                            return kicheConn.openTunnel(host, port, initialData);
                        } catch (Exception ke) {
                            throw new IOException("Kiche fallback connection failed", ke);
                        }
                    }
                    throw e;
                }
            } else if (current instanceof WarpConnectionKiche kicheConn) {
                return kicheConn.openTunnel(host, port, initialData);
            }
            throw new IOException("No active WARP connection");
        };
    }

    // DIVERGENCE: usque api/masque.go:109-161 (ConnectTunnel) has 2-attempt
    //             retry with isRetryableHTTP3ConnectFailure check (detects
    //             "PROTOCOL_VIOLATION"). Java has configurable retry count
    //             with sleep-based backoff. usque also retries per-stream
    //             (api/l4proxy.go:173-191); Java only retries at connection level.
    private WarpConnection connectWithRetry(WarpConfig config, String socks5Url, CondLogger logger, CLIArgs args) throws Exception {
        Exception lastError = null;
        int maxAttempts = args.getInitRetries() <= 0 ? 10 : args.getInitRetries();
        for (int i = 1; i <= maxAttempts; i++) {
            if (i > 1 && args.getInitRetryIntervalMillis() > 0) {
                try {
                    Thread.sleep(args.getInitRetryIntervalMillis());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            }
            logger.Info("Connecting WARP, attempt #%d...", i);
            try {
                return new WarpConnection(config, socks5Url, logger);
            } catch (Exception e) {
                lastError = e;
                String errMsg = e.getMessage();
                if (errMsg == null && e instanceof java.lang.reflect.InvocationTargetException) {
                    Throwable cause = ((java.lang.reflect.InvocationTargetException) e).getCause();
                    errMsg = cause != null ? cause.toString() : "InvocationTargetException(null cause)";
                }
                logger.Warning("WARP connection attempt #%d failed: %s (%s)", i,
                        errMsg != null ? errMsg : "null", e.getClass().getSimpleName());
                // Log root cause chain
                Throwable t = e;
                int depth = 0;
                while (t != null && depth < 4) {
                    logger.Debug("  cause[%d]: %s: %s", depth,
                            t.getClass().getName(),
                            t.getMessage() != null ? t.getMessage() : "null");
                    t = t.getCause();
                    depth++;
                }
            }
        }
        throw lastError != null ? lastError : new RuntimeException("All WARP connection attempts failed");
    }

    // Parses ":command=value" or ":command" suffix from -provider warp:enroll=PC.
    // Returns [command, value] (both empty strings if no colon present).
    static String[] parseColonCommand(String providerArg) {
        String command = "";
        String argValue = "";
        if (providerArg == null) return new String[]{"", ""};
        int colonIdx = providerArg.indexOf(':');
        if (colonIdx > 0) {
            command = providerArg.substring(colonIdx + 1);
            int equalsIdx = command.indexOf('=');
            if (equalsIdx > 0) {
                argValue = command.substring(equalsIdx + 1);
                command = command.substring(0, equalsIdx);
            }
        }
        return new String[]{command, argValue};
    }

    // Mirrors usque api/cloudflare.go:47-56 interactive ToS prompt.
    // Skipped automatically when stdin is not a TTY (IDE, piped, runwarp.cmd)
    // or when --accept-tos flag is set (see CLIArgs.isAcceptTos()).
    private void promptAcceptTos(CondLogger logger) {
        if (System.console() == null) {
            logger.Info("Non-interactive session detected, skipping ToS prompt.");
            return;
        }
        System.out.print("You must accept the Terms of Service "
                + "(https://www.cloudflare.com/application/terms/) to register. "
                + "Do you agree? (y/n): ");
        System.out.flush();
        String response;
        try {
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(System.in, java.nio.charset.StandardCharsets.UTF_8));
            response = reader.readLine();
        } catch (java.io.IOException e) {
            throw new RuntimeException("Failed to read ToS response: " + e.getMessage(), e);
        }
        if (response == null || !response.trim().equalsIgnoreCase("y")) {
            throw new RuntimeException("WARP registration aborted: Terms of Service not accepted.");
        }
        logger.Info("ToS accepted by user");
    }
}
