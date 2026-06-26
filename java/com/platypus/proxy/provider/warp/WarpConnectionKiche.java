package com.platypus.proxy.provider.warp;

import com.platypus.proxy.io.warp.TunnelConnection;
import com.platypus.proxy.logging.CondLogger;
import eu.buney.kiche.KicheAddress;
import eu.buney.kiche.KicheCcAlgorithm;
import eu.buney.kiche.KicheConfig;
import eu.buney.kiche.KicheConnection;
import eu.buney.kiche.KicheH3Config;
import eu.buney.kiche.KicheH3Connection;
import eu.buney.kiche.KicheH3Event;
import eu.buney.kiche.KicheH3EventType;
import eu.buney.kiche.KicheH3Header;
import eu.buney.kiche.KicheSendResult;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.DefaultConstructorMarker;

/**
 * Fallback WARP connection using Kiche (quiche JNI native QUIC+H3).
 * Used when the Flupke-based WarpConnection returns 403 from Cloudflare.
 *
 * DIVERGENCE: Kiche wraps Google's quiche (C/Rust via JNI), native QUIC+H3.
 *             Unlike Kwik/Flupke, Kiche cleanly separates SNI (serverName)
 *             from the UDP peer address, and handles QPACK internally with
 *             native H3 frame processing, eliminating all UnknownFrame errors.
 */
public class WarpConnectionKiche implements AutoCloseable {

    private static final String MASQUE_HOST = "consumer-masque-proxy.cloudflareclient.com";
    private static final int MASQUE_PORT = 443;

    private final KicheConnection quicConnection;
    private final KicheH3Connection h3Connection;
    private final KicheConfig quicConfig;
    private KicheH3Config h3Config;
    private final DatagramSocket udpSocket;
    private final Thread ioThread;
    private Thread h3DispatcherThread;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final Object quicLock = new Object();
    private final CondLogger logger;

    // Limits total concurrent streams on the QUIC connection. The Cloudflare
    // MASQUE endpoint (quiche) defaults to 100 bidirectional streams. Setting
    // at or below this avoids StreamBlocked (-13) retries, which cost 200+400+
    // 600ms then fail, dropping requests.
    // Permit is acquired before sendRequest() and released in the close
    // runnable (held for the entire stream lifetime).
    private final Semaphore streamSemaphore = new Semaphore(100, true);

    // Shared H3 event dispatch infrastructure. H3 events are global to the
    // H3 connection; if multiple consumers poll concurrently, events for stream A
    // can be consumed by stream B, causing hangs/timeouts. A single dispatcher
    // reads events and records per-stream state; consumers wait on/notify that
    // state instead of polling themselves.
    private final Object streamsLock = new Object();
    private final Map<Long, H3StreamState> streams = new HashMap<>();

    public WarpConnectionKiche(WarpConfig config, String socks5Proxy, CondLogger logger) throws Exception {
        this.logger = logger;

        long t0 = System.currentTimeMillis();
        try {
            logger.Debug("[Kiche 1/8] Loading private key...");
            ECPrivateKey privateKey = config.getPrivateKey();
            if (privateKey == null) throw new IllegalArgumentException("No private key in config");
            logger.Debug("[Kiche 1/8] Private key loaded (curve: %s)", privateKey.getParams().getCurve());

            logger.Debug("[Kiche 2/8] Loading public key...");
            java.security.interfaces.ECPublicKey publicKey = config.getPublicKey();
            if (publicKey == null) throw new IllegalArgumentException("No public key in config");
            logger.Debug("[Kiche 2/8] Public key loaded");

            logger.Debug("[Kiche 3/8] Generating self-signed cert...");
            byte[] certDer = WarpCertificateGenerator.generateSelfSignedDer(privateKey, publicKey);
            logger.Debug("[Kiche 3/8] Cert generated (DER: %d bytes)", certDer.length);

            String endpointHost = config.getEndpoint();
            if (endpointHost == null) endpointHost = MASQUE_HOST;
            int endpointPort = config.getEndpointPort();
            logger.Debug("[Kiche 4/8] Endpoint: %s:%d", endpointHost, endpointPort);

            // Write cert + key to temp PEM files for KicheConfig
            logger.Debug("[Kiche 4/8] Writing temp PEM files...");
            byte[] keyDer = privateKeyToDerBytes(privateKey);
            logger.Debug("  Cert DER: %d bytes, Key PKCS#8 DER: %d bytes", certDer.length, keyDer.length);
            Path certPem = writeTempPem("kiche-cert", certDer);
            Path keyPem = writeTempPem("kiche-key", keyDer);
            logger.Debug("  Key PEM header: %s", Files.readString(keyPem).substring(0, (int) Math.min(27, Files.size(keyPem))));
            logger.Debug("  Cert PEM: %s (%d bytes)", certPem, Files.size(certPem));
            logger.Debug("  Key PEM: %s (%d bytes)", keyPem, Files.size(keyPem));

            // Configure Kiche QUIC with TLS client cert
            logger.Debug("[Kiche 5/8] Creating KicheConfig (JNI native init)...");
            quicConfig = newKicheConfig();
            logger.Debug("[Kiche 5/8] KicheConfig created in %dms", System.currentTimeMillis() - t0);
            logger.Debug("[Kiche 5/8] Loading cert into KicheConfig...");
            quicConfig.loadCertChainFromPemFile(certPem.toAbsolutePath().toString());
            logger.Debug("[Kiche 5/8] Cert loaded");
            logger.Debug("[Kiche 5/8] Loading key into KicheConfig...");
            quicConfig.loadPrivKeyFromPemFile(keyPem.toAbsolutePath().toString());
            logger.Debug("[Kiche 5/8] Key loaded");
            quicConfig.verifyPeer(false);
            // ALPN: h3 in wire format (1-byte length prefix + "h3")
            quicConfig.setApplicationProtos(new byte[]{0x02, 0x68, 0x33});
            // Match usque L4 exactly: no datagrams, no extended connect.
            quicConfig.setInitialMaxStreamsBidi(100);
            quicConfig.setInitialMaxStreamsUni(100);
            quicConfig.setInitialMaxData(10_000_000);
            quicConfig.setMaxConnectionWindow(10_000_000);
            quicConfig.setInitialMaxStreamDataBidiLocal(1_000_000);
            quicConfig.setInitialMaxStreamDataBidiRemote(1_000_000);
            quicConfig.setInitialMaxStreamDataUni(1_000_000);
            quicConfig.setMaxStreamWindow(1_000_000);
            quicConfig.setCcAlgorithm(KicheCcAlgorithm.Bbr2);
            quicConfig.enablePacing(true);
            quicConfig.setMaxPacingRate(100_000_000);
            quicConfig.setInitialCongestionWindowPackets(32);
            quicConfig.discoverPmtu(true);
            quicConfig.setMaxSendUdpPayloadSize(1452);

            // Create UDP socket BEFORE connect() so we can pass actual local address
            logger.Debug("[Kiche 6/8] Resolving endpoint %s...", endpointHost);
            // LEAK: constructor-time system DNS resolution; not cached. endpointHost
            //       is re-resolved on every WarpConnectionKiche construction.
            InetAddress endpointAddr = InetAddress.getByName(endpointHost);
            byte[] peerIp = endpointAddr.getAddress();
            logger.Debug("  Resolved to %s (%d bytes)", endpointAddr.getHostAddress(), peerIp.length);

            logger.Debug("[Kiche 6/8] Creating UDP socket...");
            if (socks5Proxy != null && !socks5Proxy.isEmpty()) {
                String socksHost = config.getSocks5Host();
                int socksPort = config.getSocks5Port();
                logger.Info("Routing Kiche through SOCKS5 proxy %s:%d", socksHost, socksPort);
                long tSocks = System.currentTimeMillis();
                udpSocket = new Socks5UdpSocket(socksHost, socksPort,
                        // LEAK: same endpointHost resolved again; see above.
                        InetAddress.getByName(endpointHost), endpointPort, logger);
                logger.Debug("[Kiche 6/8] SOCKS5 UDP socket created in %dms (bind=%s:%d)",
                        System.currentTimeMillis() - tSocks,
                        udpSocket.getLocalAddress(), udpSocket.getLocalPort());
            } else {
                udpSocket = new DatagramSocket();
                // LEAK: third resolution of endpointHost in constructor.
                udpSocket.connect(new java.net.InetSocketAddress(
                        InetAddress.getByName(endpointHost), endpointPort));
                logger.Debug("[Kiche 6/8] Direct UDP socket created (local=%s:%d, remote=%s:%d)",
                        udpSocket.getLocalAddress(), udpSocket.getLocalPort(),
                        endpointHost, endpointPort);
            }

            byte[] scid = new byte[20];
            new SecureRandom().nextBytes(scid);

            byte[] localIp = udpSocket.getLocalAddress().getAddress();
            int localPort = udpSocket.getLocalPort();
            KicheAddress local = new KicheAddress(localIp, localPort);
            KicheAddress peer = new KicheAddress(peerIp, endpointPort);

            logger.Info("Connecting Kiche QUIC to %s:%d (SNI: %s)...", endpointHost, endpointPort, MASQUE_HOST);
            long tConn = System.currentTimeMillis();
            quicConnection = KicheConnection.connect(MASQUE_HOST, scid, local, peer, quicConfig);
            logger.Debug("[Kiche 6/8] KicheConnection created in %dms", System.currentTimeMillis() - tConn);

            // Start background I/O thread that drives the connection handshake
            logger.Debug("[Kiche 8/8] Starting Kiche I/O thread...");
            ioThread = new Thread(this::ioLoop, "kiche-io");
            ioThread.setDaemon(true);
            ioThread.start();

            // Wait for QUIC handshake to complete
            logger.Debug("[Kiche 8/8] Waiting for QUIC handshake (30s timeout)...");
            long handshakeStart = System.currentTimeMillis();
            long deadline = handshakeStart + 30000;
            String lastKnownError = "unknown";
            while (true) {
                boolean established, connClosed;
                synchronized (quicLock) {
                    established = quicConnection.isEstablished();
                    connClosed = quicConnection.isClosed();
                }
                if (established) break;
                if (System.currentTimeMillis() >= deadline) break;
                if (connClosed || !ioThread.isAlive()) {
                    eu.buney.kiche.KicheConnectionError localErr;
                    eu.buney.kiche.KicheConnectionError peerErr;
                    synchronized (quicLock) {
                        localErr = quicConnection.localError();
                        peerErr = quicConnection.peerError();
                    }
                    StringBuilder reason = new StringBuilder();
                    if (localErr != null) {
                        reason.append("local error ").append(localErr.getErrorCode());
                        String reasonStr = new String(localErr.getReason(), StandardCharsets.UTF_8).trim();
                        if (!reasonStr.isEmpty()) reason.append(" (").append(reasonStr).append(")");
                    }
                    if (peerErr != null) {
                        if (reason.length() > 0) reason.append(", ");
                        reason.append("peer error ").append(peerErr.getErrorCode());
                        String reasonStr = new String(peerErr.getReason(), StandardCharsets.UTF_8).trim();
                        if (!reasonStr.isEmpty()) reason.append(" (").append(reasonStr).append(")");
                    }
                    if (reason.length() == 0) reason.append("unknown");
                    lastKnownError = reason.toString();
                    logger.Debug("[Kiche 8/8] QUIC connection died: %s (ioThread alive=%s)",
                            lastKnownError, ioThread.isAlive());
                    throw new IOException("QUIC connection died during handshake: " + lastKnownError);
                }
                Thread.sleep(10);
                long elapsed = System.currentTimeMillis() - handshakeStart;
                if (elapsed > 5000 && elapsed % 5000 < 20) {
                    logger.Debug("[Kiche 8/8] Handshake in progress... %ds elapsed", elapsed / 1000);
                }
            }
            boolean finalEstablished;
            synchronized (quicLock) {
                finalEstablished = quicConnection.isEstablished();
            }
            if (!finalEstablished) {
                throw new IOException("QUIC handshake timed out after 30s");
            }
            long handshakeMs = System.currentTimeMillis() - handshakeStart;
            logger.Info("Kiche QUIC connection established in %dms", handshakeMs);

            // Set up H3 — match usque L4 plain http3.Transport{} (default config)
            // NOTE: Do NOT call h3Config.close() here. Kiche's H3 connection
            // holds native references to the config's settings table. Closing
            // the config frees those settings and breaks H3 event delivery.
            logger.Debug("Setting up Kiche H3 connection...");
            this.h3Config = new KicheH3Config();
            h3Connection = new KicheH3Connection(quicConnection, h3Config);
            logger.Info("Kiche HTTP/3 connection ready (total init: %dms)", System.currentTimeMillis() - t0);

            // Start a dedicated H3 event dispatcher.
            this.h3DispatcherThread = new Thread(this::h3DispatchLoop, "kiche-h3-dispatch");
            h3DispatcherThread.setDaemon(true);
            h3DispatcherThread.start();

            // Clean up temp PEM files
            Files.deleteIfExists(certPem);
            Files.deleteIfExists(keyPem);
        } catch (Exception e) {
            logException("WarpConnectionKiche init failed", e);
            try { closeInternal(); } catch (Exception ignored) {}
            throw e;
        }
    }

    private void logException(String label, Exception e) {
        String msg = e.getMessage();
        String cls = e.getClass().getSimpleName();
        logger.Warning("%s: %s (%s)", label, msg != null ? msg : "null", cls);
        if (e instanceof java.lang.reflect.InvocationTargetException) {
            Throwable cause = ((java.lang.reflect.InvocationTargetException) e).getCause();
            if (cause != null) {
                logger.Warning("  Root cause: %s (%s)",
                        cause.getMessage() != null ? cause.getMessage() : "null",
                        cause.getClass().getName());
            }
        }
    }

    private void ioLoop() {
        byte[] sendBuf = new byte[65536];
        byte[] recvBuf = new byte[65536];

        long sendPackets = 0, sendBytes = 0, recvPackets = 0, recvBytes = 0, timeouts = 0;
        long lastLog = System.currentTimeMillis();

        logger.Debug("Kiche I/O thread started");
        try {
            while (!closed.get()) {
                boolean connClosed;
                synchronized (quicLock) {
                    connClosed = quicConnection.isClosed();
                }
                if (connClosed) break;
                boolean didWork = false;
                // Send QUIC packets through UDP socket
                while (true) {
                    KicheSendResult result;
                    synchronized (quicLock) {
                        result = quicConnection.send(sendBuf, sendBuf.length);
                    }
                    if (result == null) break;
                    KicheAddress to = result.getTo();
                    DatagramPacket dp = new DatagramPacket(
                            sendBuf, 0, result.getWritten(),
                            InetAddress.getByAddress(to.getIp()), to.getPort());
                    udpSocket.send(dp);
                    sendPackets++;
                    sendBytes += result.getWritten();
                    didWork = true;
                }

                // Receive UDP packets, feed into Kiche
                udpSocket.setSoTimeout(1);
                try {
                    DatagramPacket dp = new DatagramPacket(recvBuf, recvBuf.length);
                    udpSocket.receive(dp);

                    byte[] fromIp = dp.getAddress().getAddress();
                    int fromPort = dp.getPort();
                    byte[] toIp = udpSocket.getLocalAddress() != null
                            ? udpSocket.getLocalAddress().getAddress()
                            : new byte[]{0, 0, 0, 0};
                    int toPort = udpSocket.getLocalPort();

                    KicheAddress from = new KicheAddress(fromIp, fromPort);
                    KicheAddress to = new KicheAddress(toIp, toPort);
                    synchronized (quicLock) {
                        quicConnection.recv(recvBuf, dp.getLength(), from, to);
                    }
                    recvPackets++;
                    recvBytes += dp.getLength();
                    didWork = true;
                } catch (java.net.SocketTimeoutException e) {
                    timeouts++;
                }

                // Handle timers
                long timeout;
                synchronized (quicLock) {
                    timeout = quicConnection.timeoutAsMillis();
                    if (timeout <= 0) {
                        quicConnection.onTimeout();
                        didWork = true;
                    }
                }

                // Periodic I/O stats (every 10 seconds)
                if (System.currentTimeMillis() - lastLog > 10000) {
                    logger.Debug("Kiche I/O stats: sent=%d pkts/%d B, recv=%d pkts/%d B, timeouts=%d",
                            sendPackets, sendBytes, recvPackets, recvBytes, timeouts);
                    lastLog = System.currentTimeMillis();
                }

                if (!didWork) {
                    long nap = (timeout > 0 && timeout < 1000) ? timeout : 1;
                    Thread.sleep(nap);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            if (!closed.get()) {
                logger.Warning("Kiche I/O error: %s", e.getMessage());
            }
        }
        logger.Debug("Kiche I/O thread stopped (sent=%d pkts/%d B, recv=%d pkts/%d B)",
                sendPackets, sendBytes, recvPackets, recvBytes);
    }

    // Per-stream H3 state maintained by the single dispatcher thread.
    private static final class H3StreamState {
        final long streamId;
        final CountDownLatch headersLatch = new CountDownLatch(1);
        final Object dataWait = new Object();
        volatile int statusCode = -1;
        volatile boolean reset;
        volatile boolean finished;
        volatile String statusText;
        volatile String headersSummary;

        H3StreamState(long streamId) {
            this.streamId = streamId;
        }
    }

    // Dedicated H3 event dispatcher. Only component that calls h3Connection.poll().
    private void h3DispatchLoop() {
        logger.Debug("Kiche H3 dispatcher started");
        int consecutiveNulls = 0;
        try {
            while (!closed.get()) {
                boolean connClosed2;
                synchronized (quicLock) {
                    connClosed2 = quicConnection.isClosed();
                }
                if (connClosed2) break;
                KicheH3Event event;
                try {
                    synchronized (quicLock) {
                        event = h3Connection.poll(quicConnection);
                    }
                } catch (Exception e) {
                    if (!closed.get()) {
                        logger.Debug("Kiche H3 dispatcher poll error: %s", e.getMessage());
                    }
                    Thread.sleep(5);
                    continue;
                }

                if (event == null) {
                    consecutiveNulls++;
                    int delay = consecutiveNulls < 10 ? 1 : (consecutiveNulls < 100 ? 2 : 5);
                    Thread.sleep(delay);
                    continue;
                }
                consecutiveNulls = 0;

                long streamId = event.getStreamId();
                KicheH3EventType type = event.getType();

                if (logger != null && type != KicheH3EventType.Data) {
                    logger.Debug("Kiche H3 dispatcher: stream=%d type=%s", streamId, type.name());
                }

                H3StreamState state;
                synchronized (streamsLock) {
                    state = streams.get(streamId);
                }
                if (state == null) {
                    continue;
                }

                switch (type) {
                    case Headers: {
                        List<KicheH3Header> responseHeaders = event.getHeaders();
                        if (responseHeaders != null) {
                            StringBuilder hdrDump = new StringBuilder();
                            for (KicheH3Header h : responseHeaders) {
                                String name = h.getNameString();
                                String value = h.getValueString();
                                if (hdrDump.length() > 0) hdrDump.append(", ");
                                hdrDump.append(name).append("=").append(value);
                                if (":status".equals(name)) {
                                    try {
                                        state.statusCode = Integer.parseInt(value);
                                    } catch (NumberFormatException ignored) {
                                        state.statusCode = -1;
                                    }
                                }
                            }
                            if (state.statusCode >= 0) {
                                state.statusText = Integer.toString(state.statusCode);
                            }
                            state.headersSummary = hdrDump.toString();
                        }
                        state.headersLatch.countDown();
                        break;
                    }
                    case Reset:
                        state.reset = true;
                        state.headersLatch.countDown();
                        break;
                    case Finished:
                        state.finished = true;
                        state.headersLatch.countDown();
                        synchronized (state.dataWait) {
                            state.dataWait.notifyAll();
                        }
                        break;
                    case Data:
                        synchronized (state.dataWait) {
                            state.dataWait.notifyAll();
                        }
                        break;
                    default:
                        break;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        logger.Debug("Kiche H3 dispatcher stopped");
    }

    private H3StreamState registerStream(long streamId) {
        H3StreamState state = new H3StreamState(streamId);
        synchronized (streamsLock) {
            streams.put(streamId, state);
        }
        return state;
    }

    private void unregisterStream(long streamId) {
        synchronized (streamsLock) {
            streams.remove(streamId);
        }
    }

    public TunnelConnection openTunnel(String targetHost, int targetPort) throws IOException {
        return openTunnel(targetHost, targetPort, null);
    }

    public TunnelConnection openTunnel(String targetHost, int targetPort, byte[] initialData) throws IOException {
        if (closed.get()) throw new IOException("Kiche WARP connection closed");

        // Resolve target to IP locally (matches usque L4 proxy resolveLocally=true)
        java.net.InetAddress resolved;
        try {
            // LEAK: per-tunnel system DNS; not cached. Same pattern as Flupke
            //       WarpConnection.openTunnel.
            resolved = java.net.InetAddress.getByName(targetHost);
        } catch (Exception e) {
            throw new IOException("DNS resolution failed for " + targetHost, e);
        }
        String ipStr = resolved.getHostAddress();
        if (ipStr.contains(":")) ipStr = "[" + ipStr + "]";
        String authority = ipStr + ":" + targetPort;
        logger.Debug("Kiche openTunnel: CONNECT :authority=%s (resolved from %s)", authority, targetHost);

        // Include :scheme and :path — usque L4 sends them, and Cloudflare
        // expects them for CONNECT over H3
        List<KicheH3Header> requestHeaders = Arrays.asList(
                new KicheH3Header(":method", "CONNECT"),
                new KicheH3Header(":scheme", "https"),
                new KicheH3Header(":authority", java.util.Objects.requireNonNull(authority, "authority must not be null")),
                new KicheH3Header(":path", "/"));

        // Acquire stream permit BEFORE sendRequest.
        try {
            if (!streamSemaphore.tryAcquire(60, TimeUnit.SECONDS)) {
                throw new IOException("Kiche CONNECT tunnel to " + authority
                        + " failed: stream creation backpressure timeout (60s)");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted waiting for stream creation permit");
        }
        long streamId;
        final int MAX_H3_RETRIES = 3;
        for (int attempt = 0; ; attempt++) {
            try {
                synchronized (quicLock) {
                    streamId = h3Connection.sendRequest(quicConnection, requestHeaders, false);
                }
                break;
            } catch (Exception e) {
                boolean blocked = e.getMessage() != null && e.getMessage().contains("StreamBlocked");
                if (blocked && attempt < MAX_H3_RETRIES) {
                    logger.Debug("Kiche openTunnel: StreamBlocked on attempt %d, retrying in %dms",
                            attempt + 1, 200L * (attempt + 1));
                    try { Thread.sleep(200L * (attempt + 1)); } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        streamSemaphore.release();
                        throw new IOException("Interrupted during StreamBlocked backoff");
                    }
                    continue;
                }
                streamSemaphore.release();
                throw new IOException("Kiche CONNECT request failed: " + e.getMessage(), e);
            }
        }
        logger.Debug("Kiche openTunnel: CONNECT request sent on stream %d", streamId);

        // Send initial data with CONNECT request, before waiting for response
        if (initialData != null && initialData.length > 0) {
            synchronized (quicLock) {
                h3Connection.sendBody(quicConnection, streamId, initialData, false);
            }
            logger.Debug("Kiche openTunnel: sent %d bytes initial data w/ CONNECT", initialData.length);
        }

        H3StreamState state = registerStream(streamId);
        try {
            boolean gotHeaders = state.headersLatch.await(15, TimeUnit.SECONDS);
            if (!gotHeaders) {
                throw new IOException("Kiche CONNECT tunnel to " + authority
                        + " failed: HTTP timeout waiting for response headers");
            }

            if (state.reset) {
                throw new IOException("Kiche CONNECT tunnel to " + authority
                        + " failed: stream reset by peer");
            }

            int statusCode = state.statusCode;
            if (statusCode >= 200 && statusCode < 300) {
                logger.Debug("Kiche openTunnel: Response headers on stream %d [%s]",
                        streamId, state.headersSummary);
                logger.Debug("Kiche openTunnel: CONNECT to %s succeeded (HTTP %d) on stream %d",
                        authority, statusCode, streamId);
            } else {
                logger.Debug("Kiche openTunnel: Response headers on stream %d [%s]",
                        streamId, state.headersSummary);
                throw new IOException("Kiche CONNECT tunnel to " + authority
                        + " failed: HTTP " + (statusCode >= 0 ? statusCode : "timeout"));
            }

            final long tunnelStreamId = streamId;
            return TunnelConnection.streamBased(
                    new KicheStreamInputStream(tunnelStreamId),
                    new KicheStreamOutputStream(tunnelStreamId),
                    () -> {
                        try {
                            synchronized (quicLock) {
                                h3Connection.sendBody(quicConnection, tunnelStreamId, new byte[0], true);
                            }
                        } catch (Exception ignored) {
                        } finally {
                            unregisterStream(tunnelStreamId);
                            streamSemaphore.release();
                        }
                    });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            streamSemaphore.release();
            unregisterStream(streamId);
            throw new IOException("Interrupted waiting for Kiche CONNECT response");
        } catch (Exception e) {
            streamSemaphore.release();
            unregisterStream(streamId);
            if (e instanceof IOException) {
                throw (IOException) e;
            }
            throw new IOException("Kiche CONNECT tunnel setup failed", e);
        }
    }

    private Path writeTempPem(String prefix, byte[] derBytes) throws IOException {
        String b64 = Base64.getEncoder().encodeToString(derBytes);
        String pem;
        if (prefix.contains("cert")) {
            pem = "-----BEGIN CERTIFICATE-----\n"
                    + b64.replaceAll("(.{64})", "$1\n")
                    + "\n-----END CERTIFICATE-----\n";
        } else {
            pem = "-----BEGIN PRIVATE KEY-----\n"
                    + b64.replaceAll("(.{64})", "$1\n")
                    + "\n-----END PRIVATE KEY-----\n";
        }
        Path tmp = Files.createTempFile(prefix, ".pem");
        Files.writeString(tmp, pem);
        return tmp;
    }

    private static byte[] privateKeyToDerBytes(ECPrivateKey privateKey) {
        return privateKey.getEncoded();
    }

    private static byte[] certToDerBytes(byte[] certBytes) {
        return certBytes;
    }

    // Reset KicheLoader so it re-extracts native libraries between attempts
    private static void resetKicheLoader() {
        try {
            Class<?> loaderClass = Class.forName("eu.buney.kiche.KicheLoader");
            java.lang.reflect.Field f = loaderClass.getDeclaredField("isLoaded");
            f.setAccessible(true);
            java.util.concurrent.atomic.AtomicBoolean cur = (java.util.concurrent.atomic.AtomicBoolean) f.get(null);
            if (cur != null) cur.set(false);
        } catch (Exception ignored) {
        }
    }

    private void preloadQuicheDll() {
        try {
            Path nativeDir = Paths.get(System.getProperty("java.io.tmpdir"),
                    "platypus-warp-native-" + ProcessHandle.current().pid());
            Files.createDirectories(nativeDir);

            Path quicheDst = nativeDir.resolve("quiche.dll");
            Path jniDst = nativeDir.resolve("libquiche_jni.dll");

            boolean haveQuiche = extractResourceTo(
                    "/native/windows/x86_64/quiche.dll", quicheDst);
            if (!haveQuiche) {
                haveQuiche = extractJarEntryTo(
                        Paths.get(System.getProperty("user.home"),
                                ".m2", "repository", "eu", "buney", "libquiche",
                                "libquiche-jvm", "0.28.0-1", "libquiche-jvm-0.28.0-1.jar"),
                        "native/windows/x86_64/quiche.dll", quicheDst);
            }
            if (!haveQuiche) {
                // Pre-staged quiche_dll/quiche.dll
                Path src = Paths.get("quiche_dll", "quiche.dll");
                if (Files.exists(src)) {
                    Files.copy(src, quicheDst, StandardCopyOption.REPLACE_EXISTING);
                    haveQuiche = true;
                    logger.Debug("Pre-staged quiche.dll from quiche_dll directory");
                }
            }

            // Extract libquiche_jni.dll from the kiche-jvm JAR
            Path kicheJar = jarPathOfClass("eu.buney.kiche.KicheConfig");
            boolean haveJni = false;
            if (kicheJar != null) {
                haveJni = extractJarEntryTo(kicheJar,
                        "native/windows/x86_64/libquiche_jni.dll", jniDst);
            }
            if (!haveJni) {
                haveJni = extractJarEntryTo(
                        Paths.get(System.getProperty("user.home"),
                                ".m2", "repository", "eu", "buney", "kiche",
                                "kiche-jvm", "0.1.0-alpha.3", "kiche-jvm-0.1.0-alpha.3.jar"),
                        "native/windows/x86_64/libquiche_jni.dll", jniDst);
            }

            if (!haveQuiche) {
                logger.Debug("quiche.dll source not found; KicheLoader will attempt its own resolution");
            } else {
                System.load(quicheDst.toAbsolutePath().toString());
                logger.Debug("Loaded quiche.dll from %s (%d bytes)",
                        quicheDst, Files.size(quicheDst));
            }
            if (haveJni) {
                System.load(jniDst.toAbsolutePath().toString());
                logger.Debug("Loaded libquiche_jni.dll from %s (%d bytes)",
                        jniDst, Files.size(jniDst));
            }

            // Tell KicheLoader that libraries are already loaded
            try {
                Class<?> loaderClass = Class.forName("eu.buney.kiche.KicheLoader");
                java.lang.reflect.Field f = loaderClass.getDeclaredField("isLoaded");
                f.setAccessible(true);
                java.util.concurrent.atomic.AtomicBoolean cur =
                        (java.util.concurrent.atomic.AtomicBoolean) f.get(null);
                if (cur != null) {
                    cur.set(true);
                    logger.Debug("KicheLoader.isLoaded set to true (preloaded)");
                }
            } catch (Exception ignored) {
            }
        } catch (UnsatisfiedLinkError e) {
            logger.Debug("Native library already loaded or load failed: %s", e.getMessage());
        } catch (Exception e) {
            logger.Debug("Failed to preload native libraries: %s", e.getMessage());
        }
    }

    private static boolean extractResourceTo(String resourcePath, Path dst) {
        try (java.io.InputStream is = WarpConnectionKiche.class.getResourceAsStream(resourcePath)) {
            if (is == null) return false;
            Files.write(dst, is.readAllBytes(), java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.TRUNCATE_EXISTING,
                    java.nio.file.StandardOpenOption.WRITE);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean extractJarEntryTo(Path jarPath, String entryName, Path dst) {
        if (!Files.exists(jarPath)) return false;
        try (java.util.jar.JarFile jf = new java.util.jar.JarFile(jarPath.toFile())) {
            java.util.jar.JarEntry entry = jf.getJarEntry(entryName);
            if (entry == null) return false;
            try (java.io.InputStream is = jf.getInputStream(entry)) {
                Files.write(dst, is.readAllBytes(), java.nio.file.StandardOpenOption.CREATE,
                        java.nio.file.StandardOpenOption.TRUNCATE_EXISTING,
                        java.nio.file.StandardOpenOption.WRITE);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static Path jarPathOfClass(String className) {
        try {
            Class<?> clazz = Class.forName(className);
            java.security.ProtectionDomain pd = clazz.getProtectionDomain();
            java.security.CodeSource cs = pd != null ? pd.getCodeSource() : null;
            if (cs == null) return null;
            java.net.URL url = cs.getLocation();
            if (url == null) return null;
            Path p = Paths.get(url.toURI());
            return Files.isRegularFile(p) ? p : null;
        } catch (Exception e) {
            return null;
        }
    }

    private KicheConfig newKicheConfig() throws Exception {
        preloadQuicheDll();

        logger.Debug("Constructing KicheConfig...");
        try {
            java.lang.reflect.Constructor<KicheConfig> ctor =
                    KicheConfig.class.getDeclaredConstructor(int.class);
            logger.Debug("  Found constructor: %s", ctor);
            ctor.setAccessible(true);
            KicheConfig cfg = ctor.newInstance(1);
            logger.Debug("  KicheConfig created via int constructor");
            return cfg;
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            logger.Debug("  int constructor threw InvocationTargetException");
            logger.Debug("    cause class: %s", cause != null ? cause.getClass().getName() : "null");
            logger.Debug("    cause message: %s", cause != null ? cause.getMessage() : "null");
            if (cause != null) {
                java.io.StringWriter sw = new java.io.StringWriter();
                cause.printStackTrace(new java.io.PrintWriter(sw));
                logger.Debug("    cause trace: %s", sw.toString().replaceAll("[\r\n]+", " | "));
            }
            logger.Debug("  Falling back to synthetic (int,int,DefaultConstructorMarker) constructor...");
            try {
                java.lang.reflect.Constructor<KicheConfig> ctor2 =
                        KicheConfig.class.getDeclaredConstructor(
                                int.class, int.class, DefaultConstructorMarker.class);
                logger.Debug("  Found synthetic constructor: %s", ctor2);
                ctor2.setAccessible(true);
                KicheConfig cfg2 = ctor2.newInstance(0, 1, null);
                logger.Debug("  KicheConfig created via synthetic constructor");
                return cfg2;
            } catch (java.lang.reflect.InvocationTargetException e2) {
                Throwable cause2 = e2.getCause();
                logger.Debug("  synthetic constructor also threw InvocationTargetException");
                logger.Debug("    cause class: %s", cause2 != null ? cause2.getClass().getName() : "null");
                logger.Debug("    cause message: %s", cause2 != null ? cause2.getMessage() : "null");
                if (cause2 != null) {
                    java.io.StringWriter sw = new java.io.StringWriter();
                    cause2.printStackTrace(new java.io.PrintWriter(sw));
                    logger.Debug("    cause trace: %s", sw.toString().replaceAll("[\r\n]+", " | "));
                }
                throw new Exception("KicheConfig construction failed: "
                        + (cause2 != null ? cause2.toString() : "null"), cause2);
            }
        } catch (Exception e) {
            logger.Debug("  Unexpected exception: %s: %s", e.getClass().getName(), e.getMessage());
            throw e;
        }
    }

    @Override
    public void close() {
        closeInternal();
    }

    private void closeInternal() {
        if (!closed.compareAndSet(false, true)) return;
        if (h3DispatcherThread != null && h3DispatcherThread.isAlive()) {
            h3DispatcherThread.interrupt();
            try {
                h3DispatcherThread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        try {
            if (h3Connection != null) h3Connection.close();
        } catch (Exception ignored) {
        }
        try {
            if (h3Config != null) h3Config.close();
        } catch (Exception ignored) {
        }
        try {
            quicConnection.close();
        } catch (Exception ignored) {
        }
        try {
            quicConfig.close();
        } catch (Exception ignored) {
        }
        try {
            udpSocket.close();
        } catch (Exception ignored) {
        }
        if (ioThread != null && ioThread.isAlive()) {
            ioThread.interrupt();
        }
    }

    private class KicheStreamInputStream extends InputStream {
        private final long streamId;
        private final byte[] oneByte = new byte[1];
        private final byte[] readBuf;
        private byte[] pendingBuf;
        private int pendingOff;
        private int pendingLen;
        private boolean eof;
        private long totalRead;
        private long lastLog;

        KicheStreamInputStream(long streamId) {
            this.streamId = streamId;
            this.lastLog = System.currentTimeMillis();
            this.readBuf = new byte[65536];
        }

        @Override
        public int read() throws IOException {
            int n = read(oneByte, 0, 1);
            return n < 0 ? -1 : oneByte[0] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (eof || closed.get()) return -1;

            if (pendingLen > 0) {
                int n = Math.min(len, pendingLen);
                System.arraycopy(pendingBuf, pendingOff, b, off, n);
                pendingOff += n;
                pendingLen -= n;
                totalRead += n;
                return n;
            }

            long deadline = System.currentTimeMillis() + 120_000;
            while (System.currentTimeMillis() < deadline) {
                int rc;
                synchronized (quicLock) {
                    rc = h3Connection.recvBody(quicConnection, streamId, readBuf);
                }
                if (rc > 0) {
                    int toReturn = Math.min(rc, len);
                    System.arraycopy(readBuf, 0, b, off, toReturn);
                    if (rc > toReturn) {
                        pendingBuf = new byte[rc - toReturn];
                        System.arraycopy(readBuf, toReturn, pendingBuf, 0, rc - toReturn);
                        pendingOff = 0;
                        pendingLen = rc - toReturn;
                    }
                    totalRead += toReturn;
                    long now = System.currentTimeMillis();
                    if (now - lastLog > 5000) {
                        logger.Debug("Kiche Stream %d recv: %d bytes (total: %d)", streamId, toReturn, totalRead);
                        lastLog = now;
                    }
                    return toReturn;
                }
                boolean finished;
                synchronized (quicLock) {
                    finished = quicConnection.streamFinished(streamId);
                }
                if (finished) {
                    eof = true;
                    logger.Debug("Kiche Stream %d finished (total read: %d bytes)", streamId, totalRead);
                    return -1;
                }
                H3StreamState st;
                synchronized (streamsLock) {
                    st = streams.get(streamId);
                }
                if (st != null) {
                    synchronized (st.dataWait) {
                        try {
                            st.dataWait.wait(100);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            throw new IOException("Interrupted");
                        }
                    }
                } else {
                    try {
                        Thread.sleep(1);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted");
                    }
                }
            }
            throw new IOException("Read timeout on stream " + streamId);
        }
    }

    private class KicheStreamOutputStream extends OutputStream {
        private final long streamId;
        private long totalWritten;
        private long lastLog;

        KicheStreamOutputStream(long streamId) {
            this.streamId = streamId;
            this.lastLog = System.currentTimeMillis();
        }

        @Override
        public void write(int b) throws IOException {
            write(new byte[]{(byte) b}, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (closed.get()) throw new IOException("Kiche stream closed");
            int written = 0;
            long deadline = System.currentTimeMillis() + 30000;
            while (written < len && System.currentTimeMillis() < deadline) {
                int remaining = len - written;
                byte[] sendChunk;
                if (off == 0 && remaining == b.length) {
                    sendChunk = b;
                } else {
                    sendChunk = new byte[remaining];
                    System.arraycopy(b, off + written, sendChunk, 0, remaining);
                }
                int n;
                synchronized (quicLock) {
                    n = h3Connection.sendBody(quicConnection, streamId, sendChunk, false);
                }
                if (n > 0) {
                    written += n;
                    totalWritten += n;
                } else if (n == 0) {
                    try {
                        Thread.sleep(1);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted");
                    }
                }
            }
            long now = System.currentTimeMillis();
            if (now - lastLog > 5000) {
                logger.Debug("Kiche Stream %d sent: chunk=%d (total: %d)", streamId, written, totalWritten);
                lastLog = now;
            }
            if (written < len) {
                throw new IOException("Kiche write timeout: " + written + "/" + len);
            }
        }

        @Override
        public void close() throws IOException {
            try {
                synchronized (quicLock) {
                    h3Connection.sendBody(quicConnection, streamId, new byte[0], true);
                }
                logger.Debug("Kiche Stream %d output closed (total written: %d bytes)", streamId, totalWritten);
            } catch (Exception ignored) {
            }
        }
    }
}
