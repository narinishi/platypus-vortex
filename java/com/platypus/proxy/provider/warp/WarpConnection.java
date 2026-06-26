package com.platypus.proxy.provider.warp;

import com.platypus.proxy.io.warp.TunnelConnection;
import com.platypus.proxy.logging.CondLogger;
import com.platypus.proxy.resolver.LookupNetIP;
import com.platypus.proxy.resolver.advanced.AdvancedResolver;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicStream;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.generic.VariableLengthInteger;
import tech.kwik.flupke.Http3Client;
import tech.kwik.flupke.HttpError;
import tech.kwik.flupke.HttpStream;
import tech.kwik.flupke.Http3ClientBuilder;
import tech.kwik.flupke.impl.HeadersFrame;
import tech.kwik.flupke.impl.Http3Frame;
import tech.kwik.flupke.impl.DataFrame;
import tech.kwik.flupke.impl.UnknownFrame;
import tech.kwik.qpack.Encoder;
import tech.kwik.qpack.Decoder;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

// USQUE-MAIN COMPARISON REFERENCE (upstream repo: native-libs-src/quic-go-master)
// This file implements an HTTP/3 CONNECT proxy using Kwik/Flupke (pure Java QUIC+H3).
// usque-main uses Go's native quic-go and BoringSSL, NOT Kwik or Flupke.
//
// KEY DIFFERENCES:
// 1. QUIC stack: Kwik (Java) vs quic-go (Go/C) — Kwik has its own TLS stack (agent15),
//    quic-go wraps crypto/tls. TLS fingerprints differ (Kwik sends agent15, quic-go
//    sends Go crypto/tls). Cloudflare may fingerprint this.
// 2. H3 framing: Flupke (Java) vs Go http3 (Go) — both follow RFC 9114 identically.
// 3. QPACK: Flupke vs Go qpack — both RFC 9204. Verified identical encoding.
// 4. SNI handling: Flupke forces SNI via reflection on private 'host' field (Kwik JAR
//    v0.10.10 lacks serverName()). quic-go splits SNI from peer address natively.
// 5. Connection model: Single connection reused for all streams. usque's l4proxy.go
//    also uses a single connection (l4Proxy.conn). No pooling in either.
// 6. Stream concurrency: No semaphore — relies on QUIC flow control natively.
//    usque sets MaxIncomingStreams=100 but the effective limit depends on quic-go
//    defaults and Cloudflare's quiche peer.
// 7. Request format: Sends :authority and :method only (no :scheme, no :path), matching
//    Go http3's request_writer.go exactly. Cloudflare's L4 PROXY endpoint still returns
//    403 despite all protocol-level matching — suggests TLS fingerprint or QUIC impl
//    detail (not protocol) is the root cause.

public class WarpConnection implements AutoCloseable {

    private static final String MASQUE_HOST = "consumer-masque-proxy.cloudflareclient.com";
    private static final int MASQUE_PORT = 443;

    // Kept as a field even though only used in constructor — prevents GC of the
    // underlying Kwik session during the connection's lifetime.
    // DIVERGENCE: usque has NO explicit Http3Client analog; the Go http3.Transport
    //             is implicitly kept alive by the connection reference.
    private final Http3Client http3Client;
    private final WarpH3Connection h3Connection;

    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final CondLogger logger;
    private final LookupNetIP resolver;

    private final QuicConnection quicConn;
    private final Encoder qpackEncoder;
    private final Decoder qpackDecoder;

    public WarpConnection(WarpConfig config, String socks5Proxy, CondLogger logger) throws Exception {
        this.logger = logger;
        this.resolver = new AdvancedResolver(logger);
        long t0 = System.currentTimeMillis();

        ECPrivateKey privateKey = config.getPrivateKey();
        if (privateKey == null) throw new IllegalArgumentException("No private key in config");
        var publicKey = config.getPublicKey();
        if (publicKey == null) throw new IllegalArgumentException("No public key in config");

        // DIVERGENCE: usque registers via cmd/enroll.go which fetches an EC keypair
        //             from the Cloudflare API. The private key is stored as a PEM file
        //             and loaded by usque's auth/token.go when creating the TLS config.
        //             Java uses the identical enrollment mechanism (WarpEnroller.java),
        //             then constructs a JKS/X509ExtendedKeyManager from the same keys
        //             for Kwik's agent15 TLS stack. The X.509 certificate is
        //             self-signed (Cloudflare does NOT validate the cert — only the
        //             token during enrollment is meaningful).
        //
        //             agent15 (Kwik's TLS library) MUST receive an X509ExtendedKeyManager;
        //             a vanilla KeyManager or PrivateKey alone won't work.
        logger.Debug("[1/5] Loading private key...");
        logger.Debug("[2/5] Generating self-signed client cert...");
        byte[] certDer = WarpCertificateGenerator.generateSelfSignedDer(privateKey, publicKey);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate clientCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));

        logger.Debug("[3/5] Building X509ExtendedKeyManager...");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("warp", privateKey, "".toCharArray(), new X509Certificate[]{clientCert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "".toCharArray());
        X509ExtendedKeyManager keyManager = null;
        for (KeyManager km : kmf.getKeyManagers()) {
            if (km instanceof X509ExtendedKeyManager) { keyManager = (X509ExtendedKeyManager) km; break; }
        }
        if (keyManager == null) throw new RuntimeException("No X509ExtendedKeyManager found");

        int endpointPort = config.getEndpointPort();
        if (endpointPort <= 0) endpointPort = MASQUE_PORT;
        String endpointHost = config.getEndpoint();

        logger.Debug("[4/5] Building H3 client with SNI=%s ...", MASQUE_HOST);
        http3Client = (Http3Client) new Http3ClientBuilder()
                .disableCertificateCheck()
                .connectTimeout(Duration.ofSeconds(35))
                .keyManager(keyManager)
                .build();

        // DIVERGENCE: usque's l4buildQUICConfig in l4_helpers.go creates a quic.Config
        //             with MaxIncomingStreams=100, MaxStreamReceiveWindow=1MB,
        //             MaxConnectionReceiveWindow=10MB. KwikBuilder lacks per-window
        //             setters — only defaultStreamReceiveBufferSize is available.
        //             Transport parameters (max_idle_timeout, ack_delay_exponent, etc.)
        //             are set by Kwik internally and cannot be overridden here.
        //             usque also sets EnableDatagrams(false) and Versions={V1}.
        logger.Debug("[5/5] Connecting to SNI=%s via endpoint=%s:%d ...", MASQUE_HOST,
                endpointHost != null ? endpointHost : "(resolve)", endpointPort);
        QuicClientConnection.Builder qBuilder = QuicClientConnection.newBuilder();
        // Use IP as connection target, we'll fix SNI via reflection after build()
        String connectHost = endpointHost != null ? endpointHost : MASQUE_HOST;
        qBuilder.uri(new URI("//" + connectHost + ":" + endpointPort));
        qBuilder.applicationProtocol("h3");
        qBuilder.connectTimeout(Duration.ofSeconds(35));
        qBuilder.noServerCertificateCheck();
        qBuilder.clientKeyManager(keyManager);
        qBuilder.maxOpenPeerInitiatedUnidirectionalStreams(100);
        qBuilder.maxOpenPeerInitiatedBidirectionalStreams(100);
        qBuilder.defaultStreamReceiveBufferSize(50_000_000L);
        qBuilder.quantumReadinessTest(256);
        quicConn = qBuilder.build();
        logger.Debug("QUIC client connection built");

        // DIVERGENCE: usque's DialContext accepts a serverName string that quic-go
        //             passes to crypto/tls.Config.ServerName. Kwik v0.10.10 compiled
        //             JAR lacks the serverName() builder method. The private 'host'
        //             field on QuicClientConnectionImpl drives tlsEngine.setServerName()
        //             during startHandshake() (line 529 of the source). Reflection is
        //             the only way to separate SNI from the UDP peer address.
        // Use reflection to fix the TLS SNI (compiled Kwik JAR v0.10.10 lacks serverName())
        // The 'host' field drives tlsEngine.setServerName(host) during startHandshake.
        try {
            Field hostField = quicConn.getClass().getDeclaredField("host");
            hostField.setAccessible(true);
            hostField.set(quicConn, MASQUE_HOST);
            logger.Debug("Forced SNI to %s via reflection on host field", MASQUE_HOST);
        } catch (Exception e) {
            throw new IOException("Failed to set SNI via reflection", e);
        }

        ExecutorService h3Exec = Executors.newCachedThreadPool(
                r -> { Thread t = new Thread(r, "h3"); t.setDaemon(true); return t; });
        // DIVERGENCE: Flupke's default SETTINGS include QPACK_BLOCKED_STREAMS=0 and
        //             QPACK_MAX_TABLE_CAPACITY=0. Go http3's newClientConn() in
        //             client.go sends SETTINGS with only MaxFieldSectionSize=10MB.
        //             We override Flupke's settings to match exactly.
        //             The server responds with 0x8=1 (SETTINGS_ENABLE_CONNECT_PROTOCOL),
        //             0x33=1 (H3_DATAGRAM), 0x6=32768, 0x276=1, 0x1=0, 0x7=0, plus GREASE.
        h3Connection = new WarpH3Connection(quicConn, h3Exec);

        // Replace Flupke's default settings to match quic-go http3 exactly:
        // only SETTINGS_MAX_FIELD_SECTION_SIZE (0x06) = 10 MB, no QPACK settings
        Map<Long, Long> settings = h3Connection.getSettingsParameters();
        settings.clear();
        settings.put(0x06L, 10_485_760L); // SETTINGS_MAX_FIELD_SECTION_SIZE = 10 MB

        // Log our SETTINGS for debugging
        StringBuilder sb = new StringBuilder("H3 SETTINGS to send:");
        for (var e : settings.entrySet()) sb.append(" 0x").append(Long.toHexString(e.getKey())).append("=").append(e.getValue());
        logger.Debug(sb.toString());

        h3Connection.connect();

        // Log server SETTINGS received from Cloudflare (wait for latch)
        try {
            h3Connection.getSettingsFrameReceived().await(10, TimeUnit.SECONDS);
            Map<Long, Long> peerSettings = h3Connection.getPeerSettingsParameters();
            StringBuilder peerSb = new StringBuilder("Server SETTINGS received:");
            for (var e : peerSettings.entrySet()) peerSb.append(" 0x").append(Long.toHexString(e.getKey())).append("=").append(e.getValue());
            logger.Debug(peerSb.toString());
        } catch (Exception e) {
            logger.Debug("Could not read server SETTINGS: %s", e.getMessage());
        }

        // Log init timing
        long t1 = System.currentTimeMillis();
        logger.Debug("QUIC handshake + control stream done in %dms", t1 - t0);

        // Log transport parameters we sent
        try {
            Field tpField = quicConn.getClass().getDeclaredField("transportParams");
            tpField.setAccessible(true);
            Object tp = tpField.get(quicConn);
            logger.Debug("Our transport params: %s", tp.toString().replace("\n", ", "));
        } catch (Exception e) {
            logger.Debug("Could not read transport params: %s", e.getMessage());
        }

        try {
            qpackEncoder = h3Connection.getQpackEncoder();

            // Log encoder dynamic table state
            Field dynTableField = qpackEncoder.getClass().getDeclaredField("dynamicTable");
            dynTableField.setAccessible(true);
            List<?> dynTable = (List<?>) dynTableField.get(qpackEncoder);
            logger.Debug("QPACK encoder: dynamicTable.size=%d", dynTable.size());

            this.qpackDecoder = h3Connection.getQpackDecoder();
            Field decDynTableField = this.qpackDecoder.getClass().getDeclaredField("dynamicTable");
            decDynTableField.setAccessible(true);
            List<?> decDynTable = (List<?>) decDynTableField.get(qpackDecoder);
            logger.Debug("QPACK decoder: dynamicTable.size=%d", decDynTable.size());

            // Log peer QPACK settings
            logger.Debug("QPACK: peer QPACK_MAX_TABLE_CAPACITY=%d, peer QPACK_BLOCKED_STREAMS=%d",
                    h3Connection.getPeerSettingsParameter(0x01L).orElse(-1L),
                    h3Connection.getPeerSettingsParameter(0x07L).orElse(-1L));
        } catch (Exception e) {
            throw new IOException("Failed to access Flupke internals", e);
        }

        logger.Info("Flupke H3 connection ready (total init: %dms)", System.currentTimeMillis() - t0);

        try {
            Class<?> cls = Class.forName("tech.kwik.core.stream.StreamInputStreamImpl");
            MethodHandles.Lookup privileged = MethodHandles.privateLookupIn(cls, MethodHandles.lookup());
            MethodHandle setter = privileged.findStaticSetter(cls, "waitForNextFrameTimeout", long.class);
            setter.invoke(10_000L);
            logger.Debug("Set kwik stream read timeout to 10s");
        } catch (Throwable e) {
            logger.Debug("Could not set kwik read timeout: %s", e.getMessage());
        }

        // Enable QUIC-level keep-alive PING to prevent WARP edge from closing the
        // connection due to idle timeout. Kwik sends PING frames at half the peer's
        // idle timeout interval (60s/2 = 30s). This does NOT prevent per-stream
        // data stalls but keeps the H3 connection alive for pool reuse.
        try {
            ((QuicClientConnection) quicConn).keepAlive(30);
            logger.Debug("QUIC keep-alive PING enabled (30s)");
        } catch (Exception e) {
            logger.Debug("Could not enable QUIC keep-alive: %s", e.getMessage());
        }
    }

    // DIVERGENCE: usque's http3.Response.Body returns raw bytes directly (the QUIC
    //             stream's unidirectional data). The H3 DATA frame layer is handled
    //             transparently by quic-go. Flupke's Http3ClientConnection.readFrame()
    //             returns raw frames — we must skip GREASE/unknown frames that
    //             Cloudflare's quiche sends before the HEADERS response. Go http3's
    //             frame parsing discards unknown frames silently; Flupke returns them
    //             as UnknownFrame objects that the caller must handle.
    //             Cloudflare sends 2 GREASE frames before the HEADERS response:
    //              type=0x2C13F6C983B26737 length=0 (empty GREASE)
    //              type=0x3E4E75CFBE55517C length=18 (payload decodes to "GREASE is the word")
    private Http3Frame readNextFrame(InputStream input) throws IOException {
        try {
            long frameType = VariableLengthInteger.parseLong(input);
            int payloadLength = VariableLengthInteger.parse(input);

            // Read full payload
            byte[] payload = new byte[payloadLength];
            int offset = 0;
            while (offset < payloadLength) {
                int read = input.read(payload, offset, payloadLength - offset);
                if (read == -1) throw new java.io.EOFException("Stream closed mid-frame");
                offset += read;
            }

            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < payload.length; i++) hex.append(String.format(" %02X", payload[i]));
            logger.Debug("readNextFrame: type=0x%02X length=%d payload[%d]:%s",
                    frameType, payloadLength, payload.length, hex.toString());

            // Parse known frame types
            if (frameType == 0x01) { // HEADERS
                HeadersFrame hf = new HeadersFrame().parsePayload(payload, qpackDecoder);
                return hf;
            } else if (frameType == 0x00) { // DATA
                return new DataFrame().parsePayload(payload);
            } else {
                // Unknown/GREASE - skip
                return new UnknownFrame();
            }
        } catch (java.io.EOFException e) {
            // Stream cleanly closed - return null (caller treats as no frame)
            return null;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to parse frame: " + e.getMessage(), e);
        }
    }

    // DIVERGENCE: usque's l4proxy.go:96-165 DialContext calls http3.RoundTrip which
    //             internally resolves the target locally (resolveLocally=true), then
    //             sends CONNECT with :scheme=https and :path=/ via Go's http.NewRequest.
    //             The Kiche fallback (WarpConnectionKiche) follows the same pattern
    //             and succeeds. Match Kiche's exact request format here.
    public TunnelConnection openTunnel(String targetHost, int targetPort) throws IOException {
        return openTunnel(targetHost, targetPort, null);
    }

    public TunnelConnection openTunnel(String targetHost, int targetPort, byte[] initialData) throws IOException {
        if (closed.get()) throw new IOException("WARP connection closed");

        // Resolve target to IP locally. Cloudflare's MASQUE service requires the
        // resolved IP in :authority (the hostname gives 403). The third-party WARP
        // client does the same (resolveLocally=true in usque's l4proxy.go).
        java.util.List<java.net.InetAddress> addresses;
        try {
            addresses = resolver.lookup(targetHost);
        } catch (Exception e) {
            throw new IOException("DNS resolution failed for " + targetHost, e);
        }
        if (addresses.isEmpty()) {
            throw new IOException("DNS resolution returned no addresses for " + targetHost);
        }
        // Use the first address (AdvancedResolver returns both A and AAAA; prefer IPv6 per Happy Eyeballs).
        java.net.InetAddress resolved = addresses.get(0);
        // Prefer IPv6 over IPv4 for Happy Eyeballs compatibility.
        for (java.net.InetAddress addr : addresses) {
            if (addr.getAddress().length == 16) { resolved = addr; break; }
        }
        String ipStr = resolved.getHostAddress();
        // IPv6 addresses must be bracketed per RFC 3986 in the :authority pseudo-header.
        if (ipStr.contains(":")) ipStr = "[" + ipStr + "]";
        String authority = ipStr + ":" + targetPort;
        logger.Debug("openTunnel: CONNECT :authority=%s (resolved from %s; IPv%d)", authority, targetHost,
                resolved.getAddress().length == 16 ? 6 : 4);

        // Build CONNECT with only :method and :authority pseudo-headers.
        //
        // Cloudflare's WARP MASQUE edge accepts these two headers alone and
        // correctly routes tunnel data through them.  Additional pseudo-headers
        // such as :scheme and :path are NOT required — the edge treats CONNECT
        // as a tunnel method regardless of scheme/path, and adding them triggered
        // per-stream data throttling that cut off DATA-frame delivery after
        // roughly 20–50 KB per tunnel.
        //
        // usque's l4proxy.go inserts :scheme=https and :path=/ automatically
        // because it uses Go's http.NewRequest("CONNECT", "https://"+target, nil),
        // which the standard library adds unconditionally.  That is a Go-idiom
        // artefact, not a WARP-edge requirement.  We omit them deliberately.
        Map<String, String> pseudoHeaders = new LinkedHashMap<>();
        pseudoHeaders.put(":method", "CONNECT");
        pseudoHeaders.put(":authority", authority);
        logger.Debug("CONNECT pseudo-headers: :method=CONNECT :authority=%s", authority);

        HttpHeaders extraHeaders = HttpHeaders.of(Map.of(), (a, b) -> true);
        logger.Debug("CONNECT extra headers: (none)");

        HeadersFrame headersFrame = new HeadersFrame(extraHeaders, pseudoHeaders);

        QuicStream httpStream;
        try {
            httpStream = quicConn.createStream(true);
        } catch (Exception e) {
            logger.Debug("openTunnel: createStream failed: %s: %s", e.getClass().getSimpleName(), e.getMessage());
            throw new IOException("Failed to create QUIC stream: " + e.getMessage(), e);
        }
        try {
            byte[] reqBytes;
            synchronized (qpackEncoder) {
                reqBytes = headersFrame.toBytes(qpackEncoder);
            }
            // Split frame header vs QPACK payload for clearer logging
            int payloadVarintLen = 1;
            if (reqBytes.length > 1) {
                int b1 = reqBytes[1] & 0xFF;
                if ((b1 & 0xC0) == 0x40) payloadVarintLen = 2;
                else if ((b1 & 0xC0) == 0x80) payloadVarintLen = 4;
                else if ((b1 & 0xC0) == 0xC0) payloadVarintLen = 8;
            }
            int hdrLen = 1 + payloadVarintLen;
            if (hdrLen > reqBytes.length) hdrLen = reqBytes.length;
            StringBuilder frameHex = new StringBuilder();
            for (int i = 0; i < Math.min(hdrLen, reqBytes.length); i++) frameHex.append(String.format("%02X ", reqBytes[i]));
            StringBuilder qpackHex = new StringBuilder();
            for (int i = Math.min(hdrLen, reqBytes.length); i < reqBytes.length; i++) qpackHex.append(String.format("%02X ", reqBytes[i]));
            logger.Debug("CONNECT request: frame hdr=%s", frameHex.toString().trim());
            logger.Debug("CONNECT request: QPACK (%d bytes)=%s", reqBytes.length - Math.min(hdrLen, reqBytes.length), qpackHex.toString().trim());
            OutputStream qOs = httpStream.getOutputStream();
            qOs.write(reqBytes); // CONNECT headers only — initial data sent after :status=200
        } catch (Exception e) {
            throw new IOException("Failed to send CONNECT request", e);
        }

        // Read frames, skipping GREASE/unknown (Cloudflare quiche sends GREASE before HEADERS)
        Http3Frame responseFrame = null;
        try {
            InputStream respIs = httpStream.getInputStream();
            int maxAttempts = 10;
            for (int attempt = 1; attempt <= maxAttempts; attempt++) {
                responseFrame = readNextFrame(respIs);
                if (responseFrame instanceof HeadersFrame heads) {
                    logger.Debug("CONNECT response: got HeadersFrame");
                    // Log all response headers for debugging
                    try {
                        Field pf = heads.getClass().getDeclaredField("pseudoHeaders");
                        pf.setAccessible(true);
                        Map<String, String> pseudoMap = (Map<String, String>) pf.get(heads);
                        StringBuilder hdrLog = new StringBuilder("CONNECT response pseudo-headers:");
                        for (var e : pseudoMap.entrySet()) hdrLog.append(" ").append(e.getKey()).append("=").append(e.getValue());
                        logger.Debug(hdrLog.toString());
                        for (var e : heads.headers().map().entrySet())
                            logger.Debug("CONNECT response header: %s=%s", e.getKey(), String.join(",", e.getValue()));
                    } catch (Exception e) {
                        logger.Debug("CONNECT response: could not parse headers (%s)", e.getMessage());
                    }
                    String statusStr = heads.getPseudoHeader(":status");
                    if (statusStr == null || statusStr.isEmpty()) {
                        httpStream.resetStream(0x010eL);
                        throw new IOException("CONNECT response missing :status pseudo-header");
                    }
                    int statusCode = Integer.parseInt(statusStr);
                    if (statusCode < 200 || statusCode >= 300) {
                        httpStream.resetStream(0x010eL);
                        throw new IOException("CONNECT to " + authority + " failed: HTTP " + statusCode);
                    }
                    logger.Debug("openTunnel: CONNECT to %s succeeded on stream %d", authority, httpStream.getStreamId());
                    break;
                }
                if (responseFrame instanceof DataFrame) {
                    httpStream.resetStream(0x010eL);
                    throw new IOException("CONNECT response: unexpected DATA frame before HEADERS");
                }
                if (responseFrame == null) {
                    httpStream.resetStream(0x010eL);
                    throw new IOException("CONNECT response: stream closed, no HEADERS frame");
                }
                // UnknownFrame = GREASE — don't count against retry budget
                if (responseFrame instanceof UnknownFrame) {
                    logger.Debug("openTunnel: skipping GREASE frame (%s)", responseFrame.getClass().getSimpleName());
                    attempt--;
                    continue;
                }
                logger.Debug("openTunnel: skipping unexpected frame type=%s (attempt %d/%d)",
                        responseFrame.getClass().getSimpleName(), attempt, maxAttempts);
            }
            if (responseFrame == null || !(responseFrame instanceof HeadersFrame)) {
                httpStream.resetStream(0x010eL);
                throw new IOException("CONNECT response: no HEADERS frame after " + maxAttempts + " attempts");
            }
        } catch (Exception e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException) throw (IOException) cause;
            throw new IOException("Failed to read CONNECT response", cause != null ? cause : e);
        }

        // Send initial data AFTER tunnel is established (separate DATA frame after :status=200)
        if (initialData != null && initialData.length > 0) {
            try {
                new DataFrame(ByteBuffer.wrap(initialData)).writeTo(httpStream.getOutputStream());
                logger.Debug("openTunnel: sent %d bytes initial data after CONNECT response", initialData.length);
            } catch (Exception e) {
                throw new IOException("Failed to send initial data after tunnel established", e);
            }
        }

        HttpStream tunnel = wrapDataFrameStream(httpStream);
        return TunnelConnection.streamBased(
                tunnel.getInputStream(),
                tunnel.getOutputStream(),
                () -> {
                    try { httpStream.resetStream(0x010fL); } catch (Exception ignored) {}
                },
                () -> {
                    try { httpStream.abortReading(0x010fL); } catch (Exception ignored) {}
                });
    }

    private HttpStream wrapDataFrameStream(QuicStream stream) {
        long qsId = stream.getStreamId();
        return new HttpStream() {
            @Override
            public OutputStream getOutputStream() {
                return new BufferedDataFrameOutputStream(stream.getOutputStream(), 65536, qsId, logger);
            }

            @Override
            public InputStream getInputStream() {
                return new InputStream() {
                    private ByteBuffer dataBuffer;

                    @Override
                    public int read() throws IOException {
                        if (dataBuffer == null || dataBuffer.remaining() == 0) {
                            if (!readData()) return -1;
                        }
                        return dataBuffer.get() & 0xFF;
                    }

                    @Override
                    public int read(byte[] b, int off, int len) throws IOException {
                        if (dataBuffer == null || dataBuffer.remaining() == 0) {
                            if (!readData()) return -1;
                        }
                        int count = Math.min(dataBuffer.remaining(), len);
                        dataBuffer.get(b, off, count);
                        return count;
                    }

                    private boolean readData() throws IOException {
                        while (true) {
                            try {
                                long t0 = System.nanoTime();
                                Http3Frame frame = h3Connection.readFramePublic(stream.getInputStream());
                                long elapsed = (System.nanoTime() - t0) / 1000000;
                                if (logger != null) logger.Debug("Tunnel qs=%d readData (blocked %dms): got %s", qsId, elapsed, frame != null ? frame.getClass().getSimpleName() : "null");
                                if (frame == null) return false;
                                if (frame instanceof DataFrame dataFrame) {
                                    byte[] payload = dataFrame.getPayload();
                                    if (logger != null) logger.Debug("Tunnel qs=%d readData: DataFrame size=%d", qsId, payload.length);
                                    dataBuffer = ByteBuffer.wrap(payload);
                                    return true;
                                }
                                if (logger != null) logger.Debug("Tunnel qs=%d readData: skipping %s, continuing", qsId, frame.getClass().getSimpleName());
                            } catch (HttpError e) {
                                throw new IOException("Failed to read DATA frame", e);
                            } catch (Exception e) {
                                Throwable cause = e.getCause();
                                if (cause instanceof IOException) throw (IOException) cause;
                                throw new IOException("Failed to read DATA frame", cause != null ? cause : e);
                            }
                        }
                    }
                };
            }

            @Override
            public long getStreamId() { return qsId; }
            @Override
            public boolean isBidirectional() { return true; }
            @Override
            public void abortReading(long errorCode) { stream.abortReading(errorCode); }
            @Override
            public void resetStream(long errorCode) { stream.resetStream(errorCode); }
        };
    }

    @Override
    public void close() {
        closed.set(true);
        if (resolver instanceof AutoCloseable c) {
            try { c.close(); } catch (Exception ignored) {}
        }
    }

    // Buffered output stream that coalesces small writes into larger DATA frames.
    // Eliminates per-write DataFrame allocation overhead for bulk transfers.
    private static class BufferedDataFrameOutputStream extends OutputStream {
        private final OutputStream quicStream;
        private final byte[] buffer;
        private int count;
        private final long qsId;
        private final CondLogger log;

        BufferedDataFrameOutputStream(OutputStream quicStream, int bufferSize, long qsId, CondLogger log) {
            this.quicStream = quicStream;
            this.buffer = new byte[bufferSize];
            this.qsId = qsId;
            this.log = log;
        }

        @Override
        public void write(int b) throws IOException {
            if (count >= buffer.length) flushBuffer();
            buffer[count++] = (byte) b;
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (count > 0) flushBuffer();
            if (len <= buffer.length) {
                if (log != null) log.Debug("BDFOS qs=%d write %d bytes to quicStream", qsId, len);
                new DataFrame(ByteBuffer.wrap(b, off, len)).writeTo(quicStream);
            } else {
                int remaining = len;
                int offset = off;
                while (remaining > 0) {
                    int chunk = Math.min(remaining, buffer.length);
                    if (log != null) log.Debug("BDFOS qs=%d write chunk %d bytes to quicStream", qsId, chunk);
                    new DataFrame(ByteBuffer.wrap(b, offset, chunk)).writeTo(quicStream);
                    offset += chunk;
                    remaining -= chunk;
                }
            }
        }

        @Override
        public void flush() throws IOException {
            if (count > 0) flushBuffer();
            if (log != null) log.Debug("BDFOS qs=%d flush", qsId);
            quicStream.flush();
        }

        @Override
        public void close() throws IOException {
            if (count > 0) flushBuffer();
            quicStream.close();
        }

        private void flushBuffer() throws IOException {
            if (log != null) log.Debug("BDFOS qs=%d flushBuffer %d buffered bytes", qsId, count);
            new DataFrame(ByteBuffer.wrap(buffer, 0, count)).writeTo(quicStream);
            count = 0;
        }
    }
}
