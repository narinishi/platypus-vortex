package com.platypus.proxy.handler.h2;

import com.platypus.proxy.ProxyApplication;
import com.platypus.proxy.handler.cert.CertificateGenerator;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.http.server.Request;
import org.glassfish.grizzly.http2.frames.Http2Frame;
import org.glassfish.grizzly.http2.frames.SettingsFrame;
import org.glassfish.grizzly.memory.MemoryManager;

/**
 * Entry point for the h1-over-CONNECT MITM downlink.  After outer TLS,
 * inner TLS is performed and then dispatches to {@link #handleH2MitmRequestStream}
 * or {@link #mitmRequestLoop}.
 *
 * <p>RFC 9113 §8.5 CONNECT method -- establishes tunnel to origin.
 * RFC 7301 §3.1 ALPN -- inner TLS advertises h2/http/1.1.
 */
public class MitmHandler {

    // RFC 9113 §6.5.2 defined SETTINGS: HEADER_TABLE_SIZE(0x1), ENABLE_PUSH(0x2),
    // MAX_CONCURRENT_STREAMS(0x3), INITIAL_WINDOW_SIZE(0x4), MAX_FRAME_SIZE(0x5)

    static final int[][] DEFAULT_SERVER_SETTINGS = {
            {0x1, 4096}, {0x2, 0}, {0x3, 100}, {0x4, 65535}, {0x5, 16384} };

    static final int SERVER_HEADER_TABLE_SIZE = 4096;
    static final MemoryManager<?> MEM_MGR = MemoryManager.DEFAULT_MEMORY_MANAGER;

    private static final Map<String, SSLContext> sslContextCache = new ConcurrentHashMap<>();

    static final Set<String> HTTP2_FORBIDDEN_HEADERS = Set.of(
            "connection", "transfer-encoding", "content-length", "keep-alive",
            "proxy-connection", "te", "trailer", "upgrade");

    private static final Set<Integer> NON_HTTP_PORTS =
            Set.of(5222, 5223, 5228, 5269, 5298, 5672, 1883, 8883, 5683, 5684);

    public static void handleMitmTunnel(H2ProxyService proxyService,
                                        SSLEngineInputStream outerIn,
                                        SSLEngineOutputStream outerOut,
                                        java.nio.channels.SocketChannel clientCh,
                                        String host, int port,
                                        Request request) throws Exception {
        ProxyApplication.getLogger().Debug("[MITM-ENTRY] handleMitmTunnel called: host=%s, port=%d", host, port);

        String ok = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n";
        outerOut.write(ok.getBytes(StandardCharsets.US_ASCII));
        outerOut.flush();

        ProxyApplication.getLogger()
                .Info("MITM CONNECT %s:%d from %s:%d", host, port,
                        clientCh.socket().getInetAddress(), clientCh.socket().getPort());

        if (NON_HTTP_PORTS.contains(port)) {
            ProxyApplication.getLogger()
                    .Info("[MITM-ENTRY] Port %d is in NON_HTTP_PORTS - plain CONNECT passthrough", port);
            proxyService.passthrough(outerIn, outerOut, host, port, clientCh);
            return;
        }

        SSLContext innerCtx = createMitmSslContext(host);
        SSLEngine innerEngine = innerCtx.createSSLEngine();
        innerEngine.setUseClientMode(false);
        innerEngine.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
        SSLParameters innerParams = innerEngine.getSSLParameters();
        innerParams.setApplicationProtocols(new String[]{"h2", "http/1.1"});
        innerEngine.setSSLParameters(innerParams);

        ReadableByteChannel inCh = Channels.newChannel(outerIn);
        WritableByteChannel outCh = Channels.newChannel(outerOut);
        java.nio.ByteBuffer extraAppData = H2ProxyService.doInnerHandshake(innerEngine, inCh, outCh, () -> {
            try { outerOut.flush(); } catch (IOException e) {
                ProxyApplication.getLogger().Error("Flush error: %s", e.getMessage());
            }
        });

        String negotiated = innerEngine.getApplicationProtocol();
        if (negotiated == null || negotiated.isEmpty()) negotiated = "http/1.1";
        ProxyApplication.getLogger().Info("[MITM-ENTRY] Inner ALPN negotiated: %s", negotiated);

        InnerInputStream innerIn = new InnerInputStream(innerEngine, inCh, extraAppData);
        InnerOutputStream innerOut = new InnerOutputStream(innerEngine, outCh, () -> {
            try { outerOut.flush(); } catch (IOException e) {
                ProxyApplication.getLogger().Error("Flush inner: %s", e.getMessage());
            }
        });

        if ("h2".equals(negotiated)) {
            ExecutorService vte = Executors.newVirtualThreadPerTaskExecutor();
            handleH2MitmRequestStream(proxyService, innerIn, innerOut, host, port, vte);
            vte.close();
        } else {
            mitmRequestLoop(proxyService, innerIn, innerOut, host, port);
        }

        ProxyApplication.getLogger().Debug("[MITM-ENTRY] MITM session ended for %s:%d", host, port);
    }

    /**
     * Called when inner ALPN selects {@code h2}.  Creates an
     * {@link H2ConnectionState} that reads frames from the plaintext
     * inner stream.
     */
    public static void handleH2MitmRequestStream(H2ProxyService proxyService,
                                                 InputStream innerIn,
                                                 OutputStream innerOut,
                                                 String host, int port,
                                                 ExecutorService vte) throws IOException {
        // Read client connection preface
        byte[] magic = new byte[24];
        int off = 0;
        while (off < 24) {
            int n = innerIn.read(magic, off, 24 - off);
            if (n < 0) throw new IOException("EOF reading inner h2 preface");
            off += n;
        }
        if (!java.util.Arrays.equals(magic, H2cDetectionFilter.HTTP2_MAGIC)) {
            throw new IOException("Invalid HTTP/2 connection preface (inner)");
        }

        InputStreamFrameSource source = new InputStreamFrameSource(innerIn);

        // Read client SETTINGS (may be preceded by WINDOW_UPDATE etc.)
        Http2Frame frame = source.nextFrame();
        while (frame != null && frame.getStreamId() != 0) {
            ProxyApplication.getLogger().Debug("[inner-h2] skip frame on stream=%d", frame.getStreamId());
            frame = source.nextFrame();
        }
        if (!(frame instanceof SettingsFrame settings)) {
            throw new IOException("Expected client SETTINGS frame on inner h2, got " + frame);
        }

        // Send server SETTINGS
        SettingsFrame serverSettings = SettingsFrame.builder()
                .setting(SettingsFrame.SETTINGS_HEADER_TABLE_SIZE, 4096)
                .setting(SettingsFrame.SETTINGS_ENABLE_PUSH, 0)
                .setting(SettingsFrame.SETTINGS_MAX_CONCURRENT_STREAMS, 100)
                .setting(SettingsFrame.SETTINGS_INITIAL_WINDOW_SIZE, 65535)
                .setting(SettingsFrame.SETTINGS_MAX_FRAME_SIZE, 16384)
                .build();
        org.glassfish.grizzly.Buffer buf = serverSettings.toBuffer(MEM_MGR);
        innerOut.write(toByteArray(buf));
        innerOut.flush();
        buf.tryDispose();

        // ACK client settings
        MitmHandlerH2c.writeFrame(innerOut, SettingsFrame.builder().setAck().build());

        H2ConnectionState conn = new H2ConnectionState(proxyService, source, innerOut, settings);
        conn.mainLoop();
    }

    /**
     * Called when inner ALPN selects {@code http/1.1}.  Relays the plain
     * HTTP/1.1 traffic.
     */
    public static void mitmRequestLoop(H2ProxyService proxyService,
                                       InputStream innerIn,
                                       OutputStream innerOut,
                                       String host, int port) throws Exception {
        String scheme = port == 443 ? "https" : "http";
        String key = H2UpstreamPool.hostKey(host, port);
        H2TunnelConnection tunnel = MitmTunnelConnector.connect(proxyService, host, port, scheme);
        try {
            boolean reusable = proxyService.relayHttp1(innerIn, innerOut, tunnel, host, port);
            if (reusable) {
                tunnel.reuse(key);
                tunnel = null;
            }
        } finally {
            if (tunnel != null) tunnel.close();
        }
    }

    static SSLContext createMitmSslContext(String host) throws Exception {
        SSLContext existing = sslContextCache.get(host);
        if (existing != null) return existing;
        CertificateGenerator gen = CertificateGenerator.getInstance();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        KeyStore.PrivateKeyEntry entry = gen.generateHostEntry(host);
        ks.setKeyEntry(host, entry.getPrivateKey(), "".toCharArray(), entry.getCertificateChain());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "".toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, new SecureRandom());
        SSLContext race = sslContextCache.putIfAbsent(host, ctx);
        return race != null ? race : ctx;
    }

    private static byte[] toByteArray(Buffer buf) {
        byte[] data = new byte[buf.remaining()];
        buf.get(data);
        return data;
    }
}
