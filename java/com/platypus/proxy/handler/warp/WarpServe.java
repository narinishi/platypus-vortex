package com.platypus.proxy.handler.warp;

import com.platypus.proxy.ProxyApplication;
import com.platypus.proxy.io.warp.TunnelConnection;
import com.platypus.proxy.io.warp.TunnelOpener;
import com.platypus.proxy.logging.CondLogger;
import gnu.crypto.der.DER;
import gnu.crypto.der.DERValue;
import gnu.crypto.der.DERWriter;
import gnu.crypto.der.OID;
import gnu.crypto.pki.X500Name;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public final class WarpServe implements Closeable {

    private static final CondLogger log = ProxyApplication.getLogger();

    private static final int RELAY_BUF_SIZE = 65536;

    private final SSLServerSocket serverSocket;
    private final TunnelOpener warpOpener;
    private final Executor executor;
    private final Thread acceptThread;

    public WarpServe(String bindAddress, TunnelOpener warpOpener, Executor executor) throws Exception {
        this.warpOpener = warpOpener;
        this.executor = executor;

        String[] parts = bindAddress.split(":");
        String host = parts[0];
        int port = Integer.parseInt(parts[1]);

        SSLContext sslCtx = createServerSslContext();
        SSLServerSocketFactory ssf = sslCtx.getServerSocketFactory();
        SSLServerSocket sslSock = (SSLServerSocket) ssf.createServerSocket(port, 0, java.net.InetAddress.getByName(host));
        sslSock.setReuseAddress(true);
        sslSock.setNeedClientAuth(false);
        sslSock.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
        sslSock.setEnabledCipherSuites(sslSock.getSupportedCipherSuites());
        SSLParameters params = sslSock.getSSLParameters();
        params.setApplicationProtocols(new String[]{"h2", "http/1.1"});
        sslSock.setSSLParameters(params);
        this.serverSocket = sslSock;

        if (log != null) log.Info("Starting WARP HTTPS proxy on %s:%d", host, port);

        this.acceptThread = new Thread(this::acceptLoop, "warp-accept");
        this.acceptThread.setDaemon(true);
        this.acceptThread.start();

        if (log != null) log.Info("WARP HTTPS proxy running on %s:%d", host, port);
    }

    private SSLContext createServerSslContext() throws Exception {
        // Generate self-signed cert
        SecureRandom rng = new SecureRandom();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4), rng);
        KeyPair kp = kpg.generateKeyPair();

        X509Certificate cert = generateSelfSignedCert(kp, "WarpProxy", rng);

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("proxy", kp.getPrivate(), "changeit".toCharArray(),
                new java.security.cert.Certificate[]{cert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, rng);
        return ctx;
    }

    private void acceptLoop() {
        while (!serverSocket.isClosed()) {
            try {
                SSLSocket client = (SSLSocket) serverSocket.accept();
                if (log != null) log.Debug("[WARP] HTTPS connection from %s", client.getRemoteSocketAddress());
                executor.execute(() -> handleTlsConnection(client));
            } catch (IOException e) {
                if (!serverSocket.isClosed() && log != null)
                    log.Debug("[WARP] Accept error: %s", e.getMessage());
            }
        }
    }

    private void handleTlsConnection(SSLSocket sslSocket) {
        try {
            sslSocket.startHandshake();
            String alpn = sslSocket.getApplicationProtocol();
            if (log != null) log.Debug("[WARP] TLS handshake done, ALPN=%s", alpn);

            InputStream in = sslSocket.getInputStream();
            OutputStream out = sslSocket.getOutputStream();

            if ("h2".equals(alpn)) {
                handleH2(in, out);
            } else {
                handleH1(in, out);
            }
        } catch (IOException e) {
            if (log != null) log.Debug("[WARP] TLS connection error: %s", e.getMessage());
        } finally {
            closeQuietly(sslSocket);
        }
    }

    private static void closeQuietly(java.net.Socket s) {
        try { s.close(); } catch (IOException ignored) {}
    }

    private void handleH2(InputStream in, OutputStream out) throws IOException {
        H2ServerSession session = new H2ServerSession(in, out,
            (session2, streamId, stream, authority, headers) ->
                handleH2Connect(session2, streamId, stream, authority),
            (session2, streamId, stream, method, authority, path, headers) ->
                handleH2Request(session2, streamId, stream, method, authority, path, headers));
        try {
            session.awaitTermination();
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    private void handleH2Connect(H2ServerSession session, int streamId, H2ServerSession.ServerStream stream, String authority) {
        if (log != null) log.Debug("[WARP] H2 CONNECT stream=%d to %s", streamId, authority);

        int colon = authority.lastIndexOf(':');
        if (colon < 0) {
            try { session.sendRstStream(streamId, 0x8); } catch (IOException ignored) {}
            return;
        }
        String host = authority.substring(0, colon);
        int port = Integer.parseInt(authority.substring(colon + 1));

        // Send :status=200 response BEFORE acquiring the tunnel (which may block
        // on the stream semaphore). This lets the browser know the CONNECT was
        // accepted, so it won't time out while we wait for a stream permit.
        Map<String, String> resp = new LinkedHashMap<>();
        resp.put(":status", "200");
        try {
            session.sendHeaders(streamId, resp, H2ServerSession.FLAG_END_HEADERS);
        } catch (IOException e) {
            if (log != null) log.Debug("[WARP] H2 CONNECT stream=%d send error: %s", streamId, e.getMessage());
            return;
        }

        TunnelConnection tunnel = null;
        try {
            tunnel = warpOpener.open(host, port); // NON-LEAK: WARP H3 CONNECT only
        } catch (IOException e) {
            if (log != null) log.Debug("[WARP] H2 CONNECT stream=%d openTunnel error: %s", streamId, e.getMessage());
            if (tunnel != null) tunnel.close();
            return;
        }

        // Relay: browser ↔ tunnel
        InputStream originIn = tunnel.inputStream();
        OutputStream originOut = tunnel.outputStream();
        OutputStream browserOut = stream.outputStream();

        Thread c2o = Thread.startVirtualThread(() -> pipeFromStream(stream, originOut));
        Thread o2c = Thread.startVirtualThread(() -> pipe(originIn, browserOut));
        try { c2o.join(); } catch (InterruptedException ignored) {}
        try { o2c.join(); } catch (InterruptedException ignored) {}
        tunnel.close();
    }

    private void handleH1(InputStream in, OutputStream out) {
        // HTTP/1.1 over TLS — simple CONNECT relay
        try {
            HttpRequest req = parseRequest(in);
            if (req == null || !"CONNECT".equalsIgnoreCase(req.method)) return;

            TunnelConnection tunnel = warpOpener.open(req.host, req.port); // NON-LEAK
            out.write("HTTP/1.1 200 OK\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            out.flush();

            Thread c2o = Thread.startVirtualThread(() -> pipe(in, tunnel.outputStream()));
            Thread o2c = Thread.startVirtualThread(() -> pipe(tunnel.inputStream(), out));
            try { c2o.join(); } catch (InterruptedException ignored) {}
            try { o2c.join(); } catch (InterruptedException ignored) {}
            tunnel.close();
        } catch (IOException e) {
            if (log != null) log.Debug("[WARP] H1 tunnel error: %s", e.getMessage());
        }
    }

    private static String parseHost(String authority) {
        int colon = authority.lastIndexOf(':');
        if (colon < 0) return authority;
        return authority.substring(0, colon);
    }

    private static int parsePort(String authority, int defaultPort) {
        int colon = authority.lastIndexOf(':');
        if (colon < 0) return defaultPort;
        return Integer.parseInt(authority.substring(colon + 1));
    }

    private static boolean isHopByHop(String key) {
        String lk = key.toLowerCase();
        return lk.equals("connection") || lk.equals("keep-alive") || lk.equals("proxy-connection")
                || lk.equals("transfer-encoding") || lk.equals("upgrade") || lk.equals("proxy-authenticate")
                || lk.equals("proxy-authorization") || lk.equals("te");
    }

    private void handleH2Request(H2ServerSession session, int streamId, H2ServerSession.ServerStream stream,
                                  String method, String authority, String path, Map<String, String> headers) {
        if (log != null) log.Debug("[WARP] H2 request stream=%d %s %s%s", streamId, method, authority, path);

        String scheme = headers.get(":scheme");
        int defaultPort = "https".equals(scheme) ? 443 : 80;
        String host = parseHost(authority);
        int port = parsePort(authority, defaultPort);
        if (path == null) path = "/";

        try (TunnelConnection tunnel = warpOpener.open(host, port)) { // NON-LEAK
            // Build HTTP/1.1 request
            StringBuilder req = new StringBuilder(512);
            req.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
            req.append("Host: ").append(host);
            if ((port == 80 && !"https".equals(scheme)) || (port == 443 && "https".equals(scheme))) {
                // default port, omit from Host
            } else {
                req.append(':').append(port);
            }
            req.append("\r\n");
            for (Map.Entry<String, String> e : headers.entrySet()) {
                String k = e.getKey();
                if (k.startsWith(":")) continue;
                if (isHopByHop(k)) continue;
                if ("host".equalsIgnoreCase(k)) continue; // added separately above
                req.append(k).append(": ").append(e.getValue()).append("\r\n");
            }
            req.append("\r\n");

            byte[] requestBytes = req.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            if (log != null) log.Debug("[WARP] H2 req=%d sending %d bytes to origin", streamId, requestBytes.length);
            tunnel.outputStream().write(requestBytes);
            tunnel.outputStream().flush();

            // Read HTTP/1.1 response
            InputStream originIn = tunnel.inputStream();
            int statusCode = 0;
            LinkedHashMap<String, String> respHeaders = new LinkedHashMap<>();

            // Parse status line
            if (log != null) log.Debug("[WARP] H2 req=%d reading response status line", streamId);
            String statusLine = readLine(originIn);
            if (log != null) log.Debug("[WARP] H2 req=%d got status line: %s", streamId, statusLine);
            if (statusLine == null) throw new IOException("No response");
            String[] statusParts = statusLine.split(" ", 3);
            if (statusParts.length >= 2) {
                try { statusCode = Integer.parseInt(statusParts[1]); } catch (NumberFormatException ignored) {}
            }

            // Parse response headers (raw, before stripping hop-by-hop)
            String rawTe = null;
            String rawCl = null;
            while (true) {
                String line = readLine(originIn);
                if (line == null || line.isEmpty()) break;
                int c = line.indexOf(':');
                if (c > 0) {
                    String key = line.substring(0, c).trim().toLowerCase();
                    String val = line.substring(c + 1).trim();
                    if ("transfer-encoding".equals(key)) rawTe = val;
                    if ("content-length".equals(key)) rawCl = val;
                    if (!isHopByHop(key)) {
                        respHeaders.put(key, val);
                    }
                }
            }

            if (statusCode == 0) throw new IOException("Bad response status");
            if (log != null) log.Debug("[WARP] H2 req=%d status=%d, %d response headers", streamId, statusCode, respHeaders.size());

            // Send H2 response headers (hop-by-hop already stripped)
            LinkedHashMap<String, String> h2Resp = new LinkedHashMap<>();
            h2Resp.put(":status", Integer.toString(statusCode));
            for (Map.Entry<String, String> e : respHeaders.entrySet()) {
                h2Resp.put(e.getKey(), e.getValue());
            }
            session.sendHeaders(streamId, h2Resp, H2ServerSession.FLAG_END_HEADERS);

            // Relay response body (use raw headers, before hop-by-hop stripping)
            String te = rawTe;
            String cl = rawCl;
            if (log != null) log.Debug("[WARP] H2 req=%d piping body: te=%s cl=%s", streamId, te, cl);
            if ("chunked".equalsIgnoreCase(te)) {
                pipeChunked(originIn, session, streamId);
            } else if (cl != null) {
                pipeBody(originIn, session, streamId, Long.parseLong(cl));
                session.sendData(streamId, new byte[0], H2ServerSession.FLAG_END_STREAM);
            } else if (statusCode >= 200 && statusCode != 204 && statusCode != 304) {
                pipeToEof(originIn, session, streamId);
            } else {
                session.sendData(streamId, new byte[0], H2ServerSession.FLAG_END_STREAM);
            }
            if (log != null) log.Debug("[WARP] H2 req=%d body done", streamId);
        } catch (IOException e) {
            if (log != null) log.Debug("[WARP] H2 request stream=%d error: %s", streamId, e.getMessage());
            try { session.sendRstStream(streamId, 0x8); } catch (IOException ignored) {}
        }
    }

    private static void pipeChunked(InputStream in, H2ServerSession session, int streamId) throws IOException {
        while (true) {
            String chunkSizeLine = readLine(in);
            if (chunkSizeLine == null) break;
            int chunkSize = Integer.parseInt(chunkSizeLine.trim(), 16);
            if (chunkSize == 0) {
                readLine(in); // trailing CRLF
                session.sendData(streamId, new byte[0], H2ServerSession.FLAG_END_STREAM);
                return;
            }
            byte[] chunk = new byte[chunkSize];
            readExact(in, chunk);
            readLine(in); // trailing CRLF
            session.sendData(streamId, chunk, 0);
        }
    }

    private static void pipeBody(InputStream in, H2ServerSession session, int streamId, long len) throws IOException {
        byte[] buf = new byte[65536];
        while (len > 0) {
            int n = in.read(buf, 0, (int) Math.min(buf.length, len));
            if (n < 0) break;
            len -= n;
            session.sendData(streamId, buf, 0, n, 0);
        }
    }

    private static void pipeToEof(InputStream in, H2ServerSession session, int streamId) throws IOException {
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) >= 0) {
            session.sendData(streamId, buf, 0, n, 0);
        }
        session.sendData(streamId, new byte[0], H2ServerSession.FLAG_END_STREAM);
    }

    private static void readExact(InputStream in, byte[] dst) throws IOException {
        int off = 0;
        while (off < dst.length) {
            int n = in.read(dst, off, dst.length - off);
            if (n < 0) throw new IOException("Unexpected EOF");
            off += n;
        }
    }

    private static void pipe(InputStream in, OutputStream out) {
        byte[] buf = new byte[RELAY_BUF_SIZE];
        try {
            int n;
            while ((n = in.read(buf)) >= 0) {
                out.write(buf, 0, n);
            }
        } catch (IOException ignored) {}
    }

    private static void pipeFromStream(H2ServerSession.ServerStream stream, OutputStream out) {
        try {
            byte[] chunk;
            while ((chunk = stream.readChunk()) != null) {
                out.write(chunk);
            }
        } catch (IOException ignored) {}
    }

    // ─── HTTP/1.1 request parsing ──────────────────────────────────────────

    private static final class HttpRequest {
        final String method;
        final String host;
        final int port;

        HttpRequest(String method, String host, int port) {
            this.method = method;
            this.host = host;
            this.port = port;
        }
    }

    private static HttpRequest parseRequest(InputStream in) throws IOException {
        String requestLine = readLine(in);
        if (requestLine == null || requestLine.isEmpty()) return null;
        String[] parts = requestLine.split(" ", 3);
        if (parts.length < 3) return null;
        String method = parts[0];
        String uri = parts[1];

        String host = null;
        int port = 443;
        if (uri.contains("://")) {
            // Absolute-form URI: CONNECT http://host:port/...
            String rest = uri.substring(uri.indexOf("://") + 3);
            int slash = rest.indexOf('/');
            if (slash > 0) rest = rest.substring(0, slash);
            int colon = rest.lastIndexOf(':');
            if (colon > 0) {
                host = rest.substring(0, colon);
                port = Integer.parseInt(rest.substring(colon + 1));
            } else {
                host = rest;
            }
        } else {
            // authority-form: CONNECT host:port
            int colon = uri.lastIndexOf(':');
            if (colon > 0) {
                host = uri.substring(0, colon);
                port = Integer.parseInt(uri.substring(colon + 1));
            } else {
                host = uri;
            }
        }
        return new HttpRequest(method, host, port);
    }

    // Per-thread scratch buffer for readLine to avoid per-byte reads
    private static final ThreadLocal<byte[]> LINE_SCRATCH = ThreadLocal.withInitial(() -> new byte[4096]);

    private static String readLine(InputStream in) throws IOException {
        byte[] scratch = LINE_SCRATCH.get();
        int pos = 0;
        int b = 0;
        while (pos < scratch.length) {
            b = in.read();
            if (b == -1) break;
            if (b == '\r') continue;
            if (b == '\n') break;
            scratch[pos++] = (byte) b;
        }
        return pos > 0 ? new String(scratch, 0, pos, java.nio.charset.StandardCharsets.ISO_8859_1) : (b == -1 ? null : "");
    }

    @Override
    public void close() {
        try { serverSocket.close(); } catch (IOException ignored) {}
    }

    // ─── Self-signed certificate generation ─────────────────────────────────

    private static final OID OID_COMMON_NAME = new OID("2.5.4.3");
    private static final String SIG_ALG = "SHA256withRSA";
    private static final String SIG_ALG_OID = "1.2.840.113549.1.1.11";

    private static X509Certificate generateSelfSignedCert(KeyPair kp, String cn, SecureRandom rng) throws Exception {
        X500Name subject = buildX500Name(cn);

        byte[] tbsCert = buildTbsCertificate(kp.getPublic(), subject, kp.getPublic(), rng);

        Signature sig = Signature.getInstance(SIG_ALG);
        sig.initSign(kp.getPrivate());
        sig.update(tbsCert);
        byte[] signatureBytes = sig.sign();

        ByteArrayOutputStream certBody = new ByteArrayOutputStream(tbsCert.length + 256);
        certBody.write(tbsCert);
        certBody.write(encodeAlgorithmIdentifier(SIG_ALG_OID));
        byte[] bitStringContent = new byte[signatureBytes.length + 1];
        bitStringContent[0] = 0;
        System.arraycopy(signatureBytes, 0, bitStringContent, 1, signatureBytes.length);
        certBody.write(DER.BIT_STRING);
        writeDerLength(certBody, bitStringContent.length);
        certBody.write(bitStringContent);

        byte[] encoded = wrapSequence(certBody.toByteArray());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoded));
    }

    private static byte[] buildTbsCertificate(PublicKey pubKey, X500Name subject,
                                              PublicKey issuerPubKey, SecureRandom rng) throws Exception {
        ByteArrayOutputStream content = new ByteArrayOutputStream(512);

        // version [0] EXPLICIT INTEGER v3 (2)
        byte[] verBytes = new DERValue(DER.INTEGER, BigInteger.valueOf(2)).getEncoded();
        content.write(0xA0);
        writeDerLength(content, verBytes.length);
        content.write(verBytes);

        // serialNumber
        byte[] serial = new byte[16];
        rng.nextBytes(serial);
        content.write(new DERValue(DER.INTEGER, new BigInteger(1, serial)).getEncoded());

        // signature AlgorithmIdentifier
        content.write(encodeAlgorithmIdentifier(SIG_ALG_OID));

        // issuer
        content.write(subject.getDer());

        // validity
        Date now = new Date();
        Date expires = new Date(now.getTime() + TimeUnit.DAYS.toMillis(365));
        List<DERValue> validity = new ArrayList<>();
        validity.add(encodeTime(now));
        validity.add(encodeTime(expires));
        DERWriter.write(content, new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, validity));

        // subject = issuer (self-signed)
        content.write(subject.getDer());

        // subjectPublicKeyInfo
        content.write(encodePublicKey(pubKey));

        byte[] tbsContent = content.toByteArray();
        return wrapSequence(tbsContent);
    }

    private static X500Name buildX500Name(String cn) throws IOException {
        List<DERValue> rdns = new ArrayList<>();
        List<DERValue> tv = new ArrayList<>();
        tv.add(new DERValue(DER.OBJECT_IDENTIFIER, OID_COMMON_NAME));
        tv.add(new DERValue(DER.UTF8_STRING, cn));
        rdns.add(new DERValue(DER.CONSTRUCTED | DER.SET, Collections.singletonList(
                new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, tv))));
        return new X500Name(new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, rdns).getEncoded());
    }

    private static byte[] encodeAlgorithmIdentifier(String oidStr) throws IOException {
        byte[] oidBytes = new DERValue(DER.OBJECT_IDENTIFIER, new OID(oidStr)).getEncoded();
        ByteArrayOutputStream baos = new ByteArrayOutputStream(oidBytes.length + 4);
        baos.write(DER.CONSTRUCTED | DER.SEQUENCE);
        writeDerLength(baos, oidBytes.length + 2);
        baos.write(oidBytes);
        baos.write(DER.NULL);
        baos.write(0);
        return baos.toByteArray();
    }

    private static byte[] encodePublicKey(PublicKey publicKey) throws GeneralSecurityException, IOException {
        byte[] encoded = publicKey.getEncoded();
        if (encoded != null && "X.509".equals(publicKey.getFormat())) return encoded;
        KeyFactory kf = KeyFactory.getInstance(publicKey.getAlgorithm());
        return kf.getKeySpec(publicKey, X509EncodedKeySpec.class).getEncoded();
    }

    private static DERValue encodeTime(Date date) {
        Instant instant = date.toInstant();
        ZonedDateTime utc = instant.atZone(ZoneOffset.UTC);
        int year = utc.getYear();
        String fmt = year >= 1950 && year < 2050 ? "yyMMddHHmmss" : "yyyyMMddHHmmss";
        return new DERValue(year >= 1950 && year < 2050 ? DER.UTC_TIME : DER.GENERALIZED_TIME,
                utc.format(DateTimeFormatter.ofPattern(fmt)) + "Z");
    }

    private static byte[] wrapSequence(byte[] inner) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(inner.length + 4);
        buf.write(DER.CONSTRUCTED | DER.SEQUENCE);
        writeDerLength(buf, inner.length);
        buf.write(inner);
        return buf.toByteArray();
    }

    private static void writeDerLength(OutputStream out, int len) throws IOException {
        if (len < 128) out.write(len);
        else if (len < 256) { out.write(0x81); out.write(len); }
        else if (len < 65536) { out.write(0x82); out.write(len >> 8); out.write(len); }
        else { out.write(0x83); out.write(len >> 16); out.write(len >> 8); out.write(len); }
    }
}
