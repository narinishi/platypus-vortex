// ===== Modified: com/platypus/proxy/connection/TlsHelper.java =====
// (ALPN support added; existing method preserved for compatibility)
package com.platypus.proxy.handler;

import java.io.IOException;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import javax.net.ssl.*;

/**
 * Shared TLS wrapping utility for outbound/proxy connections.
 * Uses a permissive trust manager because we are connecting to user-specified
 * endpoints (proxies) whose certificates may be self-signed or private.
 *
 * <p>Thread-safe lazy initialization of SSLContext.
 * <p>Now supports ALPN negotiation: {@link #wrapWithAlpn(Socket, String, boolean, String[])}
 * performs the handshake with the given application protocols and returns
 * the negotiated protocol string, enabling HTTP/2 detection and fallback.
 */
public final class TlsHelper {

    private static volatile SSLContext sslContext;

    private TlsHelper() {}

    /**
     * Result of a TLS handshake that includes ALPN negotiation.
     *
     * @param socket         the ready-to-use SSLSocket (handshake complete)
     * @param alpnProtocol   the protocol negotiated via ALPN, or {@code null} /
     *                       empty string if none was selected
     */
    public record TlsHandshakeResult(SSLSocket socket, String alpnProtocol) {}

    // ------------------------------------------------------------------
    //  Legacy wrap() - no ALPN, kept for backward compatibility.
    // ------------------------------------------------------------------

    /**
     * Wraps an existing TCP socket with TLS, optionally hiding the SNI extension.
     *
     * @param raw        connected TCP socket
     * @param serverName expected TLS server name (SNI host)
     * @param hideSNI    if true, omit the SNI extension from the ClientHello
     * @return SSLSocket ready for use
     * @throws IOException if handshake or SSL setup fails
     */
    public static Socket wrap(Socket raw, String serverName, boolean hideSNI) throws IOException {
        // Delegate to wrapWithAlpn with no ALPN protocols (preserves old behavior).
        TlsHandshakeResult result = wrapWithAlpn(raw, serverName, hideSNI, null);
        return result.socket();
    }

    // ------------------------------------------------------------------
    //  New ALPN-aware method
    // ------------------------------------------------------------------

    /**
     * Wraps an existing TCP socket with TLS and, if {@code alpnProtocols} is
     * non-null and non-empty, requests the given ALPN protocols during the
     * handshake.
     *
     * <p>After the handshake the {@link TlsHandshakeResult} contains the
     * SSLSocket and the negotiated ALPN protocol string (as returned by
     * {@link SSLSocket#getApplicationProtocol()}).  If the server did not
     * select a protocol, {@code alpnProtocol} will be {@code null} or empty.
     *
     * @param raw            connected TCP socket
     * @param serverName     expected TLS server name (SNI host)
     * @param hideSNI        if true, omit the SNI extension
     * @param alpnProtocols  application protocols to offer via ALPN; may be null
     * @return the handshake result
     * @throws IOException   if SSL setup or handshake fails
     */
    public static TlsHandshakeResult wrapWithAlpn(
            Socket raw, String serverName, boolean hideSNI, String[] alpnProtocols) throws IOException {

        try {
            SSLContext ctx = getSslContext();
            SSLSocketFactory factory = ctx.getSocketFactory();
            SSLSocket sslSocket = (SSLSocket) factory.createSocket(raw, serverName, raw.getPort(), true);

            SSLParameters params = sslSocket.getSSLParameters();
            if (hideSNI) {
                params.setServerNames(Collections.emptyList()); // hide SNI
                params.setEndpointIdentificationAlgorithm(null); // disable built-in hostname check
            }
            if (alpnProtocols != null && alpnProtocols.length > 0) {
                params.setApplicationProtocols(alpnProtocols);
            }
            sslSocket.setSSLParameters(params);

            sslSocket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
            sslSocket.startHandshake();

            // Manual hostname verification when SNI is hidden
            if (hideSNI) {
                X509Certificate[] chain =
                        (X509Certificate[]) sslSocket.getSession().getPeerCertificates();
                HostnameVerifier.verifyHostname(serverName, chain[0]);
            }

            String negotiated = sslSocket.getApplicationProtocol();
            return new TlsHandshakeResult(sslSocket, negotiated);
        } catch (CertificateException e) {
            throw new IOException("Hostname verification failed for " + serverName, e);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IOException("TLS wrapping failed", e);
        }
    }

    public static TlsHandshakeResult oldWrapWithAlpn(
            Socket raw, String serverName, boolean hideSNI, String[] alpnProtocols) throws IOException {

        try {
            SSLContext ctx = getSslContext();
            SSLSocketFactory factory = ctx.getSocketFactory();
            SSLSocket sslSocket = (SSLSocket) factory.createSocket(raw, serverName, raw.getPort(), true);

            // --- Collect all parameter changes and apply in a single call ---
            // Reading via getSSLParameters() returns a fresh mutable copy,
            // and setSSLParameters() replaces the entire parameter object.
            // Configuring SNI and ALPN in two separate calls would cause
            // the second call to overwrite the first.
            SSLParameters params = sslSocket.getSSLParameters();
            if (hideSNI) {
                params.setServerNames(Collections.emptyList());
            }
            if (alpnProtocols != null && alpnProtocols.length > 0) {
                String[] protocols = Arrays.copyOf(alpnProtocols, alpnProtocols.length);
                params.setApplicationProtocols(protocols);
            }
            if (hideSNI || (alpnProtocols != null && alpnProtocols.length > 0)) {
                sslSocket.setSSLParameters(params);
            }

            sslSocket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});

            sslSocket.startHandshake();

            // After handshake, retrieve the protocol selected by the server.
            String negotiated = sslSocket.getApplicationProtocol();

            return new TlsHandshakeResult(sslSocket, negotiated);

        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IOException("TLS wrapping failed", e);
        }
    }

    private static SSLContext getSslContext() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext ctx = sslContext;
        if (ctx == null) {
            synchronized (TlsHelper.class) {
                ctx = sslContext;
                if (ctx == null) {
                    ctx = SSLContext.getInstance("TLS");
                    ctx.init(
                            null,
                            new TrustManager[] {
                                new X509TrustManager() {
                                    @Override
                                    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

                                    @Override
                                    public void checkServerTrusted(X509Certificate[] chain, String authType) {}

                                    @Override
                                    public X509Certificate[] getAcceptedIssuers() {
                                        return new X509Certificate[0];
                                    }
                                }
                            },
                            null);
                    sslContext = ctx;
                }
            }
        }
        return ctx;
    }
}
