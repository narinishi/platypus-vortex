package com.platypus.proxy.handler.cert;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import javax.net.ssl.*;

/**
 * Utility class for building an {@link SSLContext} using the self-signed CA
 * created by {@link CertificateGenerator}.  The context carries a per-host
 * leaf certificate generated on the fly and chained to the CA.
 * <p>
 * As a side effect the leaf certificate is written to {@code certs/<hostname>.crt}
 * and the root CA (if not already present) to {@code certs/rootCA.crt}.
 * Import {@code rootCA.crt} into your browser's trust store to inspect
 * proxied HTTPS traffic.
 */
public final class SSLContextProvider {

    private static final Path CERTS_DIR = Path.of("certs");

    private SSLContextProvider() {
        // Utility class
    }

    /**
     * Creates a TLS {@link SSLContext} for the given hostname using the
     * self-signed CA that is managed by {@link CertificateGenerator}.
     *
     * @param hostname the target hostname for which a leaf certificate is generated
     * @param password password used to protect the in-memory keystore
     * @return fully initialised {@code SSLContext}
     * @throws Exception if any cryptographic or I/O error occurs
     */
    public static SSLContext createSSLContext(String hostname, String password) throws Exception {
        // 1. Use the singleton CA to generate a leaf certificate + key pair
        CertificateGenerator gen = CertificateGenerator.getInstance();
        KeyStore.PrivateKeyEntry entry = gen.generateHostEntry(hostname);

        X509Certificate leafCert = (X509Certificate) entry.getCertificateChain()[0];

        // 2. Export generated certificates for the user to import if desired
        exportLeafCertificate(hostname, leafCert);
        exportRootCertificate(CertificateGenerator.getCaCertificate());

        // 3. Build an in-memory KeyStore containing the leaf's private key and chain
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, password.toCharArray());
        ks.setKeyEntry("leaf", entry.getPrivateKey(), password.toCharArray(), entry.getCertificateChain());

        // 4. Initialise the KeyManagerFactory and SSLContext
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, password.toCharArray());

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx;
    }

    // ====================== export helpers ======================

    private static void exportLeafCertificate(String hostname, X509Certificate cert) throws Exception {
        String safeHostname = hostname.replaceAll("[^a-zA-Z0-9.-]", "_");
        Path certFile = CERTS_DIR.resolve(safeHostname + ".crt");
        writeCertificate(cert, certFile);
    }

    private static void exportRootCertificate(X509Certificate caCert) throws Exception {
        Path certFile = CERTS_DIR.resolve("rootCA.crt");
        writeCertificate(caCert, certFile);
    }

    private static void writeCertificate(X509Certificate cert, Path file) throws Exception {
        Files.createDirectories(CERTS_DIR);
        byte[] pemBytes = toPemBytes(cert);
        Files.write(file, pemBytes);
    }

    private static byte[] toPemBytes(X509Certificate cert) throws Exception {
        String encoded = Base64.getEncoder().encodeToString(cert.getEncoded());
        StringBuilder pem = new StringBuilder()
                .append("-----BEGIN CERTIFICATE-----\n")
                .append(encoded.replaceAll("(.{64})", "$1\n"))
                .append("\n-----END CERTIFICATE-----\n");
        return pem.toString().getBytes(StandardCharsets.UTF_8);
    }
}
