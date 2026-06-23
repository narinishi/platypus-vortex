package com.platypus.proxy.handler.cert;

import gnu.crypto.der.DER;
import gnu.crypto.der.DERValue;
import gnu.crypto.der.DERWriter;
import gnu.crypto.der.OID;
import gnu.crypto.pki.X500Name;
import gnu.crypto.pki.ext.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.TimeUnit;
import javax.security.auth.x500.X500Principal;

/**
 * Generates a self-signed MITM CA certificate (RSA-2048) and per-host
 * end-entity certificates signed by that CA or an externally provided CA.
 * <p>
 * All DER encoding is performed manually to guarantee strict compliance with
 * the Distinguished Encoding Rules (DER) required by RFC 5280.  In particular,
 * optional fields with DEFAULT values (such as the {@code critical} BOOLEAN in
 * extensions) are omitted when their value equals the default, as mandated by
 * X.690 §11.5.  The previous implementation delegated extension serialization
 * to {@code gnu.crypto.pki.ext.Extension}, which unconditionally encoded the
 * {@code critical} field even when FALSE -- a DER violation that causes
 * BoringSSL / Chrome to reject the certificate outright.
 * <p>
 * The issuer distinguished name of leaf certificates is an exact byte-for-byte
 * copy of the CA certificate's subject (as obtained from
 * {@link X500Principal#getEncoded()}).  This avoids encoding mismatches
 * (PrintableString vs. UTF8String) that cause modern browsers to reject the
 * certificate chain.
 * <p>
 * All leaf certificates include an Authority Key Identifier extension, matching
 * the CA's Subject Key Identifier.  This is mandatory for proper chain building
 * in Chrome and other strict implementations.
 * <p>
 * Signatures use SHA-256 (compatible with TLS 1.3).  Certificates are
 * assembled as raw DER -- pre-encoded structures are written as bytes to
 * avoid the CONSTRUCTED_VALUE round-trip bug in {@code gnu.crypto.der}.
 */
public final class CertificateGenerator {

    // ====================== constants ======================

    private static final String KEY_ALG = "RSA";
    private static final int KEY_SIZE = 2048;

    /** SHA-256 with RSA -- OID 1.2.840.113549.1.1.11 */
    private static final String SIG_ALG_JCA = "SHA256withRSA";

    private static final String SIG_ALG_OID = "1.2.840.113549.1.1.11";

    /** SHA-256 with ECDSA -- OID 1.2.840.10045.4.3.2 */
    private static final String EC_SIG_ALG_JCA = "SHA256withECDSA";

    private static final String EC_SIG_ALG_OID = "1.2.840.10045.4.3.2";

    private static final long CA_VALIDITY_DAYS = 3650;
    private static final long HOST_CERT_VALIDITY_DAYS = 365;

    /** OID for id-kp-serverAuth (TLS server authentication). */
    private static final OID OID_SERVER_AUTH = new OID("1.3.6.1.5.5.7.3.1");

    /*
     * KeyUsage bit positions (MSB-first within the byte, per RFC 5280 §4.2.1.3).
     *
     *   bit 0 (MSB) = digitalSignature
     *   bit 2       = keyEncipherment
     *   bit 5       = keyCertSign
     *   bit 6       = cRLSign
     */
    private static final int KU_DIGITAL_SIGNATURE = 0x80; // bit 0
    private static final int KU_KEY_ENCIPHERMENT = 0x20; // bit 2
    private static final int KU_KEY_CERT_SIGN = 0x04; // bit 5
    private static final int KU_CRL_SIGN = 0x02; // bit 6

    // ====================== X.500 attribute OIDs ======================

    /** commonName -- OID 2.5.4.3 */
    private static final OID OID_COMMON_NAME = new OID("2.5.4.3");

    /** organizationName -- OID 2.5.4.10 */
    private static final OID OID_ORGANIZATION = new OID("2.5.4.10");

    /** countryName -- OID 2.5.4.6 */
    private static final OID OID_COUNTRY = new OID("2.5.4.6");

    /**
     * ASN.1 universal tag for PrintableString (0x13 = 19).
     * RFC 5280 §4.1.2.4 requires the countryName attribute to be
     * encoded as a PrintableString containing exactly two alpha characters.
     */
    private static final int PRINTABLE_STRING_TAG = 19;

    private static final Path CERTS_DIR = Paths.get("certs");
    private static final String ROOT_CA_FILENAME = "rootCA.crt";

    // ====================== instance state ======================

    private final KeyPair caKeyPair;
    private final X509Certificate caCertificate;
    private final X500Name caSubject;
    private final SecureRandom rng = createSecureRandom();

    // ====================== ExtensionEntry ======================

    /**
     * Holds the components of an X.509v3 extension without performing any
     * DER serialization.  The {@link #writeTo} method encodes the extension
     * in strict DER form, omitting the {@code critical} field when it equals
     * its DEFAULT value of FALSE (as required by X.690 §11.5 / RFC 5280).
     *
     * <h3>Why this replaces {@code gnu.crypto.pki.ext.Extension}</h3>
     * <p>
     * The GNU Crypto {@link Extension} class unconditionally serializes the
     * {@code critical} field, producing e.g. {@code BOOLEAN :0} even when
     * the extension is non-critical.  Under DER rules a value equal to the
     * DEFAULT must be absent.  BoringSSL (used by Chrome) enforces this
     * strictly and rejects certificates that contain the spurious boolean.
     */
    private static final class ExtensionEntry {

        /** Extension OID (e.g. 2.5.29.19 for BasicConstraints). */
        final OID oid;

        /** Whether this extension is critical. */
        final boolean critical;

        /**
         * Raw DER encoding of the extension-specific structure.
         * <p>
         * For example, for BasicConstraints this is the DER of
         * {@code SEQUENCE { BOOLEAN cA [, INTEGER pathLen ] }}.
         * For SubjectKeyIdentifier this is the DER of an OCTET STRING
         * containing the key hash.
         * <p>
         * This value will be wrapped in an ASN.1 OCTET STRING by
         * {@link #writeTo}.
         */
        final byte[] value;

        ExtensionEntry(OID oid, boolean critical, byte[] value) {
            this.oid = oid;
            this.critical = critical;
            this.value = value;
        }

        /**
         * Writes this extension as a DER-encoded
         * {@code SEQUENCE { extnID, [critical], extnValue }} to the
         * given stream.
         * <p>
         * The {@code critical} field is <strong>only</strong> included when
         * its value is {@code true}.  When {@code false} it is omitted
         * entirely -- the key difference from the old
         * {@code gnu.crypto.pki.ext.Extension} serialization.
         */
        void writeTo(OutputStream out) throws IOException {
            ByteArrayOutputStream inner = new ByteArrayOutputStream();

            // extnID OBJECT IDENTIFIER
            inner.write(new DERValue(DER.OBJECT_IDENTIFIER, oid).getEncoded());

            // critical BOOLEAN -- ONLY written when TRUE
            // X.690 §11.5: "The encoding of a value whose type has a DEFAULT
            // shall not include the default value."
            if (critical) {
                inner.write(DER.BOOLEAN); // tag 0x01
                inner.write(0x01); // length 1
                inner.write(0xFF); // value TRUE (DER mandates 0xFF)
            }
            // When critical == false: field is completely absent ^^

            // extnValue OCTET STRING
            inner.write(DER.OCTET_STRING);
            writeDerLength(inner, value.length);
            inner.write(value);

            // Wrap everything in a SEQUENCE
            out.write(DER.CONSTRUCTED | DER.SEQUENCE);
            writeDerLength(out, inner.size());
            out.write(inner.toByteArray());
        }
    }

    // ====================== CertInfo (plain data holder) ======================

    private static class CertInfo {
        int version = 1;
        BigInteger serialNumber;
        Date notBefore;
        Date notAfter;
        X500Name subject;
        X500Name issuer; // used only for self-signed CA
        byte[] issuerDer; // raw DER of issuer name; takes precedence when present
        PublicKey publicKey;
        final Map<OID, ExtensionEntry> extensions = new LinkedHashMap<>();
    }

    // ====================== singleton bootstrap ======================

    private static final class Holder {
        static final CertificateGenerator INSTANCE;

        static {
            System.err.println("[CertificateGenerator] Starting CA initialisation...");
            long t0 = System.currentTimeMillis();
            try {
                INSTANCE = new CertificateGenerator();
            } catch (Exception e) {
                throw new ExceptionInInitializerError(e);
            }
            System.err.println("[CertificateGenerator] CA ready in " + (System.currentTimeMillis() - t0) + " ms");
        }
    }

    public static CertificateGenerator getInstance() {
        return Holder.INSTANCE;
    }

    public static X509Certificate getCaCertificate() {
        return getInstance().caCertificate;
    }

    // ====================== private constructor ======================

    private CertificateGenerator() throws Exception {
        System.err.println("[CertificateGenerator] Generating CA key pair (RSA-" + KEY_SIZE + ")...");
        long t0 = System.currentTimeMillis();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALG);
        kpg.initialize(new RSAKeyGenParameterSpec(KEY_SIZE, RSAKeyGenParameterSpec.F4), rng);
        caKeyPair = kpg.generateKeyPair();

        System.err.println("[CertificateGenerator] Key pair done in " + (System.currentTimeMillis() - t0) + " ms");

        caSubject = buildX500Name("Platypus MITM CA", "Platypus", "US");

        CertInfo info = new CertInfo();
        info.version = 3;
        info.serialNumber = generateSerialNumber();
        Date now = new Date();
        info.notBefore = now;
        info.notAfter = new Date(now.getTime() + TimeUnit.DAYS.toMillis(CA_VALIDITY_DAYS));
        info.subject = caSubject;
        info.issuer = caSubject; // self-signed -> issuer = subject
        info.publicKey = caKeyPair.getPublic();

        // BasicConstraints cA=TRUE
        info.extensions.put(BasicConstraints.ID, buildBasicConstraintsExtension(true, -1));

        // KeyUsage: keyCertSign + cRLSign
        info.extensions.put(KeyUsage.ID, buildKeyUsageExtension(KU_KEY_CERT_SIGN | KU_CRL_SIGN));

        // SubjectKeyIdentifier
        info.extensions.put(SubjectKeyIdentifier.ID, buildSkiExtension(caKeyPair.getPublic()));

        // AuthorityKeyIdentifier on a self-signed root is optional, but when
        // present it must match the SKI.
        byte[] caKeyId = getAuthorityKeyIdentifier(caKeyPair.getPublic());
        info.extensions.put(AuthorityKeyIdentifier.ID, buildAkiExtension(caKeyId));

        System.err.println("[CertificateGenerator] Signing CA certificate with " + SIG_ALG_JCA);
        caCertificate = buildCertificate(info, caKeyPair.getPrivate(), SIG_ALG_JCA, SIG_ALG_OID, null);
        System.err.println("[CertificateGenerator] CA certificate complete.");

        exportCaCertificate();
    }

    /**
     * Writes the current CA certificate in PEM format to {@code certs/rootCA.crt}.
     */
    private void exportCaCertificate() {
        try {
            Files.createDirectories(CERTS_DIR);
            Path certFile = CERTS_DIR.resolve(ROOT_CA_FILENAME);
            byte[] pemBytes = toPemBytes(caCertificate);
            Files.write(certFile, pemBytes);
            System.err.println("[CertificateGenerator] Root CA exported to " + certFile.toAbsolutePath());
        } catch (Exception e) {
            System.err.println("[CertificateGenerator] Failed to export root CA: " + e.getMessage());
        }
    }

    // ====================== public API ======================

    /**
     * Generates a leaf certificate for {@code hostname} signed by this
     * instance's built-in CA.
     */
    public KeyStore.PrivateKeyEntry generateHostEntry(String hostname) throws Exception {
        /// System.err.println("[CertificateGenerator] Generating cert for " + hostname);

        KeyPair hostKP = generateKeyPair();

        CertInfo info = new CertInfo();
        info.version = 3;
        info.serialNumber = generateSerialNumber();
        Date now = new Date();
        info.notBefore = now;
        info.notAfter = new Date(now.getTime() + TimeUnit.DAYS.toMillis(HOST_CERT_VALIDITY_DAYS));
        info.subject = buildX500Name(hostname, "Platypus Proxy", "US");
        info.issuerDer = caCertificate.getSubjectX500Principal().getEncoded();
        info.publicKey = hostKP.getPublic();

        byte[] authorityKeyId = getAuthorityKeyIdentifier(caKeyPair.getPublic());
        addLeafExtensions(info, hostname, authorityKeyId);

        X509Certificate cert = buildCertificate(info, caKeyPair.getPrivate(), SIG_ALG_JCA, SIG_ALG_OID, info.issuerDer);
        return privateKeyEntry(hostKP, cert, caCertificate);
    }

    /**
     * Generates a leaf certificate for {@code hostname} signed by the
     * supplied external CA certificate and key.
     * <p>
     * Supports both RSA and EC CA keys.  The leaf certificate will include
     * an Authority Key Identifier that matches the CA's Subject Key Identifier.
     */
    public static KeyStore.PrivateKeyEntry generateHostEntry(String hostname, X509Certificate caCert, PrivateKey caKey)
            throws Exception {

        SecureRandom rng = createSecureRandom();
        KeyPair hostKP = generateKeyPair(rng);

        String sigAlgJca, sigAlgOid;
        if ("EC".equals(caKey.getAlgorithm())) {
            sigAlgJca = EC_SIG_ALG_JCA;
            sigAlgOid = EC_SIG_ALG_OID;
        } else {
            sigAlgJca = SIG_ALG_JCA;
            sigAlgOid = SIG_ALG_OID;
        }

        byte[] issuerDer = caCert.getSubjectX500Principal().getEncoded();

        CertInfo info = new CertInfo();
        info.version = 3;
        info.serialNumber = generateSerialNumber(rng);
        Date now = new Date();
        info.notBefore = now;
        info.notAfter = new Date(now.getTime() + TimeUnit.DAYS.toMillis(HOST_CERT_VALIDITY_DAYS));
        info.subject = buildX500Name(hostname, "Platypus Proxy", "US");
        info.issuerDer = issuerDer;
        info.publicKey = hostKP.getPublic();

        byte[] authorityKeyId = getAuthorityKeyIdentifier(caCert);
        addLeafExtensions(info, hostname, authorityKeyId);

        X509Certificate cert = buildCertificate(info, caKey, sigAlgJca, sigAlgOid, issuerDer);
        return privateKeyEntry(hostKP, cert, caCert);
    }

    // ====================== Certificate building / signing ======================

    private static X509Certificate buildCertificate(
            CertInfo info, PrivateKey signerKey, String sigAlgJca, String sigAlgOid, byte[] issuerDer)
            throws Exception {

        boolean rsa = SIG_ALG_OID.equals(sigAlgOid);
        byte[] algIdBytes = encodeAlgorithmIdentifier(sigAlgOid, rsa);

        Signature sig = Signature.getInstance(sigAlgJca);
        sig.initSign(signerKey);

        ByteArrayOutputStream content = new ByteArrayOutputStream(512);

        // version [0] EXPLICIT INTEGER
        if (info.version != 1) {
            byte[] verBytes = derEncode(DER.INTEGER, BigInteger.valueOf(info.version - 1));
            content.write(0xA0);
            writeDerLength(content, verBytes.length);
            content.write(verBytes);
        }

        // serialNumber INTEGER -- must be a positive integer (RFC 5280 §4.1.2.2)
        writePositiveInteger(content, info.serialNumber);

        // signature AlgorithmIdentifier
        content.write(algIdBytes);

        // issuer Name
        if (issuerDer != null) {
            content.write(issuerDer);
        } else {
            content.write(info.issuer.getDer());
        }

        // validity
        List<DERValue> validity = Arrays.asList(encodeTime(info.notBefore), encodeTime(info.notAfter));
        DERWriter.write(content, new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, validity));

        // subject
        content.write(info.subject.getDer());

        // subjectPublicKeyInfo
        content.write(encodePublicKey(info.publicKey));

        // extensions [3] EXPLICIT SEQUENCE OF Extension
        if (!info.extensions.isEmpty()) {
            writeExtensions(content, info.extensions);
        }

        byte[] tbsContent = content.toByteArray();
        byte[] tbsCertBytes = wrapSequence(tbsContent);

        sig.update(tbsCertBytes);
        byte[] signatureBytes = sig.sign();

        ByteArrayOutputStream certBody = new ByteArrayOutputStream(tbsCertBytes.length + 256);
        certBody.write(tbsCertBytes);
        certBody.write(algIdBytes);

        byte[] bitStringContent = new byte[signatureBytes.length + 1];
        bitStringContent[0] = 0; // zero unused bits
        System.arraycopy(signatureBytes, 0, bitStringContent, 1, signatureBytes.length);
        certBody.write(DER.BIT_STRING);
        writeDerLength(certBody, bitStringContent.length);
        certBody.write(bitStringContent);

        byte[] encoded = wrapSequence(certBody.toByteArray());

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoded));
    }

    // ====================== X.500 name helpers ======================

    /**
     * Builds an {@link X500Name} with the correct ASN.1 encoding for each
     * Relative Distinguished Name.
     * <p>
     * The country attribute is encoded as a {@code PrintableString}
     * (tag&nbsp;0x13) with OID&nbsp;{@code 2.5.4.6}; CN/O use UTF8String.
     */
    private static X500Name buildX500Name(String cn, String org, String country) throws IOException {
        List<DERValue> rdns = new ArrayList<>(3);
        rdns.add(makeRDN(OID_COMMON_NAME, cn, DER.UTF8_STRING));
        rdns.add(makeRDN(OID_ORGANIZATION, org, DER.UTF8_STRING));
        rdns.add(makeRDN(OID_COUNTRY, country, PRINTABLE_STRING_TAG));
        return new X500Name(new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, rdns).getEncoded());
    }

    /**
     * Constructs a single RDN (Relative Distinguished Name) as a SET containing
     * a SEQUENCE of { OID, value }.
     */
    private static DERValue makeRDN(OID oid, String value, int stringTag) {
        List<DERValue> tv = new ArrayList<>(2);
        tv.add(new DERValue(DER.OBJECT_IDENTIFIER, oid));
        tv.add(new DERValue(stringTag, value));
        return new DERValue(
                DER.CONSTRUCTED | DER.SET, Collections.singletonList(new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, tv)));
    }

    // ====================== Extension builders ======================

    private static void addLeafExtensions(CertInfo info, String hostname, byte[] authorityKeyId) throws IOException {
        // SubjectAlternativeNames -- dNSName
        info.extensions.put(SubjectAlternativeNames.ID, buildSanExtension(hostname));

        // ExtendedKeyUsage -- id-kp-serverAuth
        info.extensions.put(ExtendedKeyUsage.ID, buildEkuExtension());

        // KeyUsage -- digitalSignature + keyEncipherment
        info.extensions.put(KeyUsage.ID, buildKeyUsageExtension(KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT));

        // SubjectKeyIdentifier
        try {
            info.extensions.put(SubjectKeyIdentifier.ID, buildSkiExtension(info.publicKey));
        } catch (Exception e) {
            e.printStackTrace();
        }

        // AuthorityKeyIdentifier -- matches the CA's SubjectKeyIdentifier
        info.extensions.put(AuthorityKeyIdentifier.ID, buildAkiExtension(authorityKeyId));
    }

    private static ExtensionEntry buildBasicConstraintsExtension(boolean ca, int pathLen) throws IOException {
        List<DERValue> seq = new ArrayList<>(2);
        // cA BOOLEAN -- only encode when TRUE (FALSE is the DEFAULT in
        // BasicConstraints, so DER forbids encoding it)
        if (ca) {
            seq.add(new DERValue(DER.BOOLEAN, Boolean.TRUE));
        }
        if (pathLen >= 0) {
            seq.add(new DERValue(DER.INTEGER, BigInteger.valueOf(pathLen)));
        }
        byte[] value = new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, seq).getEncoded();
        return new ExtensionEntry(BasicConstraints.ID, true, value);
    }

    private static ExtensionEntry buildKeyUsageExtension(int usageByte) throws IOException {
        int unusedBits = Integer.numberOfTrailingZeros(usageByte);
        byte[] kuValue = derEncodeBitString(usageByte, unusedBits);
        return new ExtensionEntry(KeyUsage.ID, true, kuValue);
    }

    private static ExtensionEntry buildEkuExtension() throws IOException {
        List<DERValue> oidList = Collections.singletonList(new DERValue(DER.OBJECT_IDENTIFIER, OID_SERVER_AUTH));
        byte[] value = new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, oidList).getEncoded();
        return new ExtensionEntry(ExtendedKeyUsage.ID, false, value);
    }

    private static ExtensionEntry buildSkiExtension(PublicKey publicKey) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-1").digest(publicKey.getEncoded());
        ByteArrayOutputStream baos = new ByteArrayOutputStream(digest.length + 6);
        baos.write(DER.OCTET_STRING);
        writeDerLength(baos, digest.length);
        baos.write(digest);
        return new ExtensionEntry(SubjectKeyIdentifier.ID, false, baos.toByteArray());
    }

    /**
     * Builds an Authority Key Identifier extension containing the key identifier
     * of the CA, encoded as a SEQUENCE { [0] IMPLICIT OCTET STRING }.
     */
    private static ExtensionEntry buildAkiExtension(byte[] authorityKeyId) {
        try {
            // [0] IMPLICIT KeyIdentifier (OCTET STRING)
            ByteArrayOutputStream keyIdElement = new ByteArrayOutputStream();
            keyIdElement.write(0x80); // context-specific tag 0, primitive
            writeDerLength(keyIdElement, authorityKeyId.length);
            keyIdElement.write(authorityKeyId);

            // Wrap in SEQUENCE
            byte[] keyIdBytes = keyIdElement.toByteArray();
            ByteArrayOutputStream seq = new ByteArrayOutputStream();
            seq.write(DER.CONSTRUCTED | DER.SEQUENCE);
            writeDerLength(seq, keyIdBytes.length);
            seq.write(keyIdBytes);

            return new ExtensionEntry(AuthorityKeyIdentifier.ID, false, seq.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException("Failed to build AKI", e);
        }
    }

    private static ExtensionEntry buildSanExtension(String hostname) throws IOException {
        DERValue dnsValue = new DERValue(DER.CONTEXT | 2, hostname.getBytes(StandardCharsets.US_ASCII));
        DERValue seq = new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, Collections.singletonList(dnsValue));
        return new ExtensionEntry(SubjectAlternativeNames.ID, false, seq.getEncoded());
    }

    // ====================== Extension serialization ======================

    /**
     * Writes the extensions as a DER-encoded {@code [3] EXPLICIT SEQUENCE OF
     * Extension}.  Each extension is encoded by
     * {@link ExtensionEntry#writeTo}, which omits the {@code critical} field
     * when it equals the DEFAULT value of FALSE.
     */
    private static void writeExtensions(OutputStream out, Map<OID, ExtensionEntry> extensions) throws IOException {
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream(256);
        for (ExtensionEntry ext : extensions.values()) {
            ext.writeTo(extBuf);
        }
        byte[] extBytes = extBuf.toByteArray();
        byte[] seqBytes = wrapSequence(extBytes);
        out.write(DER.CONSTRUCTED | DER.CONTEXT | 3);
        writeDerLength(out, seqBytes.length);
        out.write(seqBytes);
    }

    // ====================== DER utility methods ======================

    /**
     * Encodes an AlgorithmIdentifier.  For RSA this includes a NULL parameters
     * field, which is required by RFC 8017 / RFC 5280; for ECDSA the parameters
     * are absent.
     */
    private static byte[] encodeAlgorithmIdentifier(String sigAlgOid, boolean withNullParams) throws IOException {
        byte[] oidBytes = new DERValue(DER.OBJECT_IDENTIFIER, new OID(sigAlgOid)).getEncoded();
        ByteArrayOutputStream baos = new ByteArrayOutputStream(oidBytes.length + 4);
        baos.write(DER.CONSTRUCTED | DER.SEQUENCE);
        int len = oidBytes.length + (withNullParams ? 2 : 0);
        writeDerLength(baos, len);
        baos.write(oidBytes);
        if (withNullParams) {
            baos.write(DER.NULL);
            baos.write(0);
        }
        return baos.toByteArray();
    }

    /**
     * Writes a positive ASN.1 INTEGER.  BigInteger.toByteArray() already adds a
     * leading 0x00 byte when the most-significant bit would otherwise be 1,
     * guaranteeing a non-negative DER encoding.
     */
    private static void writePositiveInteger(OutputStream out, BigInteger value) throws IOException {
        if (value.signum() <= 0) {
            throw new IllegalArgumentException("Certificate serial number must be positive");
        }
        byte[] bytes = value.toByteArray();
        out.write(DER.INTEGER);
        writeDerLength(out, bytes.length);
        out.write(bytes);
    }

    private static void writeDerLength(OutputStream out, int len) throws IOException {
        if (len < 128) {
            out.write(len);
        } else if (len < 256) {
            out.write(0x81);
            out.write(len);
        } else if (len < 65536) {
            out.write(0x82);
            out.write(len >> 8);
            out.write(len);
        } else if (len < 16777216) {
            out.write(0x83);
            out.write(len >> 16);
            out.write(len >> 8);
            out.write(len);
        } else {
            out.write(0x84);
            out.write(len >> 24);
            out.write(len >> 16);
            out.write(len >> 8);
            out.write(len);
        }
    }

    private static DERValue encodeTime(Date date) {
        Instant instant = date.toInstant();
        ZonedDateTime utcDateTime = instant.atZone(ZoneOffset.UTC);
        int year = utcDateTime.getYear();

        if (year >= 1950 && year < 2050) {
            DateTimeFormatter utcFormatter = DateTimeFormatter.ofPattern("yyMMddHHmmss");
            return new DERValue(DER.UTC_TIME, utcDateTime.format(utcFormatter) + "Z");
        } else {
            DateTimeFormatter generalFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");
            return new DERValue(DER.GENERALIZED_TIME, utcDateTime.format(generalFormatter) + "Z");
        }
    }

    private static byte[] wrapSequence(byte[] inner) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(inner.length + 4);
        buf.write(DER.CONSTRUCTED | DER.SEQUENCE);
        writeDerLength(buf, inner.length);
        buf.write(inner);
        return buf.toByteArray();
    }

    private static byte[] derEncode(int tag, Object value) throws IOException {
        return new DERValue(tag, value).getEncoded();
    }

    private static byte[] derEncodeBitString(int payloadByte, int unusedBits) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(8);
        baos.write(DER.BIT_STRING);
        writeDerLength(baos, 2);
        baos.write(unusedBits);
        baos.write(payloadByte);
        return baos.toByteArray();
    }

    private static byte[] encodePublicKey(PublicKey publicKey) throws GeneralSecurityException, IOException {
        byte[] encoded = publicKey.getEncoded();
        if (encoded != null && "X.509".equals(publicKey.getFormat())) {
            return encoded;
        }
        KeyFactory kf = KeyFactory.getInstance(publicKey.getAlgorithm());
        return kf.getKeySpec(publicKey, X509EncodedKeySpec.class).getEncoded();
    }

    // ====================== Key generation / SecureRandom ======================

    private KeyPair generateKeyPair() throws GeneralSecurityException {
        return generateKeyPair(this.rng);
    }

    private static KeyPair generateKeyPair(SecureRandom rng) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALG);
        kpg.initialize(new RSAKeyGenParameterSpec(KEY_SIZE, RSAKeyGenParameterSpec.F4), rng);
        return kpg.generateKeyPair();
    }

    private BigInteger generateSerialNumber() {
        return generateSerialNumber(this.rng);
    }

    private static BigInteger generateSerialNumber(SecureRandom rng) {
        byte[] bytes = new byte[16];
        rng.nextBytes(bytes);
        return new BigInteger(1, bytes);
    }

    private static KeyStore.PrivateKeyEntry privateKeyEntry(KeyPair kp, X509Certificate leaf, X509Certificate ca) {
        return new KeyStore.PrivateKeyEntry(kp.getPrivate(), new java.security.cert.Certificate[] {leaf, ca});
    }

    static SecureRandom createSecureRandom() {
        System.setProperty("java.security.egd", "file:/dev/urandom");
        for (String algo : new String[] {"NativePRNGNonBlocking", "Windows-PRNG", "DRBG"}) {
            try {
                SecureRandom sr = SecureRandom.getInstance(algo);
                sr.nextBytes(new byte[1]);
                System.err.println("[CertificateGenerator] Using SecureRandom: " + sr.getAlgorithm());
                return sr;
            } catch (NoSuchAlgorithmException ignored) {
            }
        }
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            sr.setSeed(System.nanoTime());
            sr.nextBytes(new byte[1]);
            System.err.println("[CertificateGenerator] Using fallback SHA1PRNG");
            return sr;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("No suitable SecureRandom implementation found", e);
        }
    }

    // ====================== Authority Key Identifier helpers ======================

    private static byte[] getAuthorityKeyIdentifier(PublicKey caPublicKey) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(caPublicKey.getEncoded());
    }

    /**
     * Returns the CA's Subject Key Identifier bytes if the extension is present,
     * otherwise falls back to a SHA-1 hash of the CA's public key.
     */
    private static byte[] getAuthorityKeyIdentifier(X509Certificate caCert) throws Exception {
        byte[] ext = caCert.getExtensionValue("2.5.29.14"); // SubjectKeyIdentifier OID
        if (ext != null) {
            byte[] inner = parseOctetStringContents(ext);
            if (inner != null) {
                byte[] keyId = parseOctetStringContents(inner);
                if (keyId != null && keyId.length > 0) {
                    return keyId;
                }
            }
        }
        return MessageDigest.getInstance("SHA-1").digest(caCert.getPublicKey().getEncoded());
    }

    private static byte[] parseOctetStringContents(byte[] encoded) {
        if (encoded == null || encoded.length < 2) {
            return null;
        }
        int[] pos = {0};
        int tag = encoded[pos[0]++] & 0xFF;
        if (tag != DER.OCTET_STRING) {
            return null;
        }
        int len = readDerLength(encoded, pos);
        if (len < 0 || pos[0] + len > encoded.length) {
            return null;
        }
        return Arrays.copyOfRange(encoded, pos[0], pos[0] + len);
    }

    private static int readDerLength(byte[] data, int[] pos) {
        int b = data[pos[0]++] & 0xFF;
        if ((b & 0x80) == 0) {
            return b;
        }
        int numBytes = b & 0x7F;
        if (numBytes == 0 || numBytes > 4 || pos[0] + numBytes > data.length) {
            return -1;
        }
        int len = 0;
        for (int i = 0; i < numBytes; i++) {
            len = (len << 8) | (data[pos[0]++] & 0xFF);
        }
        return len;
    }

    // ====================== Helper: PEM export ======================

    private static byte[] toPemBytes(X509Certificate cert) throws Exception {
        String encoded = Base64.getEncoder().encodeToString(cert.getEncoded());
        StringBuilder pem = new StringBuilder()
                .append("-----BEGIN CERTIFICATE-----\n")
                .append(encoded.replaceAll("(.{64})", "$1\n"))
                .append("\n-----END CERTIFICATE-----\n");
        return pem.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ====================== Self-test ======================

    public static void main(String[] args) throws Exception {
        System.out.println("Let's taste test!");

        X509Certificate ca = getCaCertificate();
        System.out.println("CA Subject:    " + ca.getSubjectX500Principal());
        System.out.println("CA Valid until: " + ca.getNotAfter());
        System.out.println("CA certificate automatically saved to certs/rootCA.crt");

        String hostname = "example.com";
        KeyStore.PrivateKeyEntry entry = getInstance().generateHostEntry(hostname);
        X509Certificate leaf = (X509Certificate) entry.getCertificateChain()[0];
        System.out.println("Leaf Subject:  " + leaf.getSubjectX500Principal());

        Path leafFilePath = CERTS_DIR.resolve(hostname + ".crt");
        Files.write(leafFilePath, toPemBytes(leaf));
        System.out.println("Leaf certificate written to " + leafFilePath);

        try {
            leaf.verify(ca.getPublicKey());
            System.out.println("Java verification PASSED: leaf signature matches CA public key.");
        } catch (Exception e) {
            System.out.println("Java verification FAILED: " + e.getMessage());
        }

        System.out.println("To verify externally, run:");
        System.out.println("  openssl verify -CAfile certs/rootCA.crt certs/example.com.crt");
        System.out.println("  openssl x509 -in certs/example.com.crt -text -noout");
    }
}
