package com.platypus.proxy.provider.warp;

import gnu.crypto.der.BitString;
import gnu.crypto.der.DER;
import gnu.crypto.der.DERValue;
import gnu.crypto.der.DERWriter;
import gnu.crypto.der.OID;
import gnu.crypto.pki.X500Name;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.Date;

public class WarpCertificateGenerator {

    // DIVERGENCE: usque internal/utils.go:106-117 uses Go stdlib x509.CreateCertificate
    //             (declarative, 12 lines). Java constructs DER manually via GNU Crypto
    //             (procedural, ~120 lines). Same result, different approach.
    // DIVERGENCE: usque cert validity = 24 hours; Java = 365 days.
    // DIVERGENCE: usque serial = big.NewInt(0) (fixed); Java = currentTimeMillis.
    // DIVERGENCE: usque cert has NO Subject (empty x509.Certificate template);
    //             Java sets CN="usque" via manual X500Name construction.
    // DIVERGENCE: usque cert has NO extensions. Java also has none — matches.
    // DIVERGENCE: usque uses x509.MarshalECPrivateKey (SEC 1 format) for key serialization;
    //             Java uses PKCS#8 via KeyPair.getPrivate().getEncoded().
    // DIVERGENCE: Usque relies on Go's x509.CreateCertificate to fill in defaults;
    //             Java must manually encode every TBS cert field (version, serial,
    //             algorithm id, subject, validity, subject again as issuer, SPKI).

    private static final String KEYPAIR_ALG = "EC";
    private static final String EC_CURVE = "secp256r1";
    private static final String SIG_ALG_JCA = "SHA256withECDSA";
    private static final String SIG_ALG_OID = "1.2.840.10045.4.3.2";
    private static final OID OID_COMMON_NAME = new OID("2.5.4.3");

    // DIVERGENCE: usque internal/utils.go has a full cert generator (returns [][]byte).
    //             Java has an additional entry point (generateKeyPair) and self-test main();
    //             usque does NOT have these in the cert generator.
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEYPAIR_ALG);
        kpg.initialize(new ECGenParameterSpec(EC_CURVE));
        return kpg.generateKeyPair();
    }

    // DIVERGENCE: usque uses x509.CreateCertificate() with empty template.
    //             quiche/boringssl requires non-empty issuer/subject DN.
    //             Java uses CN=usque to satisfy OpenSSL/BoringSSL parser.
    public static byte[] generateSelfSignedDer(ECPrivateKey privateKey, ECPublicKey publicKey) throws Exception {
        X500Name name = buildX500Name("usque");
        byte[] nameDer = name.getDer();
        BigInteger serial = BigInteger.ZERO;
        Instant now = Instant.now();
        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plusSeconds(86400L));

        byte[] ecKeyAlgId = encodeEcAlgorithmId();
        byte[] sigAlgIdBytes = encodeSigAlgorithmId();
        byte[] pubKeyEncoded = publicKey.getEncoded();

        ByteArrayOutputStream tbs = new ByteArrayOutputStream(512);

        tbs.write(0xA0);
        tbs.write(0x03);
        tbs.write(0x02);
        tbs.write(0x01);
        tbs.write(0x02);

        tbs.write(DER.INTEGER);
        writeDerLength(tbs, 1);
        tbs.write(0);

        tbs.write(ecKeyAlgId);
        tbs.write(nameDer);

        ByteArrayOutputStream validity = new ByteArrayOutputStream();
        validity.write(encodeTime(notBefore));
        validity.write(encodeTime(notAfter));
        byte[] validityBytes = wrapDer(DER.CONSTRUCTED | DER.SEQUENCE, validity.toByteArray());
        tbs.write(validityBytes);

        tbs.write(nameDer);
        tbs.write(pubKeyEncoded);

        byte[] tbsContent = tbs.toByteArray();
        byte[] tbsCertBytes = wrapDer(DER.CONSTRUCTED | DER.SEQUENCE, tbsContent);

        Signature sig = Signature.getInstance(SIG_ALG_JCA);
        sig.initSign(privateKey);
        sig.update(tbsCertBytes);
        byte[] sigBytes = sig.sign();

        ByteArrayOutputStream full = new ByteArrayOutputStream(tbsCertBytes.length + 256);
        full.write(tbsCertBytes);
        full.write(sigAlgIdBytes);

        ByteArrayOutputStream bitContent = new ByteArrayOutputStream(sigBytes.length + 1);
        bitContent.write(0);
        bitContent.write(sigBytes);
        byte[] bitContentBytes = bitContent.toByteArray();
        full.write(DER.BIT_STRING);
        writeDerLength(full, bitContentBytes.length);
        full.write(bitContentBytes);

        return wrapDer(DER.CONSTRUCTED | DER.SEQUENCE, full.toByteArray());
    }

    private static X500Name buildX500Name(String cn) throws IOException {
        DERValue cnAttr = new DERValue(DER.UTF8_STRING, cn);
        DERValue cnOid = new DERValue(DER.OBJECT_IDENTIFIER, new OID("2.5.4.3"));
        java.util.List<DERValue> attrList = new java.util.ArrayList<>(2);
        attrList.add(cnOid);
        attrList.add(cnAttr);
        DERValue rdnSeq = new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, attrList);
        DERValue rdnSet = new DERValue(DER.CONSTRUCTED | DER.SET, Collections.singletonList(rdnSeq));
        DERValue setName = new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, Collections.singletonList(rdnSet));
        return new X500Name(setName.getEncoded());
    }

    private static byte[] encodeEcAlgorithmId() throws IOException {
        byte[] oidBytes = new DERValue(DER.OBJECT_IDENTIFIER, new OID(SIG_ALG_OID)).getEncoded();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(DER.CONSTRUCTED | DER.SEQUENCE);
        writeDerLength(baos, oidBytes.length);
        baos.write(oidBytes);
        return baos.toByteArray();
    }

    private static byte[] encodeSigAlgorithmId() throws IOException {
        byte[] oidBytes = new DERValue(DER.OBJECT_IDENTIFIER, new OID(SIG_ALG_OID)).getEncoded();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(DER.CONSTRUCTED | DER.SEQUENCE);
        writeDerLength(baos, oidBytes.length);
        baos.write(oidBytes);
        return baos.toByteArray();
    }

    // DIVERGENCE: usque builder has no outbound proxy support during enrollment.
    //             Java adds HttpClient.Builder.proxy() for the enrollment phase.
    // DIVERGENCE: usque uses x509.CreateCertificate which handles time encoding
    //             automatically (UTCTime for 1950-2049, GeneralizedTime otherwise).
    //             Java always uses UTCTime; will fail for dates beyond 2049.
    private static byte[] encodeTime(Date date) throws IOException {
        Instant instant = date.toInstant();
        ZonedDateTime utcDateTime = instant.atZone(ZoneOffset.UTC);
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyMMddHHmmss");
        String timeStr = utcDateTime.format(fmt) + "Z";
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(DER.UTC_TIME);
        writeDerLength(baos, timeStr.length());
        baos.write(timeStr.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return baos.toByteArray();
    }

    private static byte[] wrapDer(int tag, byte[] inner) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(inner.length + 4);
        baos.write(tag);
        writeDerLength(baos, inner.length);
        baos.write(inner);
        return baos.toByteArray();
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
        } else {
            out.write(0x83);
            out.write(len >> 16);
            out.write(len >> 8);
            out.write(len);
        }
    }
}
