package com.platypus.proxy.provider.warp;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class WarpConfig {

    @SerializedName("private_key")
    public String privateKeyBase64;
    @SerializedName("public_key")
    public String publicKeyBase64;
    @SerializedName("endpoint_v4")
    public String endpointV4;
    @SerializedName("endpoint_v6")
    public String endpointV6;
    @SerializedName("endpoint_h2_v4")
    public String endpointH2V4 = "162.159.198.2";
    @SerializedName("endpoint_pub_key")
    public String endpointPubKeyPem;
    @SerializedName("license")
    public String license;
    @SerializedName("id")
    public String deviceId;
    @SerializedName("access_token")
    public String accessToken;
    @SerializedName("ipv4")
    public String ipv4;
    @SerializedName("ipv6")
    public String ipv6;
    @SerializedName("socks5_proxy")
    public String socks5Proxy;
    @SerializedName("model")
    public String model = "PC";

    private transient ECPrivateKey cachedPrivateKey;
    private transient java.security.interfaces.ECPublicKey cachedPublicKey;

    // DIVERGENCE: usque config.go:86-98 uses x509.ParseECPrivateKey (SEC 1 format).
    //             Java tries PKCS#8 first (Java's native format from
    //             KeyPair.getPrivate().getEncoded()), then falls back to SEC 1
    //             parsing for usque-exported config compatibility.
    public ECPrivateKey getPrivateKey() {
        if (cachedPrivateKey != null) return cachedPrivateKey;
        if (privateKeyBase64 == null || privateKeyBase64.isEmpty()) return null;
        try {
            byte[] der = Base64.getDecoder().decode(privateKeyBase64);
            KeyFactory kf = KeyFactory.getInstance("EC");
            try {
                cachedPrivateKey = (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(der));
                return cachedPrivateKey;
            } catch (Exception e) {
                // Not PKCS#8 — try SEC 1 (usque's x509.MarshalECPrivateKey)
            }
            cachedPrivateKey = parseSec1EcPrivateKey(der);
            return cachedPrivateKey;
        } catch (Exception e) {
            throw new RuntimeException("Failed to decode private key", e);
        }
    }

    // DIVERGENCE: usque derives the public key from the private key at runtime
    //             via privKey.PublicKey (Go struct field). Java derives via
    //             scalar multiplication (Q = s * G) when no explicit public_key
    //             field exists in config (usque compatibility).
    public java.security.interfaces.ECPublicKey getPublicKey() {
        if (cachedPublicKey != null) return cachedPublicKey;
        if (publicKeyBase64 != null && !publicKeyBase64.isEmpty()) {
            try {
                byte[] der = Base64.getDecoder().decode(publicKeyBase64);
                KeyFactory kf = KeyFactory.getInstance("EC");
                cachedPublicKey = (java.security.interfaces.ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(der));
                return cachedPublicKey;
            } catch (Exception e) {
                throw new RuntimeException("Failed to decode public key", e);
            }
        }
        ECPrivateKey priv = getPrivateKey();
        if (priv == null) return null;
        try {
            cachedPublicKey = derivePublicKey(priv);
            return cachedPublicKey;
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive public key from private key", e);
        }
    }

    public String getEndpoint() {
        if (endpointV4 != null && !endpointV4.isEmpty()) return endpointV4;
        if (endpointV6 != null && !endpointV6.isEmpty()) return endpointV6;
        return null;
    }

    public int getEndpointPort() {
        return 443;
    }

    public boolean hasSocks5Proxy() {
        return socks5Proxy != null && !socks5Proxy.isEmpty();
    }

    public String getSocks5Host() {
        if (socks5Proxy == null || socks5Proxy.isEmpty()) return null;
        int lastColon = socks5Proxy.lastIndexOf(':');
        if (lastColon <= 0) return socks5Proxy;
        return socks5Proxy.substring(0, lastColon);
    }

    public int getSocks5Port() {
        if (socks5Proxy == null || socks5Proxy.isEmpty()) return 1080;
        int lastColon = socks5Proxy.lastIndexOf(':');
        if (lastColon <= 0) return 1080;
        try {
            return Integer.parseInt(socks5Proxy.substring(lastColon + 1));
        } catch (NumberFormatException e) {
            return 1080;
        }
    }

    public static WarpConfig load(Path path) throws IOException {
        String json = Files.readString(path);
        return new Gson().fromJson(json, WarpConfig.class);
    }

    public void save(Path path) throws IOException {
        String json = new Gson().toJson(this);
        Files.writeString(path, json);
    }

    public static WarpConfig loadOrDefault(Path path) {
        try {
            return load(path);
        } catch (NoSuchFileException e) {
            return null;
        } catch (IOException e) {
            throw new RuntimeException("Failed to load WARP config from " + path, e);
        }
    }

    private static ECPrivateKey parseSec1EcPrivateKey(byte[] der) throws Exception {
        int[] pos = {0};
        if ((der[pos[0]++] & 0xFF) != 0x30) {
            throw new IllegalArgumentException("Not a SEC 1 EC private key (expected SEQUENCE)");
        }
        int seqLen = readDerLength(der, pos);
        int seqEnd = pos[0] + seqLen;
        if (seqEnd > der.length) throw new IllegalArgumentException("Truncated SEC 1 key");

        if ((der[pos[0]++] & 0xFF) != 0x02) throw new IllegalArgumentException("Expected version INTEGER");
        int verLen = readDerLength(der, pos);
        pos[0] += verLen;

        if ((der[pos[0]++] & 0xFF) != 0x04) throw new IllegalArgumentException("Expected privateKey OCTET STRING");
        int keyLen = readDerLength(der, pos);
        byte[] keyBytes = new byte[keyLen];
        System.arraycopy(der, pos[0], keyBytes, 0, keyLen);
        pos[0] += keyLen;

        BigInteger s = new BigInteger(1, keyBytes);

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecParams = params.getParameterSpec(ECParameterSpec.class);

        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, ecParams);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return (ECPrivateKey) kf.generatePrivate(keySpec);
    }

    private static java.security.interfaces.ECPublicKey derivePublicKey(ECPrivateKey privKey) throws Exception {
        ECParameterSpec params = privKey.getParams();
        BigInteger s = privKey.getS();
        ECPoint G = params.getGenerator();
        java.security.spec.EllipticCurve curve = params.getCurve();
        ECFieldFp field = (ECFieldFp) curve.getField();
        BigInteger p = field.getP();
        BigInteger a = curve.getA();

        ECPoint Q = pointMultiply(G, s, a, p);

        KeyFactory kf = KeyFactory.getInstance("EC");
        return (java.security.interfaces.ECPublicKey) kf.generatePublic(
                new java.security.spec.ECPublicKeySpec(Q, params));
    }

    private static ECPoint pointMultiply(ECPoint P, BigInteger k, BigInteger a, BigInteger p) {
        if (k.signum() == 0) return ECPoint.POINT_INFINITY;
        String bits = k.toString(2);
        ECPoint R = ECPoint.POINT_INFINITY;
        for (int i = 0; i < bits.length(); i++) {
            if (R != ECPoint.POINT_INFINITY) {
                R = pointDouble(R, a, p);
            }
            if (bits.charAt(i) == '1') {
                if (R == ECPoint.POINT_INFINITY) {
                    R = P;
                } else {
                    R = pointAdd(R, P, a, p);
                }
            }
        }
        return R;
    }

    private static ECPoint pointDouble(ECPoint P, BigInteger a, BigInteger p) {
        BigInteger x = P.getAffineX();
        BigInteger y = P.getAffineY();
        BigInteger lamNum = modMul(BigInteger.valueOf(3), modMul(x, x, p), p).add(a).mod(p);
        BigInteger lamDen = modMul(BigInteger.valueOf(2), y, p);
        BigInteger lam = modMul(lamNum, modInv(lamDen, p), p);
        BigInteger x3 = modMul(lam, lam, p).subtract(modMul(BigInteger.valueOf(2), x, p)).mod(p);
        if (x3.signum() < 0) x3 = x3.add(p);
        BigInteger y3 = modMul(lam, x.subtract(x3).mod(p), p).subtract(y).mod(p);
        if (y3.signum() < 0) y3 = y3.add(p);
        return new ECPoint(x3, y3);
    }

    private static ECPoint pointAdd(ECPoint P, ECPoint Q, BigInteger a, BigInteger p) {
        if (P == ECPoint.POINT_INFINITY) return Q;
        if (Q == ECPoint.POINT_INFINITY) return P;
        if (P.getAffineX().equals(Q.getAffineX()) && P.getAffineY().equals(Q.getAffineY())) {
            return pointDouble(P, a, p);
        }
        BigInteger x1 = P.getAffineX();
        BigInteger y1 = P.getAffineY();
        BigInteger x2 = Q.getAffineX();
        BigInteger y2 = Q.getAffineY();
        BigInteger lamNum = y2.subtract(y1).mod(p);
        if (lamNum.signum() < 0) lamNum = lamNum.add(p);
        BigInteger lamDen = x2.subtract(x1).mod(p);
        if (lamDen.signum() < 0) lamDen = lamDen.add(p);
        BigInteger lam = modMul(lamNum, modInv(lamDen, p), p);
        BigInteger x3 = modMul(lam, lam, p).subtract(x1).subtract(x2).mod(p);
        if (x3.signum() < 0) x3 = x3.add(p);
        BigInteger y3 = modMul(lam, x1.subtract(x3).mod(p), p).subtract(y1).mod(p);
        if (y3.signum() < 0) y3 = y3.add(p);
        return new ECPoint(x3, y3);
    }

    private static BigInteger modMul(BigInteger a, BigInteger b, BigInteger p) {
        return a.multiply(b).mod(p);
    }

    private static BigInteger modInv(BigInteger a, BigInteger p) {
        return a.modInverse(p);
    }

    private static int readDerLength(byte[] data, int[] pos) {
        int b = data[pos[0]++] & 0xFF;
        if ((b & 0x80) == 0) return b;
        int numBytes = b & 0x7F;
        int len = 0;
        for (int i = 0; i < numBytes; i++) {
            len = (len << 8) | (data[pos[0]++] & 0xFF);
        }
        return len;
    }
}
