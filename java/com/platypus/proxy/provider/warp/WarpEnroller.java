package com.platypus.proxy.provider.warp;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.platypus.proxy.logging.CondLogger;
import java.io.*;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Random;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class WarpEnroller {

    // DIVERGENCE: usque has one extra header "Connection: Keep-Alive" (internal/consts.go:24).
    //             Java omits it — Cloudflare does not seem to care.
    // DIVERGENCE: usque also sends "Content-Type: application/json; charset=UTF-8"
    //             (with charset). Java sends "application/json" (no charset).
    private static final String API_BASE = "https://api.cloudflareclient.com/v0a4471/reg";
    private static final String USER_AGENT = "WARP for Android";
    private static final String CLIENT_VERSION = "a-6.35-4471";

    // DIVERGENCE: usque has OsVersion field (internal/consts → models/register.go).
    //             Java omits it (always empty anyway).
    public static class RegisterRequest {
        @SerializedName("key") String key;
        @SerializedName("install_id") String installId = "";
        @SerializedName("fcm_token") String fcmToken = "";
        @SerializedName("tos") String tos;
        @SerializedName("model") String model;
        @SerializedName("serial_number") String serialNumber;
        @SerializedName("key_type") String keyType = "curve25519";
        @SerializedName("tunnel_type") String tunnelType = "wireguard";
        @SerializedName("locale") String locale;
    }

    public static class EnrollRequest {
        @SerializedName("key") String key;
        @SerializedName("key_type") String keyType = "secp256r1";
        @SerializedName("tunnel_type") String tunnelType = "masque";
        @SerializedName("name") String name;
    }

    // DIVERGENCE: usque models/register.go also has policy, warp_enabled, waitlist,
    //             enabled, place, fcm_token, serial_number, install_id, tos fields
    //             in AccountData. Java only extracts id, token, license, config, policy.
    // DIVERGENCE: usque models/apierror.go has a full APIError struct with Errors
    //             list and ErrorInfo sub-struct. Java does not parse error responses.
    public static class AccountResponse {
        @SerializedName("id") String id;
        @SerializedName("token") String token;
        @SerializedName("account") Account account;
        @SerializedName("config") Config config;
        @SerializedName("policy") Policy policy;
    }

    public static class Account {
        @SerializedName("license") String license;
    }

    public static class Config {
        @SerializedName("peers") Peer[] peers;
        @SerializedName("interface") Interface iface;
        @SerializedName("services") Services services;
    }

    public static class Peer {
        @SerializedName("public_key") String publicKey;
        @SerializedName("endpoint") Endpoint endpoint;
    }

    // DIVERGENCE: usque models/register.go Peer.Endpoint has a `ports` field ([]int).
    //             Java assumes port 443 always.
    public static class Endpoint {
        @SerializedName("v4") String v4;
        @SerializedName("v6") String v6;
        @SerializedName("host") String host;
    }

    public static class Interface {
        @SerializedName("addresses") Addresses addresses;
    }

    public static class Addresses {
        @SerializedName("v4") String v4;
        @SerializedName("v6") String v6;
    }

    public static class Services {
        @SerializedName("http_proxy") String httpProxy;
    }

    public static class Policy {
        @SerializedName("tunnel_protocol") String tunnelProtocol;
    }

    // DIVERGENCE: usque api/cloudflare.go:89 uses http.DefaultClient over
    //             standard HTTPS (no InsecureSkipVerify for registration).
    //             Java bypasses all TLS verification with TRUST_ALL.
    private static final TrustManager TRUST_ALL = new X509TrustManager() {
        public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
        public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
    };

    // DIVERGENCE: usque api/cloudflare.go accepts `acceptTos bool` and prompts
    //             interactively. Java always provides a ToS timestamp without asking.
    // DIVERGENCE: usque api/cloudflare.go:85-87 supports CF-Access-Jwt-Assertion
    //             header for team accounts. Java's `jwt` parameter is passed as null.
    // DIVERGENCE: usque uses http.DefaultClient (no custom TLS). Java uses
    //             HttpClient with SSLContext allowing all certs (TRUST_ALL).
    public static WarpConfig enroll(CondLogger logger, String model, String locale, String name, String jwt, String outboundProxy) throws Exception {
        SSLContext sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(null, new TrustManager[] { TRUST_ALL }, new SecureRandom());

        HttpClient.Builder clientBuilder = HttpClient.newBuilder()
                .sslContext(sslCtx)
                .connectTimeout(java.time.Duration.ofSeconds(30));

        // DIVERGENCE: usque has no outbound proxy support during enrollment.
        //             Java adds HttpClient.Builder.proxy() for the enrollment phase.
        if (outboundProxy != null && !outboundProxy.isEmpty()) {
            URI proxyUri = URI.create(outboundProxy);
            // LEAK: InetSocketAddress(String,int) resolves the proxy hostname via
            //       system DNS. Called once during enrollment; result is not cached
            //       across enrollments.
            clientBuilder.proxy(java.net.ProxySelector.of(
                    new InetSocketAddress(proxyUri.getHost(), proxyUri.getPort())));
        }

        HttpClient client = clientBuilder.build();

        WireGuardKey wgKey = WireGuardKey.generate();
        String serial = randomHex(16);

        // DIVERGENCE: usque internal/utils.go:66-68 uses time.Format("2006-01-02T15:04:05.000-07:00")
        //             (with timezone offset). Java uses "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'" (UTC).
        //             Both are accepted by Cloudflare.
        String tos = Instant.now().atOffset(ZoneOffset.UTC)
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"));

        RegisterRequest regReq = new RegisterRequest();
        regReq.key = wgKey.publicKeyBase64();
        regReq.tos = tos;
        regReq.model = model;
        regReq.serialNumber = serial;
        regReq.locale = locale;

        String regBody = new Gson().toJson(regReq);
        logger.Info("Registering WARP device...");

        // DIVERGENCE: usque uses the url "ApiUrl/ApiVersion/reg" (two variables).
        //             Java inlines the full URL.
        HttpRequest regHttpReq = HttpRequest.newBuilder()
                .uri(URI.create(API_BASE))
                .header("Content-Type", "application/json")
                .header("User-Agent", USER_AGENT)
                .header("CF-Client-Version", CLIENT_VERSION)
                .POST(HttpRequest.BodyPublishers.ofString(regBody))
                .build();

        HttpResponse<String> regResp = client.send(regHttpReq, HttpResponse.BodyHandlers.ofString());
        if (regResp.statusCode() != 200) {
            // DIVERGENCE: usque returns fmt.Errorf without the response body.
            //             Java includes resp.body() in the error message.
            throw new IOException("Registration failed: HTTP " + regResp.statusCode() + " " + regResp.body());
        }

        AccountResponse accountData = new Gson().fromJson(regResp.body(), AccountResponse.class);
        logger.Info("Device registered, id=%s", accountData.id);

        // DIVERGENCE: usque internal/utils.go:70-93 returns both keys as byte[]
        //             (SEC 1 private, PKIX public). Java uses KeyPairGenerator
        //             directly; getEncoded() on private key returns PKCS#8, not SEC 1.
        //             usque: x509.MarshalECPrivateKey() vs Java: PKCS8EncodedKeySpec.
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecKeyPair = keyGen.generateKeyPair();
        String ecPubKeyBase64 = Base64.getEncoder().encodeToString(ecKeyPair.getPublic().getEncoded());

        EnrollRequest enrollReq = new EnrollRequest();
        enrollReq.key = ecPubKeyBase64;
        enrollReq.name = name;

        String enrollBody = new Gson().toJson(enrollReq);
        logger.Info("Enrolling ECDSA key for MASQUE...");

        HttpRequest enrollHttpReq = HttpRequest.newBuilder()
                .uri(URI.create(API_BASE + "/" + accountData.id))
                .header("Content-Type", "application/json")
                .header("User-Agent", USER_AGENT)
                .header("CF-Client-Version", CLIENT_VERSION)
                .header("Authorization", "Bearer " + accountData.token)
                .method("PATCH", HttpRequest.BodyPublishers.ofString(enrollBody))
                .build();

        // DIVERGENCE: usque api/cloudflare.go:163-168 parses the Cloudflare APIError
        //             JSON structure and returns *models.APIError alongside the error.
        //             Java does NOT parse the structured error — cannot detect
        //             "Invalid public key" to trigger key-regeneration retry
        //             (the way usque cmd/enroll.go does).
        HttpResponse<String> enrollResp = client.send(enrollHttpReq, HttpResponse.BodyHandlers.ofString());
        if (enrollResp.statusCode() != 200) {
            throw new IOException("Key enrollment failed: HTTP " + enrollResp.statusCode() + " " + enrollResp.body());
        }

        AccountResponse enrolledData = new Gson().fromJson(enrollResp.body(), AccountResponse.class);
        logger.Info("MASQUE enrollment completed");

        WarpConfig config = new WarpConfig();
        config.privateKeyBase64 = Base64.getEncoder().encodeToString(ecKeyPair.getPrivate().getEncoded());
        config.publicKeyBase64 = Base64.getEncoder().encodeToString(ecKeyPair.getPublic().getEncoded());
        // DIVERGENCE: usque stores the private key in SEC 1 ECPrivateKey format
        //             (x509.MarshalECPrivateKey). Java stores PKCS#8 format
        //             (KeyPair.private.getEncoded()). Config files are NOT
        //             interchangeable between usque and Java.
        // DIVERGENCE: usque does NOT store the public key in config — it derives
        //             it from the private key at runtime via privKey.PublicKey.
        //             Java stores both keys explicitly (defensive improvement).
        config.deviceId = accountData.id;
        config.accessToken = accountData.token;
        config.license = accountData.account != null ? accountData.account.license : "";
        config.model = model;

        // DIVERGENCE: usque cmd/register.go selects the endpoint from the
        //             enrollment response. Java also checks the registration
        //             response as fallback (lines 193-200). usque does not.
        if (enrolledData.config != null && enrolledData.config.peers != null && enrolledData.config.peers.length > 0) {
            Peer peer = enrolledData.config.peers[0];
            config.endpointPubKeyPem = peer.publicKey;
            if (peer.endpoint != null) {
                config.endpointV4 = peer.endpoint.v4;
                config.endpointV6 = peer.endpoint.v6;
            }
        } else if (accountData.config != null && accountData.config.peers != null && accountData.config.peers.length > 0) {
            Peer peer = accountData.config.peers[0];
            config.endpointPubKeyPem = peer.publicKey;
            if (peer.endpoint != null) {
                config.endpointV4 = peer.endpoint.v4;
                config.endpointV6 = peer.endpoint.v6;
            }
        }

        if (accountData.config != null && accountData.config.iface != null && accountData.config.iface.addresses != null) {
            config.ipv4 = accountData.config.iface.addresses.v4;
            config.ipv6 = accountData.config.iface.addresses.v6;
        }

        return config;
    }

    // DIVERGENCE: usque internal/utils.go:35-40 uses crypto/rand (8 bytes → hex).
    //             Java uses java.util.Random (non-cryptographic).
    static String randomHex(int length) {
        Random rnd = new Random();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) sb.append(Integer.toHexString(rnd.nextInt(16)));
        return sb.toString();
    }

    // DIVERGENCE: usque internal/utils.go:49-54 does NOT clamp (just crypto/rand.Read).
    //             Java applies WireGuard clamping (key[0]&=248, key[31]&=127, key[31]|=64).
    //             Both are functionally equivalent since this key is a throwaway.
    // DIVERGENCE: usque returns the raw bytes base64-encoded (just a random string).
    //             Java wraps it in a WireGuardKey class but also only returns base64.
    static class WireGuardKey {
        private final byte[] privateKey;

        WireGuardKey(byte[] privateKey) {
            this.privateKey = privateKey;
        }

        static WireGuardKey generate() {
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            key[0] &= 248;
            key[31] &= 127;
            key[31] |= 64;
            return new WireGuardKey(key);
        }

        String publicKeyBase64() {
            byte[] pub = new byte[32];
            System.arraycopy(privateKey, 0, pub, 0, 32);
            return Base64.getEncoder().encodeToString(pub);
        }
    }
}
