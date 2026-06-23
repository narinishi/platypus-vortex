package com.platypus.proxy.resolver;

import com.google.gson.JsonParser;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.List;

// TODO: completely rewrite

@Deprecated
public class DnsResolverFactory {

    public static LookupNetIP fromUrl(String urlStr) throws IllegalArgumentException {
        try {
            URI uri = new URI(urlStr);
            String scheme = uri.getScheme().toLowerCase();
            String host = uri.getHost();
            int port = uri.getPort();

            switch (scheme) {
                case "dns":
                case "udp":
                    if (port <= 0) port = 53;
                    return new PlainDnsResolver(host, port, false);
                case "tcp":
                    if (port <= 0) port = 53;
                    return new PlainDnsResolver(host, port, true);
                case "https":
                case "doh":
                    if (port <= 0) port = 443;
                    return new DohResolver(host, port, uri.getPath());
                case "http":
                    if (port <= 0) port = 80;
                    return new DohResolver(host, port, uri.getPath());
                case "tls":
                case "dot":
                    if (port <= 0) port = 853;
                    return new DotResolver(host, port);
                default:
                    throw new IllegalArgumentException("Unknown DNS scheme: " + scheme);
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse DNS URL: " + urlStr, e);
        }
    }

    public static LookupNetIP fastResolverFromUrls(String... urls) {
        LookupNetIP[] resolvers = new LookupNetIP[urls.length];
        for (int i = 0; i < urls.length; i++) {
            resolvers[i] = fromUrl(urls[i]);
        }
        return new FastResolver(resolvers);
    }

    private static class PlainDnsResolver implements LookupNetIP {
        private final String host;
        private final int port;

        @SuppressWarnings("unused")
        private final boolean useTcp;

        PlainDnsResolver(String host, int port, boolean useTcp) {
            this.host = host;
            this.port = port;
            this.useTcp = useTcp;
        }

        @Override
        public List<InetAddress> lookup(String host) throws UnknownHostException {
            java.net.DatagramSocket sock = null;
            try {
                sock = new java.net.DatagramSocket();
                sock.setSoTimeout(5000);
                byte[] query = buildQuery(host);
                java.net.DatagramPacket packet =
                        new java.net.DatagramPacket(query, query.length, new InetSocketAddress(this.host, this.port));
                sock.send(packet);
                byte[] response = new byte[512];
                java.net.DatagramPacket resp = new java.net.DatagramPacket(response, response.length);
                sock.receive(resp);
                return parseResponse(response);
            } catch (Exception e) {
                return java.util.Arrays.asList(java.net.InetAddress.getAllByName(host));
            } finally {
                if (sock != null) sock.close();
            }
        }

        private byte[] buildQuery(String name) {
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            java.io.DataOutputStream dos = new java.io.DataOutputStream(baos);
            try {
                dos.writeShort(0x1234);
                dos.writeShort(0x0100);
                dos.writeShort(1);
                dos.writeShort(0);
                dos.writeShort(0);
                dos.writeShort(0);
                for (String label : name.split("\\.")) {
                    dos.writeByte(label.length());
                    dos.writeBytes(label);
                }
                dos.writeByte(0);
                dos.writeShort(1);
                dos.writeShort(1);
                return baos.toByteArray();
            } catch (Exception e) {
                return new byte[0];
            }
        }

        private List<InetAddress> parseResponse(byte[] data) throws UnknownHostException {
            return parseDnsResponse(data);
        }
    }

    static List<InetAddress> parseDnsResponse(byte[] data) throws UnknownHostException {
        if (data.length < 12) throw new UnknownHostException();
        int questions = (data[4] & 0xFF) << 8 | (data[5] & 0xFF);
        int answers = (data[6] & 0xFF) << 8 | (data[7] & 0xFF);
        if (answers == 0) throw new UnknownHostException();
        List<InetAddress> result = new java.util.ArrayList<>();
        int pos = 12;
        for (int q = 0; q < questions && pos < data.length; q++) {
            if ((data[pos] & 0xC0) == 0xC0) {
                pos += 2;
            } else {
                while (pos < data.length && data[pos] != 0) {
                    pos += data[pos] + 1;
                }
                pos += 5;
            }
        }
        for (int a = 0; a < answers && pos + 10 < data.length; a++) {
            if ((data[pos] & 0xC0) == 0xC0) {
                pos += 2;
            } else {
                while (pos < data.length && data[pos] != 0) {
                    pos += data[pos] + 1;
                }
                pos += 1;
            }
            int type = (data[pos] & 0xFF) << 8 | (data[pos + 1] & 0xFF);
            int rdlength = (data[pos + 8] & 0xFF) << 8 | (data[pos + 9] & 0xFF);
            pos += 10;
            if (type == 1 && rdlength == 4 && pos + 4 <= data.length) {
                byte[] addrBytes = java.util.Arrays.copyOfRange(data, pos, pos + 4);
                result.add(java.net.InetAddress.getByAddress(addrBytes));
            } else if (type == 28 && rdlength == 16 && pos + 16 <= data.length) {
                byte[] addrBytes = java.util.Arrays.copyOfRange(data, pos, pos + 16);
                result.add(java.net.InetAddress.getByAddress(addrBytes));
            }
            pos += rdlength;
        }
        if (result.isEmpty()) throw new UnknownHostException();
        return result;
    }

    private static class DohResolver implements LookupNetIP {
        private final String host;
        private final int port;
        private final String path;

        DohResolver(String host, int port, String path) {
            this.host = host;
            this.port = port;
            this.path = path != null ? path : "/dns-query";
        }

        @Override
        public List<InetAddress> lookup(String name) throws UnknownHostException {
            try {
                java.net.URL url =
                        URI.create("https://" + host + ":" + port + path).toURL();
                java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("Accept", "application/dns-json");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                conn.connect();
                try (java.io.InputStream is = conn.getInputStream()) {
                    String json = new String(is.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                    return parseDohResponse(json);
                }
            } catch (Exception e) {
                throw new UnknownHostException(name);
            }
        }

        private List<InetAddress> parseDohResponse(String json) throws UnknownHostException {
            try {
                com.google.gson.JsonObject obj = JsonParser.parseString(json).getAsJsonObject();
                com.google.gson.JsonArray answers = obj.getAsJsonArray("Answer");
                if (answers == null) throw new UnknownHostException();
                List<InetAddress> result = new java.util.ArrayList<>();
                for (int i = 0; i < answers.size(); i++) {
                    String data = answers.get(i).getAsJsonObject().get("data").getAsString();
                    try {
                        result.add(java.net.InetAddress.getByName(data));
                    } catch (Exception ignored) {
                    }
                }
                if (result.isEmpty()) throw new UnknownHostException();
                return result;
            } catch (Exception e) {
                throw new UnknownHostException();
            }
        }
    }

    private static class DotResolver implements LookupNetIP {
        private final String host;
        private final int port;

        DotResolver(String host, int port) {
            this.host = host;
            this.port = port;
        }

        @Override
        public List<InetAddress> lookup(String name) throws UnknownHostException {
            try {
                java.security.SecureRandom rnd = new java.security.SecureRandom();
                int id = rnd.nextInt() & 0xFFFF;
                byte[] query = buildQuery(name, id);
                javax.net.ssl.SSLContext sslContext = javax.net.ssl.SSLContext.getInstance("TLS");
                sslContext.init(
                        null,
                        new javax.net.ssl.TrustManager[] {
                            new javax.net.ssl.X509TrustManager() {
                                public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}

                                public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}

                                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                                    return new java.security.cert.X509Certificate[0];
                                }
                            }
                        },
                        null);
                java.net.Socket sock = sslContext.getSocketFactory().createSocket(host, port);
                try {
                    sock.setSoTimeout(5000);
                    java.io.OutputStream out = sock.getOutputStream();
                    byte[] lenPref = new byte[] {(byte) (query.length >> 8), (byte) (query.length & 0xFF)};
                    out.write(lenPref);
                    out.write(query);
                    out.flush();
                    java.io.InputStream in = sock.getInputStream();
                    int hi = in.read();
                    int lo = in.read();
                    int respLen = (hi << 8) | lo;
                    if (respLen < 12) throw new UnknownHostException(name);
                    byte[] resp = new byte[respLen];
                    int off = 0;
                    while (off < respLen) {
                        int n = in.read(resp, off, respLen - off);
                        if (n < 0) throw new UnknownHostException(name);
                        off += n;
                    }
                    return parseDnsResponse(resp);
                } finally {
                    sock.close();
                }
            } catch (UnknownHostException e) {
                throw e;
            } catch (Exception e) {
                throw new UnknownHostException(name);
            }
        }

        private byte[] buildQuery(String name, int id) {
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            java.io.DataOutputStream dos = new java.io.DataOutputStream(baos);
            try {
                dos.writeShort(id);
                dos.writeShort(0x0100);
                dos.writeShort(1);
                dos.writeShort(0);
                dos.writeShort(0);
                dos.writeShort(0);
                for (String label : name.split("\\.")) {
                    dos.writeByte(label.length());
                    dos.writeBytes(label);
                }
                dos.writeByte(0);
                dos.writeShort(1);
                dos.writeShort(1);
                return baos.toByteArray();
            } catch (Exception e) {
                return new byte[0];
            }
        }
    }
}
