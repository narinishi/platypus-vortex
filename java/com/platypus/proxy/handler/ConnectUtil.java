package com.platypus.proxy.handler;

import com.platypus.proxy.handler.protocol.OutboundProtocol;
import com.platypus.proxy.provider.ProviderAdditionalSupplier;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.function.Supplier;

public final class ConnectUtil {
    private ConnectUtil() {}

    public static String buildConnectRequest(String host, int port, Supplier<String> authSupplier) {
        if (authSupplier instanceof ProviderAdditionalSupplier as) {
            return buildConnectRequest(host, port, as, true);
        }

        String target = host + ":" + port;
        StringBuilder sb = new StringBuilder(256);
        sb.append("CONNECT ").append(target).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(target).append("\r\n");
        if (authSupplier != null) {
            String auth = authSupplier.get();
            if (auth != null && !auth.isEmpty()) {
                sb.append("Proxy-Authorization: ").append(auth).append("\r\n");
            }
        }
        sb.append("\r\n");
        return sb.toString();
    }

    public static String buildConnectRequest(
            String host, int port, ProviderAdditionalSupplier supplier, boolean includeAuth) {
        String target = host + ":" + port;
        StringBuilder sb = new StringBuilder(256);
        sb.append("CONNECT ").append(target).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(target).append("\r\n");
        if (includeAuth) {
            String auth = supplier.get();
            if (auth != null && !auth.isEmpty()) {
                sb.append("Proxy-Authorization: Basic ").append(auth).append("\r\n");
            }
        }
        supplier.appendAdditionalTo(sb);
        sb.append("\r\n");
        return sb.toString();
    }

    public static ProxyHandler.ChainedProxyConfig parseOutboundProxy(String proxyUrl) {
        String normalized = proxyUrl;
        if (!normalized.contains("://")) {
            normalized = "http://" + normalized;
        }
        URL url;
        try {
            url = URI.create(normalized).toURL();
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid proxy URL: " + proxyUrl, e);
        }

        String scheme = url.getProtocol().toLowerCase(Locale.ROOT);
        OutboundProtocol type;
        boolean remoteDns = false;
        switch (scheme) {
            case "http" -> type = OutboundProtocol.HTTP;
            case "https" -> type = OutboundProtocol.HTTPS;
            case "socks5" -> {
                type = OutboundProtocol.SOCKS5;
                remoteDns = false;
            }
            case "socks5h" -> {
                type = OutboundProtocol.SOCKS5;
                remoteDns = true;
            }
            default -> throw new IllegalArgumentException("Unsupported proxy scheme: " + scheme);
        }

        String host = url.getHost();
        int port = url.getPort();
        if (port == -1) {
            port = (type == OutboundProtocol.HTTP) ? 80 : (type == OutboundProtocol.HTTPS ? 443 : 1080);
        }

        Supplier<String> authSupplier = null;
        if (url.getUserInfo() != null && !url.getUserInfo().isEmpty()) {
            if (type == OutboundProtocol.HTTP || type == OutboundProtocol.HTTPS) {
                String encoded =
                        Base64.getEncoder().encodeToString(url.getUserInfo().getBytes(StandardCharsets.UTF_8));
                authSupplier = () -> "Basic " + encoded;
            } else {
                authSupplier = () -> url.getUserInfo();
            }
        }
        return new ProxyHandler.ChainedProxyConfig(host, port, type, remoteDns, authSupplier);
    }

    public static boolean isAlive(Socket socket) {
        if (socket == null) return false;
        if (socket.isClosed()) return false;
        if (socket.isInputShutdown()) return false;

        int prevTimeout;
        try {
            prevTimeout = socket.getSoTimeout();
        } catch (SocketException e) {
            return false;
        }

        try {
            socket.setSoTimeout(1);
            InputStream in = socket.getInputStream();
            @SuppressWarnings("unused")
            int b = in.read();
            return false;
        } catch (SocketTimeoutException expected) {
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            try {
                socket.setSoTimeout(prevTimeout);
            } catch (SocketException ignored) {
            }
        }
    }
}
