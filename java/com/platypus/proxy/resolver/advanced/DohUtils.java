package com.platypus.proxy.resolver.advanced;

import java.net.IDN;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DohUtils {

    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);

    /**
     * Per-request timeout. Apply via
     * HttpRequest.Builder#timeout(Duration) when building
     * DoH queries; the HttpClient itself has no
     * request-level timeout setting.
     */
    static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    /**
     * Total lookup timeout including retries and failover
     * across multiple DoH servers. Managed by the caller
     * (e.g. via CompletableFuture.orTimeout).
     */
    static final Duration LOOKUP_TIMEOUT = Duration.ofSeconds(30);

    /**
     * Maximum total length of a DNS name in wire format
     * (RFC 1035 §2.3.4), minus the root label and
     * trailing length byte: 255 - 1 - 1 = 253.
     */
    static final int MAX_DNS_NAME_LENGTH = 253;

    /**
     * Maximum label length per RFC 1035 §2.3.4.
     */
    static final int MAX_LABEL_LENGTH = 63;

    /**
     * IDN conversion flags: no USE_STD3_ASCII_RULES (to
     * allow underscores in SRV/DNS-SD/DKIM names) and no
     * ALLOW_UNASSIGNED (to reject unassigned Unicode code
     * points for security).
     */
    static final int IDN_FLAGS = 0;

    // --- Shared HTTP client (lazy singleton) ---

    private static volatile HttpClient sharedClient;
    private static final Object CLIENT_LOCK = new Object();

    /**
     * True once shutdown() has been invoked.
     * Volatile so that sharedHttpClient() can read it
     * outside the lock without stale values.
     */
    private static volatile boolean shutDown;

    private static ExecutorService createDohExecutor() {
        return Executors.newFixedThreadPool(Math.max(4, Runtime.getRuntime().availableProcessors()), r -> {
            Thread t = new Thread(r, "doh-worker");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Returns a shared, lazily-created HttpClient.
     * Thread-safe.
     *
     * @throws IllegalStateException if called after
     *                               shutdown()
     */
    static HttpClient sharedHttpClient() {
        if (shutDown) {
            throw new IllegalStateException("DohUtils has been shut down");
        }
        if (sharedClient == null) {
            synchronized (CLIENT_LOCK) {
                if (shutDown) {
                    throw new IllegalStateException("DohUtils has been shut down");
                }
                if (sharedClient == null) {
                    sharedClient = buildHttpClient();
                }
            }
        }
        return sharedClient;
    }

    private static HttpClient buildHttpClient() {
        return HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .connectTimeout(CONNECT_TIMEOUT)
                .executor(createDohExecutor())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /**
     * Shuts down the shared client's executor, clears the
     * singleton reference, and prevents future client
     * creation.
     *
     * <p>
     * <b>Contract:</b> no request may be in flight when
     * this method is called. In-flight requests holding a
     * prior reference to the HttpClient will fail once
     * the backing executor is terminated.
     */
    static void shutdown() {
        synchronized (CLIENT_LOCK) {
            shutDown = true;
            if (sharedClient != null) {
                Optional.of(sharedClient)
                        .flatMap(c -> c.executor())
                        .filter(ExecutorService.class::isInstance)
                        .map(ExecutorService.class::cast)
                        .ifPresent(ExecutorService::shutdown);
                sharedClient = null;
            }
        }
    }

    // --- IPv4/IPv6 literal detection and parsing ---

    static InetAddress parseIpAddressLiteral(String host) {
        if (host == null || host.isEmpty()) return null;
        String h = host;
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }
        if (h.indexOf(':') >= 0 && looksLikeIpv6(h)) {
            // Strip zone/scope ID (%eth0) - validated by
            // looksLikeIpv6 but unsupported by getByName.
            int pct = h.indexOf('%');
            String addr = pct >= 0 ? h.substring(0, pct) : h;
            try {
                return InetAddress.getByName(addr);
            } catch (UnknownHostException e) {
                return null;
            }
        }
        if (looksLikeIpv4(h)) {
            try {
                return InetAddress.getByName(h);
            } catch (UnknownHostException e) {
                return null;
            }
        }
        return null;
    }

    static boolean looksLikeIpv4(String h) {
        int dots = 0;
        long num = 0;
        boolean hasDigit = false;
        for (int i = 0; i < h.length(); i++) {
            char c = h.charAt(i);
            if (c == '.') {
                if (!hasDigit || num > 255) return false;
                dots++;
                num = 0;
                hasDigit = false;
            } else if (c >= '0' && c <= '9') {
                if (num == 0 && hasDigit) return false;
                num = num * 10 + (c - '0');
                if (num > 255) return false;
                hasDigit = true;
            } else {
                return false;
            }
        }
        return dots == 3 && hasDigit && num <= 255;
    }

    static boolean looksLikeIpv6(String h) {
        if (h.isEmpty()) return false;
        int scopeIdx = h.indexOf('%');
        if (scopeIdx >= 0) {
            if (scopeIdx == h.length() - 1) return false;
            return looksLikeIpv6Addr(h.substring(0, scopeIdx));
        }
        return looksLikeIpv6Addr(h);
    }

    static boolean looksLikeIpv6Addr(String h) {
        if (h.endsWith(":") && !h.endsWith("::")) return false;
        int doubleColon = h.indexOf("::");
        if (doubleColon >= 0) {
            if (h.indexOf("::", doubleColon + 1) >= 0) return false;
            String before = h.substring(0, doubleColon);
            String after = h.substring(doubleColon + 2);
            int bG = before.isEmpty() ? 0 : countGroups(before);
            int aG = after.isEmpty() ? 0 : countGroups(after);
            if (bG < 0 || aG < 0) return false;
            boolean hasV4 = before.contains(".") || after.contains(".");
            if (hasV4) {
                // IPv4 suffix must be the very last
                // segment; cannot appear before the
                // :: expansion.
                if (before.contains(".")) return false;
                if (!ipv4InLastSegment(after)) return false;
                // An IPv4 dotted-quad occupies 2 group
                // slots but countGroups counts it as 1,
                // so bG+aG must be <= 6 (leaving room
                // for at least 1 expanded group + the
                // 2-slot v4).
                return (bG + aG) <= 6;
            }
            return (bG + aG) <= 7;
        }
        int groups = countGroups(h);
        if (groups < 0) return false;
        if (groups == 8 && !h.contains(".")) return true;
        if (groups == 7) return ipv4InLastSegment(h);
        return false;
    }

    /**
     * True when the dotted-decimal part is confined to
     * the final colon-separated segment of the address.
     */
    private static boolean ipv4InLastSegment(String h) {
        int lastColon = h.lastIndexOf(':');
        return lastColon < 0 ? h.contains(".") : h.indexOf('.', lastColon) >= 0;
    }

    /**
     * Counts colon-separated segments in one side of a
     * possible :: expansion. An IPv4 dotted-quad counts
     * as <b>one</b> segment here (it occupies two 16-bit
     * group slots in the address, which the caller must
     * account for separately).
     */
    static int countGroups(String part) {
        if (part.isEmpty()) return 0;
        int groups = 0;
        for (String g : part.split(":")) {
            if (g.isEmpty()) return -1;
            if (g.indexOf('.') >= 0) {
                groups++;
                continue;
            }
            if (g.length() > 4) return -1;
            for (int i = 0; i < g.length(); i++) {
                char c = g.charAt(i);
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return -1;
            }
            groups++;
        }
        return groups;
    }

    // --- Host normalization ---

    /**
     * Normalizes a host name for DNS resolution:
     * <ol>
     * <li>Converts internationalized labels to ASCII
     * via IDN (Punycode).</li>
     * <li>Lowercases the result (Locale.ROOT).</li>
     * <li>Strips a trailing root-label dot.</li>
     * <li>Validates label lengths (<=63 octets) and
     * total name length (<=253 octets) per
     * RFC 1035 §2.3.4.</li>
     * <li>Validates that each label contains only
     * ASCII letters, digits, hyphens, or
     * underscores (STD-3 + underscore for
     * SRV/DNS-SD/DKIM names).</li>
     * </ol>
     *
     * @throws UnknownHostException if host is null,
     *                              empty, or fails validation
     */
    static String normalizeHost(String host) throws UnknownHostException {
        if (host == null) {
            throw new UnknownHostException("Null host");
        }
        try {
            // No USE_STD3_ASCII_RULES: underscores are
            // valid in DNS (SRV, DNS-SD, DKIM) but
            // rejected by STD-3. We validate the
            // character set ourselves after conversion.
            String ascii = IDN.toASCII(host, IDN_FLAGS).toLowerCase(Locale.ROOT);
            if (ascii.endsWith(".")) {
                ascii = ascii.substring(0, ascii.length() - 1);
            }
            if (ascii.isEmpty()) {
                throw new UnknownHostException("Empty host: " + host);
            }
            if (ascii.length() > MAX_DNS_NAME_LENGTH) {
                throw new UnknownHostException(
                        "Host too long (" + ascii.length() + " > " + MAX_DNS_NAME_LENGTH + "): " + host);
            }
            String[] labels = ascii.split("\\.", -1);
            for (String label : labels) {
                validateLabel(label, host);
            }
            return ascii;
        } catch (IllegalArgumentException e) {
            UnknownHostException uhe = new UnknownHostException("Invalid host: " + host);
            uhe.initCause(e);
            throw uhe;
        }
    }

    /**
     * Validates a single DNS label after IDN conversion.
     * Allows ASCII letters, digits, hyphens, and
     * underscores (STD-3 plus underscore). Rejects
     * empty labels and labels exceeding 63 octets.
     */
    private static void validateLabel(String label, String originalHost) throws UnknownHostException {
        if (label.isEmpty()) {
            throw new UnknownHostException("Empty label in host: " + originalHost);
        }
        if (label.length() > MAX_LABEL_LENGTH) {
            throw new UnknownHostException(
                    "Label too long (" + label.length() + " > " + MAX_LABEL_LENGTH + "): " + originalHost);
        }
        for (int i = 0; i < label.length(); i++) {
            char c = label.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) {
                throw new UnknownHostException("Invalid character '" + c + "' in label: " + originalHost);
            }
        }
    }
}
