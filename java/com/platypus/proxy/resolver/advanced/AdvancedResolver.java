package com.platypus.proxy.resolver.advanced;

import com.platypus.proxy.logging.CondLogger;
import com.platypus.proxy.resolver.LookupNetIP;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * DNS-over-HTTPS resolver using RFC 8484 POST.
 * Falls back only to other DoH endpoints - never to system DNS.
 *
 * <p>
 * <b>DNSSEC note:</b> The {@code requestDnssecRecords} option sets
 * the EDNS(0) DO bit to request DNSSEC-related records (RRSIG, DNSKEY,
 * etc.) from upstream resolvers. It does <em>not</em> perform DNSSEC
 * validation. Callers must not rely on this flag for authentication
 * of responses.
 *
 * <p>
 * <b>Lifecycle note:</b> The caller-supplied {@link HttpClient}
 * is <em>not</em> closed by {@link #close()}. When the default shared
 * client is used its lifetime is intended to match the process.
 *
 * <p>
 * Requires Java 12+ ({@code exceptionallyCompose}).
 */
public class AdvancedResolver implements LookupNetIP, AutoCloseable {

    // --- Configuration ---

    /**
     * WARNING: This class reveals your approximate geolocation to remote sites.
     *
     * When connecting to anycast addresses, the network routes your request to
     * the nearest server. Sites can infer your approximate location from which
     * server you reached--typically accurate to the city or region level.
     *
     * Consider whether this tradeoff is acceptable for your use case before
     * using this class.
     */

    // NOTE: consider also offering Oblivious DNS over HTTPS
    // https://developers.cloudflare.com/1.1.1.1/encryption/oblivious-dns-over-https/

    private static final List<String> DOH_ENDPOINTS = List.of("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query");

    // Fix #11: lowered from 60 s so short CDN TTLs are honoured
    private static final long MIN_CACHE_TTL_MS = 5_000;
    private static final long MAX_CACHE_TTL_MS = 86_400_000;
    static final long NEGATIVE_TTL_MS = 30_000;
    // Fix #8: brief negative cache for transient errors
    static final long SERVFAIL_NEGATIVE_TTL_MS = 5_000;
    static final long STALE_TTL_MS = 3_600_000;
    static final double REFRESH_FRACTION = 0.75;

    private static final int MAX_CACHE_SIZE = 1024;
    static final long DEFAULT_TTL_SECONDS = 300;
    static final int MAX_CNAME_DEPTH = 5;

    private static final int MAX_CONCURRENT_REQUESTS = 10;

    private static final int SEMAPHORE_RETRIES = 3;
    private static final int SEMAPHORE_RETRY_MS = 100;

    private static final Set<String> BLOCKING_IPS = Set.of("0.0.0.0");

    // intentionally unused
    @SuppressWarnings("unused")
    private static final String USER_AGENT = "AdvancedResolver/1.0";

    // --- Instance state ---

    // Fix #3: removed separate cacheSize counter; use cache.size()
    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, CompletableFuture<CacheEntry>> inFlight = new ConcurrentHashMap<>();
    // Fix #12: O(1) removal via CHM-backed Set
    private final Set<CompletableFuture<?>> activeRequests = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Semaphore requestSemaphore = new Semaphore(MAX_CONCURRENT_REQUESTS);
    // Fix #5: separate executor so retries never block eviction
    private final ScheduledExecutorService evictor;
    private final ScheduledExecutorService retryExecutor;
    private final HttpClient httpClient;
    private final boolean requestDnssecRecords;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    private static final HttpClient SHARED_HTTP_CLIENT = DohUtils.sharedHttpClient();

    /** Sorted array of hostnames from the hosts file (lowercased). */
    private String[] hostsNames;
    /**
     * Parallel array - exactly one IP address per hostname (null marks a blocked
     * entry).
     */
    private InetAddress[] hostsAddresses;

    private final CondLogger logger;

    // --- Constructor / close ---

    public AdvancedResolver(CondLogger logger) {
        this(logger, SHARED_HTTP_CLIENT, false, Paths.get("hosts"));
    }

    // public AdvancedResolver(boolean requestDnssecRecords) {
    // this(SHARED_HTTP_CLIENT, requestDnssecRecords);
    // }

    // public AdvancedResolver(HttpClient httpClient) {
    // this(httpClient, false);
    // }

    // public AdvancedResolver(HttpClient httpClient,
    // boolean requestDnssecRecords) {
    // this(httpClient, requestDnssecRecords, Paths.get("hosts"));
    // }

    /**
     * Creates a resolver with a custom client, DNSSEC flag, and hosts file.
     *
     * @param httpClient           HTTP client for DoH requests
     * @param requestDnssecRecords whether to set the DNSSEC DO bit
     * @param hostsFilePath        path to a hosts file
     */
    public AdvancedResolver(
            CondLogger logger, HttpClient httpClient, boolean requestDnssecRecords, Path hostsFilePath) {
        this(logger, httpClient, requestDnssecRecords, loadHostsFileSafe(logger, hostsFilePath));
    }

    // Private master constructor - all others delegate here
    private AdvancedResolver(
            CondLogger logger, HttpClient httpClient, boolean requestDnssecRecords, Map<String, InetAddress> hostsMap) {
        this.logger = logger;
        this.httpClient = httpClient;
        this.requestDnssecRecords = requestDnssecRecords;

        // Use a TreeMap to sort entries case-insensitively and align arrays
        TreeMap<String, InetAddress> sorted = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        sorted.putAll(hostsMap);

        int size = sorted.size();
        this.hostsNames = new String[size];
        this.hostsAddresses = new InetAddress[size];
        int idx = 0;
        for (Map.Entry<String, InetAddress> entry : sorted.entrySet()) {
            this.hostsNames[idx] = entry.getKey(); // already lowercased by loader
            this.hostsAddresses[idx] = entry.getValue();
            idx++;
        }

        evictor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "dns-cache-evictor");
            t.setDaemon(true);
            return t;
        });
        retryExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "dns-retry-scheduler");
            t.setDaemon(true);
            return t;
        });

        evictor.scheduleAtFixedRate(
                () -> {
                    try {
                        evictExpired();
                    } catch (Throwable t) {
                        logger.Warning("Cache eviction failed: %s", t);
                    }
                },
                60,
                60,
                TimeUnit.SECONDS);
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            for (CompletableFuture<?> f : activeRequests) {
                f.cancel(true);
            }
            // Fix #5: shut down retry executor first
            retryExecutor.shutdownNow();
            evictor.shutdownNow();
            try {
                retryExecutor.awaitTermination(1, TimeUnit.SECONDS);
                evictor.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            // Fix #13 (lifecycle note): the HttpClient is not
            // closed here; see class Javadoc.
        }
    }

    // --- Hosts file loader ---

    /**
     * Reads a hosts file in standard format.
     * Each hostname maps to exactly one IP address (the last occurrence
     * overwrites earlier ones).
     */
    static Map<String, InetAddress> loadHostsFile(BufferedReader reader) throws IOException {
        Map<String, InetAddress> map = new LinkedHashMap<>();
        String line;
        while ((line = reader.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            String[] parts = line.split("\\s+");
            if (parts.length < 2) {
                continue;
            }

            String ipStr = parts[0];
            InetAddress addr;
            try {
                addr = BLOCKING_IPS.contains(ipStr) ? null : InetAddress.getByName(ipStr);
            } catch (UnknownHostException e) {
                continue; // invalid IP - skip the line
            }

            for (int i = 1; i < parts.length; i++) {
                map.put(parts[i].toLowerCase(Locale.ROOT), addr);
            }
        }
        return map;
    }

    private static Map<String, InetAddress> loadHostsFileSafe(CondLogger logger, Path path) {
        if (path == null) return Collections.emptyMap();
        File file = path.toFile();
        if (!file.isFile()) {
            logger.Warning("No hostfile located: " + file.getAbsolutePath());
            return Collections.emptyMap();
        }
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            logger.Info("Using hosts file: " + path);
            return loadHostsFile(reader);
        } catch (IOException e) {
            logger.Warning("Could not load hosts file: %s: %s", path, e);
            return Collections.emptyMap();
        }
    }

    // --- Public API: synchronous ---

    @Override
    public List<InetAddress> lookup(String host) throws UnknownHostException {
        ensureOpen();
        try {
            return lookupAsync(host)
                    .toCompletableFuture()
                    .get(DohUtils.LOOKUP_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        } catch (ExecutionException e) {
            Throwable cause = unwrap(e);
            if (cause instanceof UnknownHostException uh) throw uh;
            UnknownHostException uhe = new UnknownHostException(host + " (" + cause + ")");
            uhe.initCause(cause);
            throw uhe;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            UnknownHostException uhe = new UnknownHostException("Interrupted: " + host);
            uhe.initCause(e);
            throw uhe;
        } catch (TimeoutException e) {
            UnknownHostException uhe = new UnknownHostException("Timed out: " + host);
            uhe.initCause(e);
            throw uhe;
        }
    }

    // --- Public API: asynchronous ---

    public CompletableFuture<List<InetAddress>> lookupAsync(String host) {
        ensureOpen();

        if (host == null || host.isEmpty()) {
            return CompletableFuture.failedFuture(new UnknownHostException("null or empty host"));
        }

        InetAddress literal = DohUtils.parseIpAddressLiteral(host);
        if (literal != null) {
            return CompletableFuture.completedFuture(List.of(literal));
        }

        final String normalizedHost;
        try {
            normalizedHost = DohUtils.normalizeHost(host);
        } catch (UnknownHostException e) {
            return CompletableFuture.failedFuture(e);
        }

        // --- Hosts file override via binary search ---
        if (hostsNames != null) {
            int idx = Arrays.binarySearch(hostsNames, normalizedHost, String.CASE_INSENSITIVE_ORDER);
            if (idx >= 0) {
                InetAddress addr = hostsAddresses[idx];
                if (addr == null) {
                    /// LOGGER.log(Level.INFO, "the hosts files blocked domain " + normalizedHost);
                    // Host explicitly blocked (e.g., 0.0.0.0)
                    return CompletableFuture.failedFuture(
                            new UnknownHostException(normalizedHost + " (blocked by hosts file)"));
                }
                // Return immediately - hosts entries are NEVER cached
                /// LOGGER.log(Level.INFO, "the hosts entry for domain " + normalizedHost + ", "
                // + addr.toString());
                return CompletableFuture.completedFuture(List.of(addr));
            }
        }

        // --- Fast path: unexpired cache hit ---
        CacheEntry cached = cache.get(normalizedHost);

        if (cached != null && !cached.isExpired()) {
            cached.touch();
            if (cached.isApproachingExpiry()) {
                triggerBackgroundRefresh(normalizedHost);
            }
            if (cached.isNegative) {
                return CompletableFuture.failedFuture(new UnknownHostException(normalizedHost + " (cached negative)"));
            }
            return CompletableFuture.completedFuture(cached.addresses);
        }

        // --- Stale-while-revalidate ---
        // Fix #1: single stale-check block (removed the
        // redundant re-read that followed in the original).
        if (cached != null && !cached.isStaleExpired()) {
            cached.touch();
            triggerBackgroundRefresh(normalizedHost);
            if (cached.isNegative) {
                return CompletableFuture.failedFuture(new UnknownHostException(normalizedHost + " (cached negative)"));
            }
            return CompletableFuture.completedFuture(cached.addresses);
        }

        // --- Cache miss or fully stale: resolve ---
        CompletableFuture<CacheEntry> future =
                inFlight.computeIfAbsent(normalizedHost, k -> resolveAndCache(normalizedHost));

        return future.thenApply(entry -> {
            if (entry.isNegative) {
                throw new CompletionException(new UnknownHostException(normalizedHost));
            }
            return entry.addresses;
        });
    }

    private void triggerBackgroundRefresh(String host) {
        if (closed.get()) return;
        inFlight.computeIfAbsent(host, k -> resolveAndCache(host));
    }

    // --- Core resolution -> cache update ---

    private CompletableFuture<CacheEntry> resolveAndCache(String host) {

        return resolveWithCnameChasing(host, host, 0, Long.MAX_VALUE, List.of())
                .thenApply(dohResult -> {
                    if (dohResult.addresses().isEmpty()) {
                        CacheEntry neg = CacheEntry.negative();
                        putCache(host, neg);
                        return neg;
                    }
                    long ttlMs = dohResult.minTtlSeconds() > (MAX_CACHE_TTL_MS / 1000)
                            ? MAX_CACHE_TTL_MS
                            : clampTtlMs(dohResult.minTtlSeconds() * 1000L);
                    CacheEntry entry = CacheEntry.positive(dohResult.addresses(), ttlMs);
                    putCache(host, entry);
                    return entry;
                })
                .exceptionallyCompose(dohEx -> {
                    // Fix #4: serve stale only when entry has
                    // not passed its stale window
                    CacheEntry existing = cache.get(host);
                    if (existing != null && !existing.isNegative && !existing.isStaleExpired()) {
                        existing.touch();
                        logger.Warning("Serving stale entry for %s due to error", host);

                        return CompletableFuture.completedFuture(existing);
                    }

                    if (isNxDomain(dohEx)) {
                        long soaTtl = extractSoaMinimumTtl(dohEx);
                        CacheEntry neg = soaTtl > 0 ? CacheEntry.negative(soaTtl) : CacheEntry.negative();
                        putCache(host, neg);
                        return CompletableFuture.completedFuture(neg);
                    }

                    // Fix #8: brief negative cache for transient
                    // errors to avoid hammering upstream
                    CacheEntry transientNeg = CacheEntry.negative(SERVFAIL_NEGATIVE_TTL_MS);
                    putCache(host, transientNeg);

                    return CompletableFuture.failedFuture(dohEx);
                })
                .whenComplete((entry, ex) -> inFlight.remove(host));
    }

    // --- CNAME Chasing ---

    private CompletableFuture<DohResult> resolveWithCnameChasing(
            String host, String originalHost, int depth, long minCnameTtl, List<String> visitedNames) {

        if (depth > MAX_CNAME_DEPTH) {
            return CompletableFuture.failedFuture(
                    new UnknownHostException("CNAME chain too long for: " + originalHost));
        }

        if (visitedNames.stream().anyMatch(v -> v.equalsIgnoreCase(host))) {
            return CompletableFuture.failedFuture(new UnknownHostException("CNAME loop detected: " + host));
        }

        return resolveViaDohWithFailover(host, originalHost).thenCompose(result -> {
            // Fix #2: only chase when no addresses have
            // been resolved. If addresses are already
            // present the upstream resolver followed the
            // chain for at least one record type and the
            // addresses belong to the final target.
            if (result.cnameTarget() != null && result.addresses().isEmpty()) {
                long cnameTtl =
                        result.cnameTtlSeconds() == Long.MAX_VALUE ? DEFAULT_TTL_SECONDS : result.cnameTtlSeconds();
                long newMinCnameTtl = minCnameTtl == Long.MAX_VALUE ? cnameTtl : Math.min(minCnameTtl, cnameTtl);
                List<String> updatedVisited = appendList(visitedNames, host);
                return resolveWithCnameChasing(
                        result.cnameTarget(), originalHost, depth + 1, newMinCnameTtl, updatedVisited);
            }

            DohResult finalResult = result;
            long allCnameTtl = minCnameTtl;
            if (result.cnameTtlSeconds() != Long.MAX_VALUE) {
                allCnameTtl = allCnameTtl == Long.MAX_VALUE
                        ? result.cnameTtlSeconds()
                        : Math.min(allCnameTtl, result.cnameTtlSeconds());
            }
            if (allCnameTtl != Long.MAX_VALUE && !result.addresses().isEmpty()) {
                long effectiveTtl = Math.min(result.minTtlSeconds(), allCnameTtl);
                finalResult = new DohResult(
                        result.addresses(),
                        effectiveTtl,
                        allCnameTtl,
                        result.nxDomain(),
                        result.error(),
                        result.cnameTarget(),
                        result.soaMinimumTtl());
            }

            // Fix #10: create a separate CacheEntry per
            // visited name so LRU tracking is independent
            if (!finalResult.addresses().isEmpty() && !visitedNames.isEmpty()) {
                long ttlMs = clampTtlMs(finalResult.minTtlSeconds() * 1000L);
                for (String target : visitedNames) {
                    CacheEntry perName = CacheEntry.positive(finalResult.addresses(), ttlMs);
                    putCache(target, perName);
                }
            }

            return CompletableFuture.completedFuture(finalResult);
        });
    }

    private static List<String> appendList(List<String> list, String item) {
        List<String> newList = new ArrayList<>(list.size() + 1);
        newList.addAll(list);
        newList.add(item);
        return Collections.unmodifiableList(newList);
    }

    // --- Failure classification ---

    private static boolean isNxDomain(Throwable t) {
        Throwable cur = unwrap(t);
        while (cur != null) {
            if (cur instanceof NxDomainException) return true;
            cur = cur.getCause();
        }
        return false;
    }

    private static long extractSoaMinimumTtl(Throwable t) {
        Throwable cur = unwrap(t);
        while (cur != null) {
            if (cur instanceof NxDomainException nxd) {
                return nxd.getSoaMinimumTtl();
            }
            cur = cur.getCause();
        }
        return -1;
    }

    private static Throwable unwrap(Throwable t) {
        while (t instanceof CompletionException && t.getCause() != null) {
            t = t.getCause();
        }
        return t;
    }

    // --- DoH resolution with endpoint failover ---

    private CompletableFuture<DohResult> resolveViaDohWithFailover(String host, String originalHost) {
        return tryEndpoint(host, originalHost, 0);
    }

    private CompletableFuture<DohResult> tryEndpoint(String host, String originalHost, int index) {

        if (index >= DOH_ENDPOINTS.size()) {
            return CompletableFuture.failedFuture(
                    new UnknownHostException("All DoH endpoints failed for: " + originalHost));
        }

        String endpoint = DOH_ENDPOINTS.get(index);

        CompletableFuture<DohResult> aFuture = dohRequest(host, originalHost, endpoint, DnsWireFormat.DNS_TYPE_A);
        CompletableFuture<DohResult> aaaaFuture = dohRequest(host, originalHost, endpoint, DnsWireFormat.DNS_TYPE_AAAA);

        return aFuture.thenCombine(aaaaFuture, (aResult, aaaaResult) -> {
                    if (aResult.nxDomain() != aaaaResult.nxDomain()
                            && (!aResult.addresses().isEmpty()
                                    || !aaaaResult.addresses().isEmpty())) {
                        logger.Warning(
                                "NXDOMAIN inconsistency for %s: one query type returned NXDOMAIN while the other returned addresses",
                                originalHost);
                    }
                    return aResult.merge(aaaaResult);
                })
                .thenCompose(merged -> {
                    // Fix #7: NXDOMAIN + addresses is
                    // contradictory; the name exists.
                    // Prefer the addresses.
                    if (merged.nxDomain() && !merged.addresses().isEmpty()) {
                        return CompletableFuture.completedFuture(merged);
                    }
                    if (merged.nxDomain()) {
                        return CompletableFuture.failedFuture(
                                new NxDomainException(originalHost, merged.soaMinimumTtl()));
                    }
                    if (!merged.addresses().isEmpty()) {
                        return CompletableFuture.completedFuture(merged);
                    }
                    if (merged.cnameTarget() != null) {
                        return CompletableFuture.completedFuture(merged);
                    }
                    if (merged.error() == null) {
                        return CompletableFuture.completedFuture(merged);
                    }
                    return tryEndpoint(host, originalHost, index + 1);
                });
    }

    // --- Single DoH request ---

    private CompletableFuture<DohResult> dohRequest(String host, String originalHost, String endpoint, int recordType) {
        return dohRequest0(host, originalHost, endpoint, recordType, SEMAPHORE_RETRIES);
    }

    /**
     * Semaphore acquisition is fully non-blocking.
     * On contention an async retry is scheduled on the
     * dedicated retry executor after a short delay,
     * preserving the calling thread's liveness.
     */
    private CompletableFuture<DohResult> dohRequest0(
            String host, String originalHost, String endpoint, int recordType, int retries) {

        if (closed.get()) {
            return CompletableFuture.failedFuture(new UnknownHostException("Resolver closed: " + host));
        }

        if (!requestSemaphore.tryAcquire()) {
            if (retries <= 0) {
                return CompletableFuture.failedFuture(
                        new UnknownHostException("DoH concurrency limit exceeded " + "for: " + host));
            }
            CompletableFuture<DohResult> retry = new CompletableFuture<>();
            // Fix #5: schedule on the dedicated retry
            // executor, not on the evictor. Check the
            // closed flag inside the scheduled task so
            // retries fail-fast after close().
            retryExecutor.schedule(
                    () -> {
                        if (closed.get()) {
                            retry.completeExceptionally(new UnknownHostException("Resolver closed: " + host));
                            return;
                        }
                        try {
                            dohRequest0(host, originalHost, endpoint, recordType, retries - 1)
                                    .whenComplete((r, e) -> {
                                        if (e != null) retry.completeExceptionally(e);
                                        else retry.complete(r);
                                    });
                        } catch (Exception e) {
                            retry.completeExceptionally(e);
                        }
                    },
                    SEMAPHORE_RETRY_MS,
                    TimeUnit.MILLISECONDS);
            return retry;
        }

        byte[] queryBytes = DnsWireFormat.buildDnsQuery(host, recordType, requestDnssecRecords);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(java.net.URI.create(endpoint))
                .header("Accept", "application/dns-message")
                .header("Content-Type", "application/dns-message")
                // .header("User-Agent", USER_AGENT)
                .timeout(DohUtils.REQUEST_TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofByteArray(queryBytes))
                .build();

        CompletableFuture<HttpResponse<byte[]>> httpFuture;
        try {
            httpFuture = httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (Exception e) {
            requestSemaphore.release();
            return CompletableFuture.failedFuture(e);
        }

        activeRequests.add(httpFuture);
        httpFuture.whenComplete((r, e) -> {
            activeRequests.remove(httpFuture);
            requestSemaphore.release();
        });

        return httpFuture
                .thenApply(response -> DnsWireFormat.parseDnsResponse(
                        host, originalHost,
                        response, recordType))
                .exceptionally(ex -> {
                    Throwable cause = unwrap(ex);
                    if (cause instanceof NxDomainException nxd) {
                        return DohResult.nxDomain(nxd.getSoaMinimumTtl());
                    }
                    return DohResult.error(cause);
                });
    }

    // --- Cache management ---

    private void putCache(String host, CacheEntry entry) {
        cache.put(host, entry);
        if (cache.size() > MAX_CACHE_SIZE) {
            evictToCapacity();
        }
    }

    /**
     * Best-effort LRU eviction. The snapshot nature of
     * {@link ConcurrentHashMap} iteration means an entry's
     * last-access time may have changed between sorting and
     * removal; this is acceptable for an approximate LRU
     * policy.
     */
    private void evictToCapacity() {
        cache.entrySet().removeIf(e -> e.getValue().isStaleExpired());

        if (cache.size() > MAX_CACHE_SIZE) {
            int excess = cache.size() - MAX_CACHE_SIZE;
            List<String> lru = cache.entrySet().stream()
                    .sorted((a, b) -> Long.compare(
                            a.getValue().lastAccessedAt.get(),
                            b.getValue().lastAccessedAt.get()))
                    .limit(excess)
                    .map(java.util.Map.Entry::getKey)
                    .toList();
            for (String key : lru) {
                cache.remove(key);
            }
        }
    }

    private void evictExpired() {
        cache.entrySet().removeIf(e -> e.getValue().isStaleExpired());
    }

    // --- Utility ---

    static long clampTtlMs(long ttlMs) {
        return Math.max(MIN_CACHE_TTL_MS, Math.min(ttlMs, MAX_CACHE_TTL_MS));
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new IllegalStateException("AdvancedResolver is closed");
        }
    }

    // --- Nested cache entry (fix #6: AtomicLong) ---

}
