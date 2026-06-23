package com.platypus.proxy.resolver;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

public class FastResolver implements LookupNetIP {
    private static final long RESOLVER_TIMEOUT_MS = 5000;

    private final List<LookupNetIP> upstreams;

    public FastResolver(LookupNetIP... upstreams) {
        this.upstreams = List.of(upstreams);
    }

    @Override
    public List<InetAddress> lookup(String host) throws UnknownHostException {
        if (upstreams.isEmpty()) {
            return fallbackLookup(host);
        }

        ExecutorService executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "fast-resolver");
            t.setDaemon(true);
            return t;
        });

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<List<InetAddress>> winner = new AtomicReference<>();
        List<Future<?>> futures = new ArrayList<>();

        for (LookupNetIP upstream : upstreams) {
            futures.add(executor.submit(() -> {
                try {
                    List<InetAddress> result = upstream.lookup(host);
                    if (result != null && !result.isEmpty() && winner.compareAndSet(null, result)) {
                        latch.countDown();
                    }
                } catch (UnknownHostException e) {
                    // ignore - other resolvers may succeed
                }
            }));
        }

        try {
            latch.await(RESOLVER_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ignored) {
        }

        executor.shutdownNow();

        List<InetAddress> result = winner.get();
        if (result != null) {
            return result;
        }
        return fallbackLookup(host);
    }

    private List<InetAddress> fallbackLookup(String host) throws UnknownHostException {
        InetAddress[] addrs = InetAddress.getAllByName(host);
        return List.of(addrs);
    }
}
