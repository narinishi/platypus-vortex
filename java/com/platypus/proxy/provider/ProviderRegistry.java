package com.platypus.proxy.provider;

import java.util.Locale;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public enum ProviderRegistry {
    DUMMY(() -> { throw new UnsupportedOperationException("Not yet implemented"); });

    // NON-LEAK: WARP is NOT registered here — handled as standalone mode
    //           directly by ProxyApplication via WarpProvider.

    private final Supplier<ProxyProvider> factory;

    ProviderRegistry(Supplier<ProxyProvider> factory) {
        this.factory = factory;
    }

    public ProxyProvider create() {
        return factory.get();
    }

    public String configName() {
        return name().toLowerCase(Locale.ROOT);
    }

    public static ProviderRegistry fromConfigName(String name) {
        for (ProviderRegistry t : values()) {
            if (t.configName().equals(name)) {
                return t;
            }
        }
        return null;
    }

    public static Set<String> allowedNames() {
        return java.util.Arrays.stream(values()).map(ProviderRegistry::configName).collect(Collectors.toUnmodifiableSet());
    }
}
