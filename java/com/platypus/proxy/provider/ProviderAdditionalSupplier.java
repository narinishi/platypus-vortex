package com.platypus.proxy.provider;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

/**
 * A {@link Supplier}{@code <String>} that holds a primary string and an
 * ordered list of additional strings.
 */
public final class ProviderAdditionalSupplier implements Supplier<String> {

    private final String primary;
    private final List<String> additional = new CopyOnWriteArrayList<>();

    public ProviderAdditionalSupplier(String primary) {
        this.primary = Objects.requireNonNull(primary, "primary must not be null");
    }

    @Override
    public String get() {
        return primary;
    }

    public void registerAdditional(String... additions) {
        Objects.requireNonNull(additions, "additions array must not be null");
        additional.addAll(Arrays.asList(additions));
    }

    public void appendAdditionalTo(StringBuilder sb) {
        Objects.requireNonNull(sb, "StringBuilder must not be null");
        for (String s : additional) {
            sb.append(s);
        }
    }

    public List<String> getAdditional() {
        return List.copyOf(additional);
    }
}
