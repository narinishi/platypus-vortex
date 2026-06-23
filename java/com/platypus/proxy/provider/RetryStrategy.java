package com.platypus.proxy.provider;

import com.platypus.proxy.logging.CondLogger;
import java.util.function.Function;

/**
 * Synchronous retry strategy - all logger calls come from this class.
 */
public class RetryStrategy {

    /**
     * Returns a two-stage function: first bind the name, then apply the action.
     */
    public static Function<String, Function<Runnable, Exception>> create(
            int retries, long retryIntervalMs, CondLogger logger) {
        return name -> action -> retryLoop(name, retries, retryIntervalMs, logger, action);
    }

    /**
     * Convenience method - immediately executes the action with retries.
     */
    public static Exception execute(
            String name, int retries, long retryIntervalMs, CondLogger logger, Runnable action) {
        return retryLoop(name, retries, retryIntervalMs, logger, action);
    }

    // ------------------------------------------------------------------
    // The actual retry loop - all logger calls live here, so the logger
    // always sees RetryStrategy as the calling class.
    // ------------------------------------------------------------------
    private static Exception retryLoop(
            String name, int retries, long retryIntervalMs, CondLogger logger, Runnable action) {
        Exception lastError = null;
        int maxAttempts = retries <= 0 ? 10 : retries;

        for (int i = 1; i <= maxAttempts; i++) {
            // Log "Retrying..." only once, before the first delayed retry
            if (i > 1 && retryIntervalMs > 0 && i == 2) {
                logger.Warning("Retrying action '%s' in %d ms...", name, retryIntervalMs);
            }
            if (i > 1 && retryIntervalMs > 0) {
                try {
                    Thread.sleep(retryIntervalMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return e;
                }
            }

            logger.Info("Attempting action '%s', attempt #%d...", name, i);
            try {
                action.run();
                logger.Info("Action '%s' succeeded on attempt #%d", name, i);
                return null;
            } catch (Exception e) {
                lastError = e;
                logger.Warning("Action '%s' failed: %s", name, e.getMessage());
            }
        }

        logger.Critical(
                "All attempts for action '%s' have failed. Last error: %s",
                name, lastError != null ? lastError.getMessage() : "unknown");
        return lastError;
    }
}
