package com.platypus.proxy.handler;

import com.platypus.proxy.logging.CondLogger;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

/**
 * Utility for executing an action with retries and delays.
 * The old {@code RetryDialer} logic is now encapsulated here.
 * Uses {@link Thread#sleep} for simplicity (virtual threads make this safe).
 */
public final class HostRetryExecutor {

    private HostRetryExecutor() {}

    /**
     * Execute the given action up to {@code maxAttempts} times,
     * waiting {@code delayMs} milliseconds between attempts.
     * The action should return {@code true} if successful.
     *
     * @param name        a descriptive name for logging
     * @param maxAttempts maximum number of tries (including the first)
     * @param delayMs     sleep between retries (0 for no delay)
     * @param logger      may be null (will skip logging)
     * @param action      the task to execute; must return {@code true} on success
     * @return {@code true} if the action succeeded, {@code false} after all
     *         attempts fail
     */
    public static boolean execute(
            String name, int maxAttempts, long delayMs, CondLogger logger, Callable<Boolean> action) {
        for (int i = 1; i <= maxAttempts; i++) {
            if (i > 1 && delayMs > 0) {
                try {
                    TimeUnit.MILLISECONDS.sleep(delayMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            if (logger != null) {
                logger.Info("Attempting '%s' (try %d/%d)", name, i, maxAttempts);
            }
            try {
                if (Boolean.TRUE.equals(action.call())) {
                    return true;
                }
            } catch (Exception e) {
                if (logger != null) {
                    logger.Warning("Attempt %d of '%s' failed: %s", i, name, e.getMessage());
                }
            }
        }
        return false;
    }
}
