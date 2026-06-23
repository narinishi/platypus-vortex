package com.platypus.proxy.logging;

import java.io.PrintStream;
import java.lang.StackWalker.StackFrame;
import java.text.MessageFormat;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

public class CondLogger extends Logger {

    enum LogLevel {
        CRITICAL(50),
        ERROR(40),
        WARNING(30),
        INFO(20),
        DEBUG(10);

        private final int level;
        final String shortName;

        LogLevel(int level) {
            this.level = level;
            this.shortName = devowel(name()).substring(0, 3);
        }

        private String devowel(String input) {
            return input.replaceAll("(?<=.)[AEIOU]", "");
        }

        public static LogLevel fromLevel(int level) {
            for (LogLevel l : values()) {
                if (l.level == level) {
                    return l;
                }
            }
            throw new IllegalArgumentException("No LogLevel for value: " + level);
        }
    }

    private final PrintStream delegate;
    private final ExecutorService executor;
    private final LogLevel level;

    private static DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss");

    @SuppressWarnings("unused")
    private final String name;

    public CondLogger(String name, int level) {
        this(System.out, name, level);
    }

    public CondLogger subdivide(String name) {
        return new CondLogger(this, name);
    }

    private CondLogger(CondLogger logger, String name) {
        this(logger.executor, logger.delegate, name, logger.level);
    }

    private CondLogger(ExecutorService executor, PrintStream delegate, String name, LogLevel level) {
        super(name, null);
        this.executor = executor;
        this.delegate = delegate;
        this.name = name;
        this.level = level;
    }

    private CondLogger(PrintStream delegate, String name, int level) {
        this(
                Executors.newSingleThreadExecutor(new ThreadFactory() {
                    private final AtomicInteger count = new AtomicInteger(0);

                    @Override
                    public Thread newThread(Runnable r) {
                        Thread t = new Thread(r, "cond-log-" + count.getAndIncrement());
                        t.setDaemon(true);
                        return t;
                    }
                }),
                delegate,
                name,
                LogLevel.fromLevel(level));
    }

    private boolean isLoggable(LogLevel desiredLevel) {
        return desiredLevel.level >= this.level.level;
    }

    private String format(String fmt, Object[] args) {
        if (args == null || args.length == 0) {
            return fmt;
        }
        try {
            return String.format(fmt, args);
        } catch (Exception e) {
            return fmt;
        }
    }

    public void Info(String s, Object... args) {
        log(LogLevel.INFO, format(s, args));
    }

    public void Error(String s, Object... args) {
        log(LogLevel.ERROR, format(s, args));
    }

    public void Warning(String s, Object... args) {
        log(LogLevel.WARNING, format(s, args));
    }

    public void Debug(String s, Object... args) {
        log(LogLevel.DEBUG, format(s, args));
    }

    public void Critical(String s, Object... args) {
        log(LogLevel.CRITICAL, format(s, args));
    }

    public void log(String level, String className, int lineNumber, String s, Object... args) {
        long rightNow = System.currentTimeMillis();
        String formatted = format(s, args);
        logWithTime(rightNow, LogLevel.valueOf(level), className, lineNumber, formatted);
    }

    private void logWithTime(long millis, LogLevel level, String className, int lineNumber, String msg) {

        executor.submit(() -> {
            Instant instant = Instant.ofEpochMilli(millis); // absolute point in time
            ZonedDateTime zdt = instant.atZone(ZoneId.systemDefault()); // local time
            String time = zdt.format(TIME_FORMATTER);

            if (!isLoggable(level)) {
                return;
            }

            delegate.println(time + " " + level.shortName + " " + msg + " (" + className + ":" + lineNumber + ")");
        });
    }

    /**
     * Graceful shutdown - waits for queued messages to drain.
     * Call this before JVM exit (e.g., in a shutdown hook).
     */
    public void shutdown() {
        shutdown(5, TimeUnit.SECONDS);
    }

    public void shutdown(long timeout, TimeUnit unit) {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(timeout, unit)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private void log(LogLevel level, String msg) {
        long millis = System.currentTimeMillis();
        log(level, msg, millis);
    }

    private void log(LogLevel level, String msg, long millis) {
        StackWalker walker = StackWalker.getInstance();

        String callerClassName = null;
        int callerLineNumber = -1;

        Optional<StackFrame> optionalFrame = walker.walk(frames -> frames.filter(frame -> {
                    String name = frame.getClassName();
                    return !name.startsWith("com.platypus.proxy.logging") && !name.startsWith("java.util.logging");
                })
                .findFirst());

        if (optionalFrame.isPresent()) {
            StackFrame frame = optionalFrame.get();
            String fullName = frame.getClassName();
            callerClassName = fullName.substring(fullName.lastIndexOf('.') + 1);
            callerLineNumber = frame.getLineNumber();
        }

        logWithTime(millis, level, callerClassName, callerLineNumber, msg);
    }

    @Override
    public void log(LogRecord record) {
        String formatted = MessageFormat.format(record.getMessage(), record.getParameters());
        log(LogLevel.INFO, formatted, record.getMillis());
    }
}
