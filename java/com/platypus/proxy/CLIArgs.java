package com.platypus.proxy;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

// TODO: switch to custom logger

// NOTE: ideally the -list flags would not be boolean

/**
 * Command-line arguments for platypus-proxy.
 * Uses Java standard library only (no external CLI framework).
 *
 * <p>
 * Supported formats:
 * </p>
 * <ul>
 * <li>{@code -flag value} - space-separated</li>
 * <li>{@code --flag value} - double-dash (also accepted)</li>
 * <li>{@code -flag=value} - equals-sign assignment</li>
 * <li>For boolean flags an explicit {@code true / false} is always
 * required.</li>
 * </ul>
 */
public class CLIArgs {

    // TODO: move provider-specific defaults to providers

    private static final Set<String> ALLOWED_PROVIDERS = java.util.Set.of("warp");

    /**
     * Help entries stored as an array of [flag_syntax, description].
     * The description string can contain newline characters ('\n') to
     * indicate where subsequent lines should break.
     */
    private static final String[][] HELP_ENTRIES = {
        {"-help", "Show this help message and exit"},
        {"-version", "Show program version and exit"},
        {
            "-ext-ver string",
            "Extension version to mimic in requests.\nCan be obtained from:\nhttps://chrome.google.com/webstore/detail/hola-vpn-the-website-unbl/gkojfkhlekighikafcpjkiklfbnlmeio"
        },
        {"-country string", "Desired proxy location (default: 'us' for hola, 'EU' for opera)"},
        {"-list-countries bool", "List available countries and exit (e.g. -list-countries true)"},
        {"-list-proxies bool", "Output proxy list and exit (e.g. -list-proxies true)"},
        {
            "-test string",
            "Test proxy and exit. Values: 'ip'\n(fetch https://api.ipify.org?format=json),\n'file' (download 10MB from http://speedtest.tele2.net/10MB.zip)"
        },
        {"-limit int", "Amount of proxies in retrieved list (default: 3)"},
        {"-warp bool", "Enable standalone WARP forward proxy (port from --bind-address, mutually exclusive with --http2) (default: false)"},
        {"-bind-address string", "HTTP proxy listen address (default: '127.0.0.1:8080')"},
        {
            "-verbosity int",
            "Logging verbosity (10 - debug, 20 - info, 30 - warning,\n40 - error, 50 - critical) (default: 20)"
        },
        {
            "-timeout duration",
            "Timeout for network operations (e.g. 35s, 2m)\n(default: '35s' for hola, '10s' for opera)"
        },
        {"-rotate duration", "Rotate user ID once per given period (e.g. 48h, 7d) (default: '48h')"},
        {"-proxy-type string", "Proxy type: direct or lum (default: 'direct')"},
        {"-resolver strings", "Comma-separated list of DNS/DoH/DoT resolvers\n(default: https://1.1.1.3/dns-query,...)"
        },
        {"-dont-use-trial bool", "Use regular ports instead of trial ports (e.g. -dont-use-trial true)"},
        {
            "-proxy string",
            "Sets base proxy to use for all dial-outs.\nFormat: <http|https|socks5|socks5h>://[login:password@]host[:port]"
        },
        {"-cafile string", "Use custom CA certificate bundle file"},
        {
            "-user-agent string",
            "Value of User-Agent header in requests.\nDefault: Chrome for Windows (hola) or Opera for Windows (opera)"
        },
        {"-hide-SNI bool", "Hide SNI in TLS sessions with proxy server (default: true)"},
        {"-provider string", "Proxy provider: 'warp' (default: use --warp flag)"},
        {"-fake-sni string", "Domain name to use as SNI in communications with Opera servers"},
        {
            "-cache-extver bool",
            "Cache Chrome and extension versions in .extver file (default: true)\nSet to false to always fetch fresh values"
        },
        {
            "-direct-dns bool",
            "Resolve domain names directly via DoH (1.1.1.1, 8.8.8.8)\ninstead of relying on the proxy (default: false)"
        },
        {"-force-port-field string", "Force specific port field/num (e.g. 24232 or lum)"},
        {"-backoff-initial duration", "Initial average backoff delay for zgettunnels (e.g. 3s, 1m) (default: '3s')"},
        {"-backoff-deadline duration", "Total duration of zgettunnels method attempts (e.g. 5m, 1h) (default: '5m')"},
        {"-init-retries int", "Number of attempts for initialization steps, zero for unlimited retry (default: 0)"},
        {"-init-retry-interval duration", "Delay between initialization retries (e.g. 5s, 30s) (default: '5s')"},
        {"-accept-tos bool", "Skip Cloudflare Terms-of-Service interactive prompt (default: false)"}
    };

    // ---- Parsed flag values ----

    private String extVer = "";
    private String country = "us";
    private boolean http2 = false;
    private boolean warp = false;
    private boolean listCountries = false;
    private boolean listProxies = false;
    private String test = "";
    private int limit = 3;
    private String bindAddress = "127.0.0.1:8080";
    private int verbosity = 20;
    private String timeout = "35s";
    private String rotate = "48h";
    private String proxyType = "direct";
    private String[] resolver = new String[] {
        "https://1.1.1.3/dns-query",
        "https://8.8.8.8/dns-query",
        "https://dns.google/dns-query",
        "https://security.cloudflare-dns.com/dns-query",
        "https://fidelity.vm-0.com/q",
        "https://wikimedia-dns.org/dns-query",
        "https://dns.adguard-dns.com/dns-query",
        "https://dns.quad9.net/dns-query",
        "https://doh.cleanbrowsing.org/doh/adult-filter/"
    };
    private boolean dontUseTrial = false;
    private String outboundProxy = "";
    private String caFile = "";
    private String userAgent = null;
    private boolean hideSNI = true;
    private boolean cacheExtver = true;
    private String forcePortField = "";
    private String provider = "hola";
    private String fakeSNI = "";
    private String backoffInitial = "3s";
    private String backoffDeadline = "5m";
    private int initRetries = 0;
    private String initRetryInterval = "5s";
    private boolean directDns = false;
    private boolean acceptTos = false;

    // ---- Tracks which flags were explicitly set by the user ----
    private final Set<String> explicitlySet = new HashSet<>();

    private CLIArgs() {}

    // ==================== Error handling ====================

    private enum ErrorAction {
        NONE,
        SHOW_HELP,
        SHOW_USAGE
    }

    private static class ParseError extends RuntimeException {
        final ErrorAction action;

        ParseError(String message, ErrorAction action) {
            super(message);
            this.action = action;
        }
    }

    // ==================== Public API ====================

    /**
     * Parse command-line arguments using Java standard library.
     *
     * <p>
     * Supported formats:
     * </p>
     * <ul>
     * <li>{@code -flag value} - space-separated</li>
     * <li>{@code --flag value} - double-dash (also accepted)</li>
     * <li>{@code -flag=value} - equals-sign assignment</li>
     * <li>Boolean flags always require an explicit value (e.g.
     * {@code --cache-extver=false} or {@code --list-countries true}).</li>
     * </ul>
     *
     * @param args raw command-line arguments (typically from main())
     * @return parsed CLIArgs instance, or {@code null} if help/version
     *         was printed or an error occurred
     */
    public static CLIArgs parse(String[] args) {
        CLIArgs a = new CLIArgs();

        try {
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                if (arg.isEmpty()) continue;

                // Parse flag name and optional inline value (--flag=value)
                int eqIdx = arg.indexOf('=');
                String name;
                String inlineValue;
                if (eqIdx > 0) {
                    name = stripLeadingDashes(arg.substring(0, eqIdx));
                    inlineValue = arg.substring(eqIdx + 1);
                } else if (arg.startsWith("-")) {
                    name = stripLeadingDashes(arg);
                    inlineValue = null;
                } else {
                    throw new ParseError("Unexpected argument: " + arg, ErrorAction.SHOW_HELP);
                }

                // Help & version (no value required)
                if (isHelpFlag(name)) {
                    printHelp();
                    return null;
                }
                if (isVersionFlag(name)) {
                    printVersion();
                    return null;
                }

                // All other flags require a value: get it from inline or next arg
                String value = inlineValue;
                if (value == null) {
                    value = consumeNextArgValue(args, name, i);
                    if (value != null) i++;
                }

                if (!a.tryApplyFlag(name, value)) {
                    throw new ParseError("Unknown flag: " + name, ErrorAction.SHOW_HELP);
                }
            }

            a.applyOperaProviderDefaults();
            a.validate();

        } catch (ParseError e) {
            System.err.println(e.getMessage());
            switch (e.action) {
                case SHOW_HELP:
                    printHelp();
                    break;
                case SHOW_USAGE:
                    printUsage();
                    break;
                default:
                    break;
            }
            return null;
        }

        return a;
    }

    // ==================== Flag name helpers ====================

    private static String stripLeadingDashes(String s) {
        return s.replaceFirst("^-+", "");
    }

    private static boolean isHelpFlag(String name) {
        return "help".equals(name);
    }

    private static boolean isVersionFlag(String name) {
        return "version".equals(name);
    }

    private static void printVersion() {
        System.out.println("platypus-proxy version 1.0-SNAPSHOT");
    }

    /**
     * Consume the next argument as a flag value.
     * All flags that reach here require a value.
     */
    private static String consumeNextArgValue(String[] args, String flagName, int currentIndex) {
        if (currentIndex + 1 >= args.length || args[currentIndex + 1].startsWith("-")) {
            throw new ParseError("Flag '" + flagName + "' requires a value", ErrorAction.SHOW_HELP);
        }
        return args[currentIndex + 1];
    }

    // ==================== Flag application (all flags, including booleans)
    // ====================

    /**
     * Apply a flag and its (non-null) value. Returns {@code true} if the flag
     * is recognized, {@code false} otherwise.
     *
     * @throws ParseError if an integer or boolean value is invalid
     */
    private boolean tryApplyFlag(String name, String value) {
        switch (name) {
            // String flags
            case "ext-ver":
                extVer = value;
                return true;
            case "test":
                test = value;
                return true;
            case "country":
                country = value;
                explicitlySet.add("country");
                return true;
            case "bind-address":
                bindAddress = value;
                return true;
            case "timeout":
                timeout = value;
                explicitlySet.add("timeout");
                return true;
            case "rotate":
                rotate = value;
                return true;
            case "proxy-type":
                proxyType = value;
                return true;
            case "resolver":
                resolver = value.split(",");
                return true;
            case "proxy":
                outboundProxy = value;
                return true;
            case "cafile":
                caFile = value;
                return true;
            case "user-agent":
                userAgent = value;
                explicitlySet.add("user-agent");
                return true;
            case "provider":
                provider = value;
                return true;
            case "fake-sni":
                fakeSNI = value;
                return true;
            case "force-port-field":
                forcePortField = value;
                return true;
            case "backoff-initial":
                backoffInitial = value;
                return true;
            case "backoff-deadline":
                backoffDeadline = value;
                return true;
            case "init-retry-interval":
                initRetryInterval = value;
                return true;

            // Integer flags
            case "limit":
                limit = parseIntValue(value, "limit");
                return true;
            case "verbosity":
                verbosity = parseIntValue(value, "verbosity");
                return true;
            case "init-retries":
                initRetries = parseIntValue(value, "init-retries");
                return true;
            case "accept-tos":
                acceptTos = parseBooleanValueRequired(value, "accept-tos");
                return true;

            // Boolean flags (always require a value)
            case "warp":
                warp = parseBooleanValueRequired(value, "warp");
                return true;
            case "http2":
                http2 = parseBooleanValueRequired(value, "http2");
                return true;
            case "list-countries":
                listCountries = parseBooleanValueRequired(value, "list-countries");
                return true;
            case "list-proxies":
                listProxies = parseBooleanValueRequired(value, "list-proxies");
                return true;
            case "dont-use-trial":
                dontUseTrial = parseBooleanValueRequired(value, "dont-use-trial");
                return true;
            case "cache-extver":
                cacheExtver = parseBooleanValueRequired(value, "cache-extver");
                return true;
            case "hide-SNI":
                hideSNI = parseBooleanValueRequired(value, "hide-SNI");
                return true;
            case "direct-dns":
                directDns = parseBooleanValueRequired(value, "direct-dns");
                return true;

            default:
                return false;
        }
    }

    private static int parseIntValue(String value, String fieldName) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new ParseError("Invalid " + fieldName + " value: " + value, ErrorAction.NONE);
        }
    }

    /**
     * Parse a boolean value that must be provided explicitly.
     * Accepts "true"/"false" (case-insensitive) and "1"/"0".
     * Throws ParseError on any other value.
     */
    private static boolean parseBooleanValueRequired(String value, String flagName) {
        if ("true".equalsIgnoreCase(value) || "1".equals(value)) return true;
        if ("false".equalsIgnoreCase(value) || "0".equals(value)) return false;
        throw new ParseError(
                "Invalid value for '" + flagName + "': '" + value + "'. Must be boolean (true/false or 1/0).",
                ErrorAction.SHOW_HELP);
    }

    // ==================== Provider-specific defaults ====================

    private void applyOperaProviderDefaults() {
        if (!"opera".equals(provider)) return;

        if (!explicitlySet.contains("country")) {
            country = "EU";
        }
        if (!explicitlySet.contains("timeout")) {
            timeout = "10s";
        }
        if (!explicitlySet.contains("user-agent")) {
            // NOTE: reduce instances of user agent
            userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    + "AppleWebKit/537.36 (KHTML, like Gecko) "
                    + "Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0";
        }
    }

    // ==================== Validation ====================

    private void validate() {
        if (country.isEmpty()) {
            throw new ParseError("Country can't be empty string.", ErrorAction.SHOW_USAGE);
        }

        if (proxyType.isEmpty()) {
            throw new ParseError("Proxy type can't be an empty string.", ErrorAction.SHOW_USAGE);
        }

        if (listCountries && listProxies) {
            throw new ParseError(
                    "list-countries and list-proxies flags are mutually exclusive", ErrorAction.SHOW_USAGE);
        }

        if (!ALLOWED_PROVIDERS.contains(provider)) {
            throw new ParseError(
                    "Invalid provider: " + provider + ". Allowed: " + ALLOWED_PROVIDERS, ErrorAction.SHOW_USAGE);
        }

        if (!test.isEmpty() && !"ip".equals(test) && !"file".equals(test)) {
            throw new ParseError("Invalid test value: '" + test + "'. Must be 'ip' or 'file'.", ErrorAction.SHOW_HELP);
        }

        if ("hola_indirect".equals(provider) && (!outboundProxy.isEmpty())) {
            throw new ParseError("Provider 'hola_indirect' cannot be combined with --proxy.", ErrorAction.SHOW_USAGE);
        }
    }

    // ==================== Help / Usage output ====================

    public static void printHelp() {
        System.out.println("Usage: platypus-proxy [options]");
        System.out.println();
        System.out.println("platypus proxy client");
        System.out.println();
        printUsage();
    }

    private static void printUsage() {
        Arrays.sort(HELP_ENTRIES, (a, b) -> a[0].compareTo(b[0]));

        System.out.println("Options:");
        for (String[] entry : HELP_ENTRIES) {
            System.out.println("  " + entry[0]);

            String[] descLines = entry[1].split("\n");
            for (String line : descLines) {
                System.out.println("        " + line);
            }
        }
    }

    // ==================== Getters ====================

    public String getExtVer() {
        return extVer;
    }

    public String getCountry() {
        return country;
    }

    public boolean isListCountries() {
        return listCountries;
    }

    public boolean isListProxies() {
        return listProxies;
    }

    public String getTest() {
        return test;
    }

    public int getLimit() {
        return limit;
    }

    public String getBindAddress() {
        return bindAddress;
    }

    public int getVerbosity() {
        return verbosity;
    }

    public long getTimeoutMillis() {
        return parseDuration(timeout);
    }

    public long getRotateMillis() {
        return parseDuration(rotate);
    }

    public String getProxyType() {
        return proxyType;
    }

    public String[] getResolver() {
        return resolver;
    }

    public boolean isDontUseTrial() {
        return dontUseTrial;
    }

    public boolean useTrial() {
        return !dontUseTrial;
    }

    public String getOutboundProxy() {
        return outboundProxy;
    }

    public String getCaFile() {
        return caFile;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public boolean isHideSNI() {
        return hideSNI;
    }

    public boolean isCacheExtver() {
        return cacheExtver;
    }

    public String getForcePortField() {
        return forcePortField;
    }

    public String getProvider() {
        return provider;
    }

    public String getFakeSNI() {
        return fakeSNI;
    }

    public long getBackoffInitialMillis() {
        return parseDuration(backoffInitial);
    }

    public long getBackoffDeadlineMillis() {
        return parseDuration(backoffDeadline);
    }

    public int getInitRetries() {
        return initRetries;
    }

    public long getInitRetryIntervalMillis() {
        return parseDuration(initRetryInterval);
    }

    public boolean isDirectDns() {
        return directDns;
    }

    public boolean isAcceptTos() {
        return acceptTos;
    }

    public boolean useHttp2() {
        return http2;
    }

    public boolean useWarp() {
        return warp;
    }

    // ==================== Duration parsing ====================

    /**
     * Parse a duration string (e.g., "35s", "2m", "48h", "7d", "500ms")
     * into milliseconds. Matches Go's time.Duration parsing behavior.
     */
    private static long parseDuration(String duration) {
        if (duration == null || duration.isEmpty()) return 0;

        String value = duration;
        String unit = "";
        for (int i = 0; i < duration.length(); i++) {
            if (Character.isLetter(duration.charAt(i))) {
                value = duration.substring(0, i);
                unit = duration.substring(i).toLowerCase();
                break;
            }
        }
        long val;
        try {
            val = Long.parseLong(value);
        } catch (NumberFormatException e) {
            return 0;
        }
        switch (unit) {
            case "ms":
                return val;
            case "s":
                return val * 1000;
            case "m":
                return val * 60 * 1000;
            case "h":
                return val * 60 * 60 * 1000;
            case "d":
                return val * 24 * 60 * 60 * 1000;
            default:
                return val;
        }
    }
}
