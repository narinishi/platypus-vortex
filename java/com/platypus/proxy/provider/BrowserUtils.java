package com.platypus.proxy.provider;

import com.google.gson.Gson;
import com.platypus.proxy.handler.TlsHelper;
import com.platypus.proxy.io.TcpConnector;
import com.platypus.proxy.io.TunnelConnection;
import java.io.*;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Utility class that fetches the latest Chrome version and the latest
 * extension version for a given VPN provider.
 *
 * <p>All HTTP requests go through the provided {@link TcpConnector}, which
 * may be configured to use an outbound proxy.  Responses are cached in a
 * local JSON file with a configurable TTL.
 */
public class BrowserUtils {

    // NOTE: reduce instances of user agent
    private static final String DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            + "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

    private static final long DEFAULT_CACHE_TTL_MS = 24 * 60 * 60 * 1000L;
    private static final Path DEFAULT_CACHE_FILE = Paths.get(".platypus-providers.json");

    private final TcpConnector connector;
    private final String userAgent;
    private final Path cacheFile;
    private final long cacheTtlMs;
    private final Gson gson = new Gson();

    /**
     * Creates an instance with default user agent, default cache file
     * ({@code browser_info.json}) and default TTL (24 hours).
     */
    public BrowserUtils(TcpConnector connector) {
        this(connector, DEFAULT_USER_AGENT, DEFAULT_CACHE_FILE, DEFAULT_CACHE_TTL_MS);
    }

    /**
     * Full constructor allowing full customisation.
     */
    public BrowserUtils(TcpConnector connector, String userAgent, Path cacheFile, long cacheTtlMs) {
        this.connector = Objects.requireNonNull(connector);
        this.userAgent = userAgent != null ? userAgent : DEFAULT_USER_AGENT;
        this.cacheFile = cacheFile != null ? cacheFile : DEFAULT_CACHE_FILE;
        this.cacheTtlMs = cacheTtlMs > 0 ? cacheTtlMs : DEFAULT_CACHE_TTL_MS;
    }

    // -----------------------------------------------------------------
    //  Cache data structures
    // -----------------------------------------------------------------

    private static class CacheData {
        String chromeVersion;
        long chromeTimestamp; // epoch millis
        Map<String, ProviderEntry> providers = new HashMap<>();
    }

    private static class ProviderEntry {
        String extensionVersion;
        long extensionTimestamp; // epoch millis
        Map<String, String> properties = new HashMap<>();
    }

    // -----------------------------------------------------------------
    //  File I/O (load / save) - instance methods using this.cacheFile
    // -----------------------------------------------------------------

    private CacheData loadCache() {
        if (!Files.exists(cacheFile)) {
            return new CacheData();
        }
        try {
            String json = new String(Files.readAllBytes(cacheFile), StandardCharsets.UTF_8);
            return gson.fromJson(json, CacheData.class);
        } catch (Exception e) {
            // corrupted file -> start fresh
            return new CacheData();
        }
    }

    private void saveCache(CacheData data) {
        try {
            String json = gson.toJson(data);
            Files.write(
                    cacheFile,
                    json.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException ignored) {
            // non-fatal; caching is best-effort
        }
    }

    // -----------------------------------------------------------------
    //  Public API
    // -----------------------------------------------------------------

    /**
     * Returns the latest stable Chrome version, fetching it if the cache is
     * missing or stale.
     *
     * @throws IOException if the network request fails
     */
    public String getChromeVersion() throws IOException {
        CacheData cache = loadCache();

        // use cache if still fresh
        if (cache.chromeVersion != null && System.currentTimeMillis() - cache.chromeTimestamp <= cacheTtlMs) {
            return cache.chromeVersion;
        }

        // fetch
        String version = fetchChromeVersion();

        // update and persist
        cache.chromeVersion = version;
        cache.chromeTimestamp = System.currentTimeMillis();
        saveCache(cache);
        return version;
    }

    /**
     * Returns the latest version of the extension with the given
     * {@code extensionId}, stored under the {@code provider} name.
     *
     * @param provider    logical name of the VPN provider (e.g. "hola")
     * @param extensionId Chrome Web Store extension ID
     * @param prodVersion the Chrome version to send in the update check;
     *                    if {@code null} or empty, the latest Chrome version
     *                    will be fetched automatically.
     * @throws IOException if the network request fails or parsing fails
     */
    public String getExtensionVersion(String provider, String extensionId, String prodVersion) throws IOException {
        CacheData cache = loadCache();
        ProviderEntry entry = cache.providers.get(provider);

        // use cache if fresh
        if (entry != null
                && entry.extensionVersion != null
                && System.currentTimeMillis() - entry.extensionTimestamp <= cacheTtlMs) {
            return entry.extensionVersion;
        }

        if (prodVersion == null || prodVersion.isEmpty()) {
            prodVersion = getChromeVersion(); // may hit cache or fetch
        }

        String extVer = fetchExtensionVersion(extensionId, prodVersion);

        // update cache
        entry = cache.providers.computeIfAbsent(provider, k -> new ProviderEntry());
        entry.extensionVersion = extVer;
        entry.extensionTimestamp = System.currentTimeMillis();
        saveCache(cache);
        return extVer;
    }

    /**
     * Stores an arbitrary string value inside the provider's object.
     * Persisted immediately to the cache file.
     */
    public void setProviderProperty(String provider, String key, String value) {
        CacheData cache = loadCache();
        ProviderEntry entry = cache.providers.computeIfAbsent(provider, k -> new ProviderEntry());
        entry.properties.put(key, value);
        saveCache(cache);
    }

    /**
     * Returns a previously stored property, or {@code null} if the key
     * (or the provider) does not exist.
     */
    public String getProviderProperty(String provider, String key) {
        CacheData cache = loadCache();
        ProviderEntry entry = cache.providers.get(provider);
        return entry != null ? entry.properties.get(key) : null;
    }

    // -----------------------------------------------------------------
    //  Internal HTTP helper - now delegates to ProviderUtils
    // -----------------------------------------------------------------

    /**
     * Performs a GET request over TLS via the {@link TcpConnector},
     * decodes the body, and returns the raw bytes.
     * @param browserUtils
     */
    private static byte[] executeGet(BrowserUtils browserUtils, String urlStr) throws IOException {
        URL url = URI.create(urlStr).toURL();
        String host = url.getHost();
        int port = url.getPort() > 0 ? url.getPort() : 443;

        // build request path
        String path = url.getPath();
        if (url.getQuery() != null) {
            path += "?" + url.getQuery();
        }
        if (path.isEmpty()) {
            path = "/";
        }

        // headers required for a GET to the Chrome Web Store / version API
        Map<String, String> reqHeaders = new LinkedHashMap<>();
        reqHeaders.put("User-Agent", browserUtils.userAgent);
        reqHeaders.put("Accept", "*/*");
        reqHeaders.put("Accept-Encoding", "gzip, deflate");

        byte[] requestHead = ProviderUtils.buildRequestHead("GET", path, host, reqHeaders, -1);

        TunnelConnection dialerConn = browserUtils.connector.connect("tcp", host + ":" + port);
        try {
            Socket socket = TlsHelper.wrap(dialerConn.socket(), host, false);
            OutputStream out = socket.getOutputStream();
            out.write(requestHead);
            out.flush();

            InputStream in = socket.getInputStream();
            ProviderUtils.HttpResponseWithBody httpResp = ProviderUtils.readHttpResponse(in);
            if (httpResp == null) {
                throw new IOException("empty or malformed HTTP response");
            }

            // lower-case header keys for reliable lookups
            ProviderUtils.lowerCaseHeaders(httpResp.headers());

            if (httpResp.statusCode() != 200) {
                byte[] errorBody = ProviderUtils.readAllBytes(httpResp.bodyStream());
                throw new IOException("Bad HTTP status " + httpResp.statusCode() + ": "
                        + (errorBody.length > 0 ? new String(errorBody, StandardCharsets.UTF_8) : ""));
            }

            return ProviderUtils.decodeBody(httpResp, true);
        } finally {
            dialerConn.close();
        }
    }

    // -----------------------------------------------------------------
    //  Chrome version fetch
    // -----------------------------------------------------------------

    private String fetchChromeVersion() throws IOException {
        String urlStr = "https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/"
                + "versions?alt=json&orderBy=version+desc&pageSize=1&prettyPrint=false";
        byte[] respBytes = BrowserUtils.executeGet(this, urlStr);
        String json = new String(respBytes, StandardCharsets.UTF_8);
        GoogleVersionResponse resp = gson.fromJson(json, GoogleVersionResponse.class);
        if (resp.versions != null && !resp.versions.isEmpty()) {
            return resp.versions.get(0).version;
        }
        throw new IOException("No version found in Chrome version API response");
    }

    @SuppressWarnings("unused")
    private static class GoogleVersionResponse {
        List<VersionItem> versions;
    }

    @SuppressWarnings("unused")
    private static class VersionItem {
        String version;
    }

    // -----------------------------------------------------------------
    //  Extension version fetch
    // -----------------------------------------------------------------

    private String fetchExtensionVersion(String extensionId, String prodVersion) throws IOException {
        // Ensure version has at least major.minor
        if (!prodVersion.contains(".")) {
            prodVersion += ".0";
        }

        String encodedX = URLEncoder.encode("id=" + extensionId + "&uc=", "UTF-8");
        String urlStr = "https://clients2.google.com/service/update2/crx"
                + "?prodversion=" + URLEncoder.encode(prodVersion, "UTF-8")
                + "&acceptformat=crx2,crx3"
                + "&x=" + encodedX;

        byte[] respBytes = BrowserUtils.executeGet(this, urlStr);
        String xml = new String(respBytes, StandardCharsets.UTF_8);
        return parseExtensionVersionXml(xml);
    }

    /**
     * Minimal XML parsing - extracts the {@code version} attribute from
     * the {@code <updatecheck>} element.
     */
    private static String parseExtensionVersionXml(String xml) throws IOException {
        try {
            javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(new org.xml.sax.InputSource(new StringReader(xml)));

            org.w3c.dom.Element root = doc.getDocumentElement();
            if (root == null) throw new IOException("empty XML");
            if (!"gupdate".equals(root.getTagName())) {
                root = getChildElement(root, "gupdate");
                if (root == null) throw new IOException("no gupdate element");
            }
            org.w3c.dom.Element app = getChildElement(root, "app");
            if (app == null) throw new IOException("no app element");
            org.w3c.dom.Element updatecheck = getChildElement(app, "updatecheck");
            if (updatecheck == null) throw new IOException("no updatecheck element");
            String version = updatecheck.getAttribute("version");
            if (version != null && !version.isEmpty()) return version;
            throw new IOException("no version attribute in updatecheck");
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to parse Chrome Web Store response", e);
        }
    }

    private static org.w3c.dom.Element getChildElement(org.w3c.dom.Element parent, String tagName) {
        org.w3c.dom.NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            org.w3c.dom.Node node = children.item(i);
            if (node instanceof org.w3c.dom.Element && tagName.equals(node.getNodeName())) {
                return (org.w3c.dom.Element) node;
            }
        }
        return null;
    }
}
