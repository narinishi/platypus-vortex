package com.platypus.proxy.provider;

import com.platypus.proxy.handler.TlsHelper;
import com.platypus.proxy.io.ChunkedDecodingInputStream;
import com.platypus.proxy.io.LimitedInputStream;
import com.platypus.proxy.io.TcpConnector;
import com.platypus.proxy.io.TunnelConnection;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

/**
 * Centralised helper for low-level HTTP operations used by all providers.
 * <p>
 * Provides methods for building raw request head bytes, sending a request
 * through a {@link TcpConnector} / TLS connection, parsing the response with
 * header-only reading, and decoding the body (handling chunked transfer coding,
 * content-length, and optional gzip/deflate decompression).
 * <p>
 * Providers should use these methods instead of manually managing sockets and
 * raw byte handling in order to reduce duplication and potential subtle errors.
 */
public class ProviderUtils {

    // ===================================================================
    //  Existing response record and HTTP header parser
    // ===================================================================

    public record HttpResponseWithBody(
            String statusLine, int statusCode, Map<String, List<String>> headers, InputStream bodyStream) {}

    /**
     * Parses HTTP response headers without consuming any body bytes.
     * Returns a fully populated {@link HttpResponseWithBody} whose {@code bodyStream}
     * gives an {@link InputStream} positioned exactly after the headers.
     */
    public static HttpResponseWithBody readHttpResponse(InputStream in) throws IOException {
        ByteArrayOutputStream headerBuf = new ByteArrayOutputStream();
        int totalRead = 0;
        int headerEnd = -1;
        int prev = -1;

        while (true) {
            int b = in.read();
            if (b == -1) break;
            headerBuf.write(b);
            totalRead++;
            if (b == '\n' && prev == '\r') {
                // possible header terminator - check last 4 bytes
                if (totalRead >= 4) {
                    byte[] data = headerBuf.toByteArray();
                    int len = data.length;
                    if (data[len - 4] == '\r'
                            && data[len - 3] == '\n'
                            && data[len - 2] == '\r'
                            && data[len - 1] == '\n') {
                        headerEnd = len;
                        break;
                    }
                }
            }
            prev = b;
        }
        if (headerEnd < 0) {
            return null; // no complete header found
        }

        byte[] headerBytes = headerBuf.toByteArray();
        // The body stream: leftover bytes (if any) past headerEnd, then the rest of 'in'
        InputStream bodyStream;
        int leftoverLen = headerBytes.length - headerEnd;
        if (leftoverLen > 0) {
            byte[] leftover = Arrays.copyOfRange(headerBytes, headerEnd, headerBytes.length);
            bodyStream = new SequenceInputStream(new ByteArrayInputStream(leftover), in);
        } else {
            bodyStream = in;
        }

        // Parse the header block
        String headerBlock = new String(headerBytes, 0, headerEnd, StandardCharsets.US_ASCII);
        String[] lines = headerBlock.split("\r\n", -1);
        if (lines.length == 0) return null;
        String statusLine = lines[0];
        int statusCode = parseStatusCode(statusLine);
        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) continue; // the empty line before body
            int colon = line.indexOf(':');
            if (colon > 0) {
                String name = line.substring(0, colon).trim();
                String value = line.substring(colon + 1).trim();
                headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
            }
        }
        return new HttpResponseWithBody(statusLine, statusCode, headers, bodyStream);
    }

    private static int parseStatusCode(String statusLine) {
        String[] parts = statusLine.split(" ", 3);
        if (parts.length >= 2) {
            try {
                return Integer.parseInt(parts[1]);
            } catch (NumberFormatException ignored) {
            }
        }
        return -1;
    }

    // ===================================================================
    //  New helper methods
    // ===================================================================

    /**
     * Reads all bytes from the given stream and returns them as a byte array.
     * The stream is not closed by this method.
     */
    public static byte[] readAllBytes(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    /**
     * Converts all header names to lower case (the map is mutated).
     * Used to make lookups case-insensitive.
     */
    public static void lowerCaseHeaders(Map<String, List<String>> headers) {
        List<Map.Entry<String, List<String>>> entries = new ArrayList<>(headers.entrySet());
        headers.clear();
        for (Map.Entry<String, List<String>> e : entries) {
            headers.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue());
        }
    }

    /**
     * Constructs the head of an HTTP/1.1 request as a byte array.
     * The returned bytes contain the request line and all headers,
     * terminated by the empty line ({@code \r\n\r\n}).
     *
     * @param method       HTTP method (GET, POST, etc.)
     * @param requestPath  path and query string (e.g. "/api/v1/test")
     * @param host         value for the Host header
     * @param headers      additional headers (may be {@code null}); the map values
     *                     are used directly
     * @param bodyLength   length of the body that will follow, or -1 if no body
     * @return the header bytes ready to be written to an OutputStream
     */
    public static byte[] buildRequestHead(
            String method, String requestPath, String host, Map<String, String> headers, int bodyLength) {
        StringBuilder sb = new StringBuilder(512);
        sb.append(method).append(' ').append(requestPath).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(host).append("\r\n");
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                sb.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
            }
        }
        if (bodyLength >= 0) {
            sb.append("Content-Length: ").append(bodyLength).append("\r\n");
        }
        sb.append("Connection: close\r\n");
        sb.append("\r\n");
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Sends a complete HTTP request via a TcpConnector, optionally over TLS,
     * and returns the fully decoded response body.
     * <p>
     * Handles the entire lifecycle: connect, TLS wrap, write request head and body,
     * parse response, verify status is in the 2xx range, decode the body
     * (transfer coding, content-length, optional decompression), and close the
     * connection.
     *
     * @param connector   used to open the underlying TCP connection
     * @param host        remote host (used for Host header and TLS SNI)
     * @param port        remote port
     * @param requestHead the raw header bytes (see {@link #buildRequestHead})
     * @param body        the request body bytes, or {@code null} for none
     * @param timeoutMs   socket read timeout in milliseconds; 0 means no timeout
     * @param useTls      if {@code true}, a TLS handshake is performed
     *                    (via {@link TlsHelper#wrap}) with {@code host} as the SNI
     * @param decompress  if {@code true}, Content-Encoding gzip/deflate is
     *                    transparently decompressed
     * @return the decoded response body bytes
     * @throws IOException if any network error occurs or the status code is not 2xx
     */
    public static byte[] sendRequest(
            TcpConnector connector,
            String host,
            int port,
            byte[] requestHead,
            byte[] body,
            long timeoutMs,
            boolean useTls,
            boolean decompress)
            throws IOException {
        TunnelConnection conn = connector.connect("tcp", host + ":" + port);
        try {
            Socket socket = conn.socket();
            if (useTls) {
                socket = TlsHelper.wrap(socket, host, false);
            }
            if (timeoutMs > 0) {
                socket.setSoTimeout((int) timeoutMs);
            }

            OutputStream out = socket.getOutputStream();
            out.write(requestHead);
            if (body != null && body.length > 0) {
                out.write(body);
            }
            out.flush();

            HttpResponseWithBody httpResp = readHttpResponse(socket.getInputStream());
            if (httpResp == null) {
                throw new IOException("Empty or malformed HTTP response");
            }

            // Check status
            int status = httpResp.statusCode();
            if (status < 200 || status >= 300) {
                // Read the error body for a meaningful message
                try (InputStream errStream = httpResp.bodyStream()) {
                    byte[] errBody = readAllBytes(errStream);
                    throw new IOException("HTTP " + status + " " + httpResp.statusLine()
                            + (errBody.length > 0 ? ": " + new String(errBody, StandardCharsets.UTF_8) : ""));
                }
            }

            // Decode body
            return decodeBody(httpResp, decompress);
        } finally {
            conn.close();
        }
    }

    /**
     * Decodes the response body from an {@link HttpResponseWithBody}, optionally
     * decompressing it.
     * <p>
     * Applies chunked transfer coding (or content-length limiting) first,
     * then, if {@code decompress} is {@code true}, wraps the stream with
     * gzip / deflate decompressors when the {@code Content-Encoding} header
     * indicates such compression.
     *
     * @param response    the parsed HTTP response (header names must be
     *                    lower-case for reliable lookup)
     * @param decompress  whether to handle {@code Content-Encoding: gzip} / {@code deflate}
     * @return all body bytes
     * @throws IOException if reading the stream fails
     */
    public static byte[] decodeBody(HttpResponseWithBody response, boolean decompress) throws IOException {
        InputStream stream = response.bodyStream();
        Map<String, List<String>> headers = response.headers();

        // Transfer-Encoding
        List<String> teValues = headers.get("transfer-encoding");
        boolean chunked = teValues != null
                && teValues.stream().anyMatch(v -> v.toLowerCase(Locale.ROOT).contains("chunked"));

        // Content-Length
        long contentLength = -1;
        List<String> clValues = headers.get("content-length");
        if (clValues != null && !clValues.isEmpty()) {
            try {
                contentLength = Long.parseLong(clValues.get(0));
            } catch (NumberFormatException ignored) {
            }
        }

        if (chunked) {
            stream = new ChunkedDecodingInputStream(stream);
        } else if (contentLength >= 0) {
            stream = new LimitedInputStream(stream, contentLength);
        }

        // Decompress if requested
        if (decompress) {
            List<String> ceValues = headers.get("content-encoding");
            boolean gzip = ceValues != null
                    && ceValues.stream()
                            .anyMatch(v -> v.toLowerCase(Locale.ROOT).contains("gzip"));
            boolean deflate = ceValues != null
                    && ceValues.stream()
                            .anyMatch(v -> v.toLowerCase(Locale.ROOT).contains("deflate"));

            if (gzip) {
                stream = new GZIPInputStream(stream);
            } else if (deflate) {
                stream = new InflaterInputStream(stream);
            }
        }

        return readAllBytes(stream);
    }

    /**
     * Serialises a parsed header map back into its raw HTTP wire form
     * (CRLF-separated {@code Name: Value} lines, no terminating blank
     * line). Useful for logging the response headers exactly as they
     * were received.
     *
     * @param headers header map (e.g. from {@link HttpResponseWithBody#headers()})
     * @return the serialised header block
     */
    public static String serializeHeaders(Map<String, List<String>> headers) {
        StringBuilder sb = new StringBuilder(256);
        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
            String name = e.getKey();
            for (String v : e.getValue()) {
                if (v == null) continue;
                sb.append(name).append(": ").append(v).append("\r\n");
            }
        }
        return sb.toString();
    }

    /**
     * Reads up to {@code byteLimit} decoded bytes from the response body,
     * applying chunked or content-length transfer decoding as appropriate.
     * The decoded stream is read with a hard cap of {@code byteLimit} so
     * that a malicious or unexpectedly large response cannot exhaust
     * memory.
     *
     * <p>For chunked responses the decoder is left in an indeterminate
     * state if the cap is hit before the terminating chunk; this is fine
     * for error paths where the connection will be discarded immediately.
     *
     * <p>Header names in {@code response.headers()} are expected to be
     * lower-case (call {@link #lowerCaseHeaders(Map)} first if unsure).
     *
     * @param response  the parsed HTTP response
     * @param byteLimit maximum number of decoded body bytes to return;
     *                  values {@code <= 0} return an empty array
     * @return the decoded body bytes (length &le; {@code byteLimit})
     * @throws IOException if reading fails
     */
    public static byte[] readBodyBytes(HttpResponseWithBody response, int byteLimit) throws IOException {
        if (byteLimit <= 0) return new byte[0];
        InputStream stream = response.bodyStream();
        Map<String, List<String>> headers = response.headers();

        List<String> teValues = headers.get("transfer-encoding");
        boolean chunked = teValues != null
                && teValues.stream()
                        .anyMatch(v -> v != null && v.toLowerCase(Locale.ROOT).contains("chunked"));

        long contentLength = -1;
        List<String> clValues = headers.get("content-length");
        if (clValues != null && !clValues.isEmpty()) {
            try {
                contentLength = Long.parseLong(clValues.get(0));
            } catch (NumberFormatException ignored) {
            }
        }

        if (chunked) {
            stream = new ChunkedDecodingInputStream(stream);
        } else if (contentLength >= 0) {
            stream = new LimitedInputStream(stream, Math.min(contentLength, byteLimit));
        } else {
            stream = new LimitedInputStream(stream, byteLimit);
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream(Math.min(byteLimit, 8192));
        byte[] buf = new byte[8192];
        int remaining = byteLimit;
        while (remaining > 0) {
            int toRead = Math.min(remaining, buf.length);
            int read = stream.read(buf, 0, toRead);
            if (read < 0) break;
            bos.write(buf, 0, read);
            remaining -= read;
        }
        return bos.toByteArray();
    }

    /**
     * Reads up to {@code byteLimit} decoded bytes from the response body
     * and returns them as a UTF-8 string. See {@link #readBodyBytes} for
     * transfer-coding and cap semantics.
     */
    public static String readBodyText(HttpResponseWithBody response, int byteLimit) throws IOException {
        byte[] body = readBodyBytes(response, byteLimit);
        return new String(body, StandardCharsets.UTF_8);
    }
}
