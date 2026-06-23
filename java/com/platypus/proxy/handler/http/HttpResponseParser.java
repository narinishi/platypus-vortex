// ResponseParser.java - cleaned of unused field
package com.platypus.proxy.handler.http;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class HttpResponseParser {
    private final InputStream in;
    private final int maxHeaderSize;

    private byte[] headerBuffer;
    private int headerEndOffset;
    private boolean parsed;
    private String statusLine;
    private Map<String, List<String>> headers;

    public HttpResponseParser(InputStream in, int maxHeaderSize) {
        this.in = in;
        this.maxHeaderSize = maxHeaderSize;
    }

    public void parse() throws IOException {
        if (parsed) return;

        ByteArrayOutputStream buf = new ByteArrayOutputStream(512);
        byte[] marker = "\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
        int totalRead = 0;
        boolean done = false;

        byte[] chunk = new byte[Math.min(maxHeaderSize, 8192)];
        while (totalRead < maxHeaderSize && !done) {
            int n = in.read(chunk, 0, Math.min(chunk.length, maxHeaderSize - totalRead));
            if (n == -1) {
                if (totalRead == 0) throw new IOException("Unexpected EOF before headers");
                break;
            }
            totalRead += n;
            buf.write(chunk, 0, n);

            byte[] data = buf.toByteArray();
            int searchStart = Math.max(0, data.length - n - 3);
            for (int i = searchStart; i <= data.length - 4; i++) {
                if (data[i] == marker[0]
                        && data[i + 1] == marker[1]
                        && data[i + 2] == marker[2]
                        && data[i + 3] == marker[3]) {
                    headerEndOffset = i + 4;
                    done = true;
                    break;
                }
            }
        }

        if (!done) {
            headerEndOffset = totalRead;
        }

        headerBuffer = buf.toByteArray();
        parseStatusAndHeaders();
        parsed = true;
    }

    public int getStatusCode() {
        if (!parsed) throw new IllegalStateException("Not parsed");
        String[] parts = statusLine.split(" ", 3);
        if (parts.length >= 2) {
            try {
                return Integer.parseInt(parts[1]);
            } catch (NumberFormatException e) {
            }
        }
        throw new IllegalStateException("Invalid status line: " + statusLine);
    }

    public Map<String, List<String>> getHeaders() {
        if (!parsed) throw new IllegalStateException("Not parsed");
        return headers;
    }

    public InputStream getBodyStream() {
        if (!parsed) throw new IllegalStateException("Not parsed");
        int leftoverLen = headerBuffer.length - headerEndOffset;
        if (leftoverLen == 0) return in;
        if (in instanceof PushbackInputStream pbin) {
            byte[] leftover = Arrays.copyOfRange(headerBuffer, headerEndOffset, headerBuffer.length);
            try {
                pbin.unread(leftover);
                headerEndOffset = headerBuffer.length;
                return in;
            } catch (IOException e) {
                // pushback buffer too small, fall back
            }
        }
        byte[] leftover = Arrays.copyOfRange(headerBuffer, headerEndOffset, headerBuffer.length);
        return new SequenceInputStream(new ByteArrayInputStream(leftover), in);
    }

    /**
     * Return the bytes that were read past the header terminator
     * ({@code \r\n\r\n}) during parsing, or null if there are none.
     * These bytes belong to the response body (or, for bodyless
     * responses like 204/304/HEAD, to the next response on a
     * keep-alive connection) and must be preserved for connection reuse.
     */
    public byte[] getLeftoverBytes() {
        if (!parsed) throw new IllegalStateException("Not parsed");
        int leftoverLen = headerBuffer.length - headerEndOffset;
        if (leftoverLen == 0) return null;
        return Arrays.copyOfRange(headerBuffer, headerEndOffset, headerBuffer.length);
    }

    private void parseStatusAndHeaders() {
        String headerBlock = new String(headerBuffer, 0, headerEndOffset, StandardCharsets.US_ASCII);
        String[] lines = headerBlock.split("\r\n", -1);
        if (lines.length == 0) throw new IllegalStateException("Empty header block");

        statusLine = lines[0];
        headers = new LinkedHashMap<>();

        String currentName = null; // header we are currently building
        for (int i = 1; i < lines.length && !lines[i].isEmpty(); i++) {
            String line = lines[i];

            // Check for obs-fold: line starts with SP or HT
            if (!line.isEmpty() && (line.charAt(0) == ' ' || line.charAt(0) == '\t')) {
                if (currentName == null) {
                    // Folded line without a previous header - ignore or treat as malformed
                    continue;
                }
                // Append folded value to the last entry, trimming only the leading whitespace
                String continuation = line.stripLeading(); // removes only leading whitespace
                // Add as another value for the same header name
                headers.get(currentName).add(continuation);
            } else {
                // Normal header line
                int colon = line.indexOf(':');
                if (colon > 0) {
                    currentName = line.substring(0, colon).trim();
                    String value = line.substring(colon + 1).trim();
                    headers.computeIfAbsent(currentName, k -> new ArrayList<>()).add(value);
                } else {
                    // Invalid header line without colon - ignore or handle as needed
                    currentName = null;
                }
            }
        }
    }
}
