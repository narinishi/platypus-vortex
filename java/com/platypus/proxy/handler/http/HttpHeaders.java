package com.platypus.proxy.handler.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.nio.charset.StandardCharsets;

public final class HttpHeaders {
    private HttpHeaders() {}

    /* terrible shouldn't exist */
    @Deprecated
    public static String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int prev = -1;
        while (true) {
            int b = in.read();
            if (b == -1) {
                if (sb.length() == 0 && prev == -1) return null; // true EOF at start
                if (prev == '\r') {
                    // EOF right after \r without \n - include it as-is
                    break;
                }
                break;
            }
            if (prev == '\r' && b == '\n') {
                // Found CRLF - strip the \r we already appended and return
                sb.setLength(sb.length() - 1);
                return sb.toString();
            }
            if (b != '\n') {
                sb.append((char) b);
            } else {
                // Bare LF without preceding CR - treat as line ending
                return sb.toString();
            }
            prev = b;
        }
        return sb.toString();
    }

    /**
     * Consumes exactly the HTTP response headers (including the trailing
     * \r\n\r\n) and returns the first line (status line). When this method
     * returns the PushbackInputStream is positioned at the first byte of the
     * body - no tunnel data is lost.
     */
    public static String consumeHeadersAndReadStatusLine(PushbackInputStream in) throws IOException {
        ByteArrayOutputStream headerBuf = new ByteArrayOutputStream();
        int prev = -1;
        boolean headersDone = false;

        while (!headersDone) {
            int b = in.read();
            if (b == -1) return null;
            headerBuf.write(b);
            if (b == '\n' && prev == '\r') {
                byte[] data = headerBuf.toByteArray();
                int len = data.length;
                if (len >= 4
                        && data[len - 4] == '\r'
                        && data[len - 3] == '\n'
                        && data[len - 2] == '\r'
                        && data[len - 1] == '\n') {
                    headersDone = true;
                }
            }
            prev = b;
        }

        byte[] headerBytes = headerBuf.toByteArray();
        // extract the very first line
        int lineEnd = 0;
        while (lineEnd < headerBytes.length && headerBytes[lineEnd] != '\r') {
            lineEnd++;
        }
        return new String(headerBytes, 0, lineEnd, StandardCharsets.US_ASCII);
    }
}
