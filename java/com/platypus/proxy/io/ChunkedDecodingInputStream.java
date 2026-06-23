package com.platypus.proxy.io;

import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * Decodes HTTP chunked transfer encoding (RFC 7230 §4.1).
 * Correctly handles chunk extensions and trailers.
 * The read(byte[], int, int) method reads as many bytes as possible
 * from the current chunk.
 */
public class ChunkedDecodingInputStream extends InputStream {
    private final InputStream in;
    private long chunkRemaining = 0;
    private boolean eof = false;
    private boolean needCrLf = false;

    public ChunkedDecodingInputStream(InputStream in) {
        this.in = in;
    }

    @Override
    public int read() throws IOException {
        if (eof) return -1;

        if (needCrLf) {
            skipCrLf();
            needCrLf = false;
        }

        if (chunkRemaining == 0) {
            readChunkHeader();
            if (eof) return -1;
        }

        int b = in.read();
        if (b == -1) {
            eof = true;
            return -1;
        }
        chunkRemaining--;

        if (chunkRemaining == 0) {
            needCrLf = true;
        }
        return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (eof) return -1;
        if (len == 0) return 0;

        if (needCrLf) {
            skipCrLf();
            needCrLf = false;
        }

        if (chunkRemaining == 0) {
            readChunkHeader();
            if (eof) return -1;
        }

        int toRead = (int) Math.min(len, chunkRemaining);
        int n = in.read(b, off, toRead);
        if (n <= 0) {
            eof = true;
            return -1;
        }
        chunkRemaining -= n;

        if (chunkRemaining == 0) {
            needCrLf = true;
        }
        return n;
    }

    private void readChunkHeader() throws IOException {
        String line = readLine(in);
        if (line == null) {
            eof = true;
            return;
        }
        int semi = line.indexOf(';');
        String hex = (semi >= 0) ? line.substring(0, semi).trim() : line.trim();
        try {
            chunkRemaining = Long.parseLong(hex, 16);
        } catch (NumberFormatException e) {
            throw new IOException("Invalid chunk size: " + hex, e);
        }
        if (chunkRemaining == 0) {
            eof = true;
            // Consume trailers (if any)
            while (true) {
                String trailer = readLine(in);
                if (trailer == null || trailer.isEmpty()) break;
            }
        }
    }

    private void skipCrLf() throws IOException {
        int cr = in.read();
        int lf = in.read();
        if (cr == -1 || lf == -1) throw new IOException("Truncated chunk: missing CRLF");
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(64);
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                String s = buf.toString(StandardCharsets.US_ASCII.name());
                // Remove trailing \r if present
                if (s.endsWith("\r")) s = s.substring(0, s.length() - 1);
                return s;
            }
            buf.write(b);
        }
        if (buf.size() == 0) return null;
        return buf.toString(StandardCharsets.US_ASCII.name());
    }
}
