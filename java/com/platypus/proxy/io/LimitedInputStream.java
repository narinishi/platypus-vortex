package com.platypus.proxy.io;

import java.io.IOException;
import java.io.InputStream;

// == Utility classes =========================================
public class LimitedInputStream extends InputStream {
    private final InputStream in;
    private long remaining;

    public LimitedInputStream(InputStream in, long len) {
        this.in = in;
        this.remaining = len;
    }

    @Override
    public int read() throws IOException {
        if (remaining <= 0) return -1;
        int b = in.read();
        if (b >= 0) remaining--;
        return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (remaining <= 0) return -1;
        int toRead = (int) Math.min(len, remaining);
        int n = in.read(b, off, toRead);
        if (n > 0) remaining -= n;
        return n;
    }
}
