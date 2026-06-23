package com.platypus.proxy.io;

import java.io.IOException;
import java.io.InputStream;

public class ReadUntilCloseInputStream extends InputStream {
    private final InputStream in;

    public ReadUntilCloseInputStream(InputStream in) {
        this.in = in;
    }

    @Override
    public int read() throws IOException {
        return in.read();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        return in.read(b, off, len);
    }

    @Override
    public void close() {}
}
