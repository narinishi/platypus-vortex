package com.platypus.proxy.handler.h2;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * InputStream backed by a queue of DATA frame payloads for a single
 * HTTP/2 stream.  Bytes are fed by {@link H2ConnectionState#handleData}
 * and consumed by the MITM tunnel worker.
 *
 * <p>RFC 9113 §6.1 DATA frames -- payload flows through this queue
 * to the CONNECT tunnel inner TLS handshake.
 */
class StreamInputStream extends InputStream {

    private final BlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
    private byte[] current;
    private int currentOffset;
    private volatile boolean closed;
    private volatile boolean ended;

    void feed(byte[] data) {
        if (closed) return;
        queue.offer(data);
    }

    void feedEnd() {
        ended = true;
        queue.offer(new byte[0]);
    }

    @Override
    public int read() throws IOException {
        byte[] b = new byte[1];
        int n = read(b, 0, 1);
        return n == -1 ? -1 : b[0] & 0xFF;
    }

    @Override
    public int read(byte[] buf, int off, int len) throws IOException {
        if (closed) return -1;
        if (len == 0) return 0;

        try {
            if (current == null || currentOffset >= current.length) {
                current = null;
                currentOffset = 0;
                if (ended && queue.isEmpty()) return -1;
                current = queue.take();
                if (current.length == 0) {
                    ended = true;
                    return -1;
                }
            }

            int toRead = Math.min(len, current.length - currentOffset);
            System.arraycopy(current, currentOffset, buf, off, toRead);
            currentOffset += toRead;
            return toRead;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted reading from stream", e);
        }
    }

    @Override
    public int available() throws IOException {
        if (current != null && currentOffset < current.length) {
            return current.length - currentOffset;
        }
        return queue.size() > 0 ? 1 : 0;
    }

    @Override
    public void close() {
        closed = true;
        queue.clear();
    }
}
