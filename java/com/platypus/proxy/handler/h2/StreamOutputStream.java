package com.platypus.proxy.handler.h2;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.http2.frames.DataFrame;
import org.glassfish.grizzly.memory.MemoryManager;

/**
 * OutputStream that writes DATA frames to an HTTP/2 stream with flow
 * control.  Used by the CONNECT MITM tunnel inner TLS path as the
 * transport that carries encrypted bytes from the inner SSLEngine
 * back to the outer HTTP/2 client.
 *
 * <p>RFC 9113 §6.1 DATA frames -- each write chunks payload into
 * flow-controlled DATA frames back to the H2 client.
 */
class StreamOutputStream extends OutputStream implements WritableByteChannel {

    private static final MemoryManager<?> MEM_MGR = MemoryManager.DEFAULT_MEMORY_MANAGER;

    private final int streamId;
    private final H2ConnectionState conn;
    private volatile boolean closed;

    StreamOutputStream(int streamId, H2ConnectionState conn) {
        this.streamId = streamId;
        this.conn = conn;
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[]{(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] buf, int off, int len) throws IOException {
        if (closed) throw new IOException("Stream closed");
        if (len == 0) return;
        conn.sendDataFrame(streamId, buf, len, false);
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
        if (closed) throw new IOException("Stream closed");
        if (!src.hasRemaining()) return 0;
        int toWrite = src.remaining();
        byte[] bytes = new byte[toWrite];
        src.get(bytes);
        conn.sendDataFrame(streamId, bytes, toWrite, false);
        return toWrite;
    }

    @Override
    public boolean isOpen() {
        return !closed;
    }

    public void flush() {
    }

    @Override
    public void close() {
        if (closed) return;
        closed = true;
        try {
            conn.sendDataFrame(streamId, new byte[0], 0, true);
        } catch (IOException ignored) {
        }
    }

    @SuppressWarnings("unused")
    private void writeRawData(byte[] bytes) throws IOException {
        Buffer dataBuf = MEM_MGR.allocate(bytes.length);
        dataBuf.put(bytes);
        dataBuf.flip();
        DataFrame df = DataFrame.builder()
                .streamId(streamId)
                .data(dataBuf)
                .endStream(false)
                .build();
        conn.writeFrame(df);
    }
}
