package com.platypus.proxy.handler.h2;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.http2.Http2Session;
import org.glassfish.grizzly.http2.Http2Stream;
import org.glassfish.grizzly.http2.frames.DataFrame;
import org.glassfish.grizzly.http2.frames.WindowUpdateFrame;
import org.glassfish.grizzly.memory.MemoryManager;

// RFC 9113 §8.5 CONNECT -- tunnel over single H2 stream; DATA frames carry tunnel bytes (§6.1)
// Flow control per RFC 9113 §5.2 -- WINDOW_UPDATE frames sent when threshold exceeded
public class H2StreamTunnel implements ReadableByteChannel, WritableByteChannel {

    private static final int WINDOW_UPDATE_THRESHOLD = 65535 / 2;
    private static final MemoryManager<?> memMgr = MemoryManager.DEFAULT_MEMORY_MANAGER;

    private final Http2Session session;
    private final Http2Stream stream;
    private final int streamId;

    private final BlockingQueue<ByteBuffer> readQueue = new LinkedBlockingQueue<>();
    private long readWindowConsumed = 0;
    private long connectionReadConsumed = 0;
    private volatile boolean readEnded = false;
    private volatile boolean closed = false;

    public H2StreamTunnel(Http2Session session, Http2Stream stream) {
        this.session = session;
        this.stream = stream;
        this.streamId = stream.getId();
    }

    public void onDataFrame(ByteBuffer payload) {
        if (closed) return;
        readQueue.add(payload);
        long len = payload.remaining();
        readWindowConsumed += len;
        connectionReadConsumed += len;
    }

    public void onEndStream() {
        readEnded = true;
        readQueue.add(ByteBuffer.allocate(0));
    }

    public void onWindowUpdate(int increment) {
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
        if (closed) return -1;
        try {
            ByteBuffer data;
            if (readEnded && readQueue.isEmpty()) return -1;
            data = readQueue.take();
            if (!data.hasRemaining() && readEnded && readQueue.isEmpty()) return -1;
            int len = Math.min(dst.remaining(), data.remaining());
            if (len > 0) {
                int oldLimit = data.limit();
                data.limit(data.position() + len);
                dst.put(data);
                data.limit(oldLimit);
            }
            if (data.hasRemaining()) readQueue.add(data);
            maybeSendReceiveWindowUpdate();
            return len;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while reading from stream", e);
        }
    }

    @Override
    public boolean isOpen() { return !closed; }

    @Override
    public int write(ByteBuffer src) throws IOException {
        if (closed) throw new IOException("Tunnel closed");
        if (!src.hasRemaining()) return 0;

        int toWrite = src.remaining();
        byte[] bytes = new byte[toWrite];
        src.get(bytes);
        Buffer dataBuf = memMgr.allocate(toWrite);
        dataBuf.put(bytes);
        dataBuf.flip();

        H2MitmServerFilter.writeFrame(session, DataFrame.builder()
                .streamId(streamId)
                .data(dataBuf)
                .endStream(false)
                .build());
        return toWrite;
    }

    public int writeCompletely(ByteBuffer src) throws IOException {
        int total = 0;
        while (src.hasRemaining()) {
            int written = write(src);
            if (written <= 0) throw new IOException("Write returned " + written);
            total += written;
        }
        return total;
    }

    @Override
    public void close() {
        if (closed) return;
        closed = true;
        try {
            H2MitmServerFilter.writeFrame(session, DataFrame.builder()
                    .streamId(streamId)
                    .endStream(true)
                    .build());
        } catch (Exception ignored) { }
        readQueue.clear();
        readEnded = true;
    }

    private void maybeSendReceiveWindowUpdate() {
        if (readWindowConsumed >= WINDOW_UPDATE_THRESHOLD) {
            emitWindowUpdate(streamId, (int) readWindowConsumed);
            readWindowConsumed = 0;
        }
        if (connectionReadConsumed >= WINDOW_UPDATE_THRESHOLD) {
            emitWindowUpdate(0, (int) connectionReadConsumed);
            connectionReadConsumed = 0;
        }
    }

    private void emitWindowUpdate(int streamId, int increment) {
        H2MitmServerFilter.writeFrame(session, WindowUpdateFrame.builder()
                .streamId(streamId)
                .windowSizeIncrement(increment)
                .build());
    }
}
