package com.platypus.proxy.handler.h2;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.http2.Http2Session;
import org.glassfish.grizzly.http2.frames.Http2Frame;

/**
 * Dedicated thread that serialises HTTP/2 frames and writes the raw
 * bytes directly to the {@link SocketChannel} of the Grizzly connection,
 * <b>completely bypassing the filter chain</b>.
 *
 * <p>RFC 9113 §4.1 frame format -- 9-octet header + variable-length payload.
 */
class H2FrameWriter implements Closeable {
    private final BlockingQueue<Runnable> queue = new LinkedBlockingQueue<>();
    private final Thread thread;
    private final SocketChannel channel;

    private static final ConcurrentHashMap<SocketChannel, H2FrameWriter> WRITERS =
            new ConcurrentHashMap<>();

    H2FrameWriter(String name, SocketChannel channel) {
        this.channel = channel;
        thread = new Thread(
                () -> {
                    while (true) {
                        try {
                            Runnable task = queue.take();
                            task.run();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                },
                name);
        thread.setDaemon(true);
        thread.start();
    }

    void submit(Runnable task) {
        queue.offer(task);
    }

    /**
     * Serialises the frame and writes the bytes to the raw channel.
     */
    void writeFrame(Http2Session session, Http2Frame frame) {
        submit(() -> {
            try {
                Buffer buf = frame.toBuffer(session.getMemoryManager());
                if (buf != null && buf.remaining() > 0) {
                    doWrite(buf);
                }
            } catch (Exception ignore) {
                // Grizzly already logs write errors; we suppress further throwing
            }
        });
    }

    /**
     * Writes an already-serialised frame buffer directly to the channel.
     */
    void writeRawBuffer(Buffer buffer) {
        if (buffer == null || buffer.remaining() == 0) return;
        Buffer dup = buffer.duplicate();
        submit(() -> {
            try {
                doWrite(dup);
            } catch (Exception e) {
                // ignore
            } finally {
                dup.tryDispose();
            }
        });
    }

    private void doWrite(Buffer buf) throws IOException {
        ByteBuffer nioBuf = buf.toByteBuffer();
        try {
            channel.configureBlocking(true);
            while (nioBuf.hasRemaining()) {
                channel.write(nioBuf);
            }
        } finally {
            channel.configureBlocking(false);
            buf.tryDispose();
        }
    }

    /**
     * Retrieves or creates the per-channel writer thread.
     */
    static H2FrameWriter getOrCreate(SocketChannel channel) {
        return WRITERS.computeIfAbsent(channel,
                ch -> new H2FrameWriter("h2-writer-" + ch.socket().getRemoteSocketAddress(), ch));
    }

    @Override
    public void close() {
        thread.interrupt();
        WRITERS.remove(channel);
    }
}
