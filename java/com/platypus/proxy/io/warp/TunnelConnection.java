package com.platypus.proxy.io.warp;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

public class TunnelConnection implements AutoCloseable {
    private final Socket socket;
    private final InputStream inputStream;
    private final OutputStream outputStream;
    private final Consumer<Socket> closer;
    private final Runnable streamCloser;
    private final Runnable readAborter;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    public TunnelConnection(Socket socket, InputStream inputStream) {
        this(socket, inputStream, null, null);
    }

    public TunnelConnection(Socket socket, InputStream inputStream, Consumer<Socket> closer) {
        this.socket = socket;
        this.inputStream = inputStream;
        this.outputStream = null;
        this.closer = closer;
        this.streamCloser = null;
        this.readAborter = null;
    }

    public TunnelConnection(Socket socket, InputStream inputStream, OutputStream outputStream, Consumer<Socket> closer) {
        this.socket = socket;
        this.inputStream = inputStream;
        this.outputStream = outputStream;
        this.closer = closer;
        this.streamCloser = null;
        this.readAborter = null;
    }

    public static TunnelConnection streamBased(InputStream inputStream, OutputStream outputStream, Runnable streamCloser) {
        return new TunnelConnection(inputStream, outputStream, streamCloser, null);
    }

    public static TunnelConnection streamBased(InputStream inputStream, OutputStream outputStream, Runnable streamCloser, Runnable readAborter) {
        return new TunnelConnection(inputStream, outputStream, streamCloser, readAborter);
    }

    private TunnelConnection(InputStream inputStream, OutputStream outputStream, Runnable streamCloser, Runnable readAborter) {
        this.socket = null;
        this.inputStream = inputStream;
        this.outputStream = outputStream;
        this.closer = null;
        this.streamCloser = streamCloser;
        this.readAborter = readAborter;
    }

    public void abortRead() {
        if (readAborter != null) readAborter.run();
    }

    public Socket socket() {
        if (socket == null) {
            throw new UnsupportedOperationException("stream-based TunnelConnection has no socket");
        }
        return socket;
    }

    public boolean hasSocket() {
        return socket != null;
    }

    public InputStream inputStream() {
        return inputStream;
    }

    public OutputStream outputStream() {
        if (outputStream != null) return outputStream;
        if (socket != null) {
            try {
                return socket.getOutputStream();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        throw new UnsupportedOperationException("no output stream available");
    }

    public boolean isOpen() {
        return !closed.get();
    }

    @Override
    public void close() {
        closed.set(true);
        if (streamCloser != null) {
            streamCloser.run();
        }
        if (closer != null && socket != null) {
            closer.accept(socket);
        }
        if (socket != null) {
            try {
                socket.close();
            } catch (Exception ignored) {
            }
        }
    }
}
