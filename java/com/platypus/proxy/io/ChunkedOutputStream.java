package com.platypus.proxy.io;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * An {@link OutputStream} that wraps an underlying stream and applies HTTP/1.1
 * chunked transfer coding, as specified in RFC 7230 §4.1.
 *
 * <p>Every call to {@link #write(byte[], int, int)} produces a complete chunk:
 * <ul>
 *   <li>the size of the data in hexadecimal, followed by CRLF,</li>
 *   <li>the data bytes,</li>
 *   <li>and a trailing CRLF.</li>
 * </ul>
 * The {@link #close()} method sends the final zero-length chunk (the terminating
 * sequence {@code 0\r\n\r\n}) and then closes this wrapper, but <b>does not</b>
 * close the underlying stream - that responsibility remains with the caller.
 * The underlying stream is flushed after every chunk to ensure timely delivery.
 *
 * <p>This class is used in the MITM request loop to re-chunk a decoded response
 * body when the upstream response carried a {@code Transfer-Encoding: chunked}
 * header.  Without it, the decoded (raw) body would be sent following the
 * chunked header, causing client protocol errors.
 */
public class ChunkedOutputStream extends OutputStream {

    private final OutputStream out;
    private boolean closed;

    /**
     * @param out the underlying output stream (e.g. the inner TLS stream).
     */
    public ChunkedOutputStream(OutputStream out) {
        this.out = out;
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[] {(byte) b}, 0, 1);
    }

    /**
     * Writes a single chunk.  If {@code len} is zero, no data is sent.
     *
     * @param b   the byte array
     * @param off start offset in the array
     * @param len number of bytes to write
     * @throws IOException if the underlying write or flush fails
     */
    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (closed) {
            throw new IOException("Stream closed");
        }
        if (len == 0) {
            return;
        }

        // ---- Write chunk header: hexadecimal length + CRLF ----
        String sizeHex = Integer.toHexString(len);
        out.write(sizeHex.getBytes(StandardCharsets.US_ASCII));
        out.write('\r');
        out.write('\n');

        // ---- Write chunk data ----
        out.write(b, off, len);

        // ---- Write chunk trailer: CRLF ----
        out.write('\r');
        out.write('\n');

        // Ensure the chunk is sent immediately
        out.flush();
    }

    /**
     * Writes the terminating zero-size chunk and flushes, then marks this
     * stream as closed.  The underlying stream remains open.
     */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;

        // Zero-length chunk ending the stream
        out.write('0');
        out.write('\r');
        out.write('\n');
        out.write('\r');
        out.write('\n');
        out.flush();

        // We intentionally do NOT close the underlying stream; the caller
        // (the MITM loop) manages it.
    }
}
