package com.platypus.proxy.handler.h2;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.http2.frames.ContinuationFrame;
import org.glassfish.grizzly.http2.frames.DataFrame;
import org.glassfish.grizzly.http2.frames.GoAwayFrame;
import org.glassfish.grizzly.http2.frames.HeadersFrame;
import org.glassfish.grizzly.http2.frames.Http2Frame;
import org.glassfish.grizzly.http2.frames.PingFrame;
import org.glassfish.grizzly.http2.frames.PriorityFrame;
import org.glassfish.grizzly.http2.frames.RstStreamFrame;
import org.glassfish.grizzly.http2.frames.SettingsFrame;
import org.glassfish.grizzly.http2.frames.WindowUpdateFrame;
import org.glassfish.grizzly.memory.MemoryManager;

/**
 * Reads HTTP/2 frames from a blocking {@link InputStream}.  Used by
 * the inner h2 MITM handler to parse frames from the decrypted inner
 * TLS stream ({@link InnerInputStream}).
 *
 * <p>Frame parsing follows <b>RFC 9113 §4.1 (Frame Format)</b>: a
 * 9-octet header (24-bit length, 8-bit type, 8-bit flags, 1-bit
 * reserved + 31-bit stream identifier) followed by the payload.
 * Frame types dispatched: DATA (§6.1), HEADERS (§6.2), PRIORITY
 * (§6.3, deprecated per §5.3.2), RST_STREAM (§6.4), SETTINGS
 * (§6.5), PING (§6.7), GOAWAY (§6.8), WINDOW_UPDATE (§6.9),
 * CONTINUATION (§6.10).  Per §4.2 frames exceeding the peer's
 * SETTINGS_MAX_FRAME_SIZE (§6.5.2) trigger a FRAME_SIZE_ERROR.
 */
class InputStreamFrameSource {

    private static final MemoryManager<?> MEM_MGR = MemoryManager.DEFAULT_MEMORY_MANAGER;

    private final DataInputStream dataIn;
    private final int maxFrameSize;

    InputStreamFrameSource(InputStream in) {
        this(in, 16384);
    }

    InputStreamFrameSource(InputStream in, int maxFrameSize) {
        this.dataIn = new DataInputStream(in);
        this.maxFrameSize = maxFrameSize <= 0 ? Integer.MAX_VALUE : maxFrameSize;
    }

    Http2Frame nextFrame() throws IOException {
        byte[] header = new byte[9];
        dataIn.readFully(header);

        int length = ((header[0] & 0xFF) << 16) | ((header[1] & 0xFF) << 8) | (header[2] & 0xFF);
        int type = header[3] & 0xFF;
        int flags = header[4] & 0xFF;
        int streamId = ((header[5] & 0x7F) << 24)
                | ((header[6] & 0xFF) << 16)
                | ((header[7] & 0xFF) << 8)
                | (header[8] & 0xFF);

        if (length > maxFrameSize && type != DataFrame.TYPE) {
            throw new IOException("Frame size " + length + " exceeds max " + maxFrameSize);
        }

        byte[] payload = new byte[length];
        if (length > 0) dataIn.readFully(payload);

        Buffer gBuffer = wrap(payload);
        switch (type) {
            case DataFrame.TYPE:
                return DataFrame.fromBuffer(flags, streamId, gBuffer);
            case HeadersFrame.TYPE:
                return HeadersFrame.fromBuffer(flags, streamId, gBuffer);
            case PriorityFrame.TYPE:
                return PriorityFrame.fromBuffer(streamId, gBuffer);
            case RstStreamFrame.TYPE:
                return RstStreamFrame.fromBuffer(flags, streamId, gBuffer);
            case SettingsFrame.TYPE:
                return SettingsFrame.fromBuffer(flags, streamId, gBuffer);
            case PingFrame.TYPE:
                return PingFrame.fromBuffer(flags, streamId, gBuffer);
            case GoAwayFrame.TYPE:
                return GoAwayFrame.fromBuffer(streamId, gBuffer);
            case WindowUpdateFrame.TYPE:
                return WindowUpdateFrame.fromBuffer(flags, streamId, gBuffer);
            case ContinuationFrame.TYPE:
                return ContinuationFrame.fromBuffer(flags, streamId, gBuffer);
            default:
                throw new IOException("Unsupported frame type: 0x" + Integer.toHexString(type));
        }
    }

    private static Buffer wrap(byte[] data) {
        Buffer buffer = MEM_MGR.allocate(data.length);
        buffer.put(data);
        buffer.flip();
        return buffer;
    }
}
