package com.platypus.proxy.handler.h2;

import com.platypus.proxy.ProxyApplication;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.util.concurrent.ExecutorService;
import org.glassfish.grizzly.http2.frames.Http2Frame;
import org.glassfish.grizzly.http2.frames.SettingsFrame;

/**
 * Handles the h2c (cleartext) path.  After {@link H2cDetectionFilter}
 * detaches the raw socket, the preface bytes are fed here.
 *
 * <p>RFC 9113 §3.3 starting H2 with prior knowledge -- processes
 * cleartext connection preface and SETTINGS exchange.
 */
public class MitmHandlerH2c {

    public static void handleH2cConnection(H2ProxyService proxyService,
                                            InputStream rawIn,
                                            OutputStream rawOut,
                                            byte[] prefaceBytes) throws IOException {
        handleH2cConnection(proxyService, rawIn, rawOut, prefaceBytes, null);
    }

    public static void handleH2cConnection(H2ProxyService proxyService,
                                            InputStream rawIn,
                                            OutputStream rawOut,
                                            byte[] prefaceBytes,
                                            ExecutorService executor) throws IOException {
        InputStream combinedIn = new SequenceInputStream(
                new ByteArrayInputStream(prefaceBytes), rawIn);

        // Validate HTTP/2 client preface magic (24 bytes)
        byte[] magic = new byte[24];
        for (int off = 0; off < 24; ) {
            int n = combinedIn.read(magic, off, 24 - off);
            if (n < 0) throw new IOException("EOF reading client preface");
            off += n;
        }
        if (!java.util.Arrays.equals(magic, H2cDetectionFilter.HTTP2_MAGIC)) {
            throw new IOException("Invalid HTTP/2 connection preface");
        }

        InputStreamFrameSource source = new InputStreamFrameSource(combinedIn);

        // Read client SETTINGS frame (may be preceded by WINDOW_UPDATE etc.)
        Http2Frame frame = source.nextFrame();
        while (frame != null && frame.getStreamId() != 0) {
            ProxyApplication.getLogger().Debug("[h2c] Skipping frame on stream=%d", frame.getStreamId());
            frame = source.nextFrame();
        }
        if (!(frame instanceof SettingsFrame settings)) {
            throw new IOException("Expected client SETTINGS frame, got " + frame);
        }
        SettingsFrame clientSettings = settings;

        // Send server SETTINGS
        SettingsFrame serverSettings = SettingsFrame.builder()
                .setting(SettingsFrame.SETTINGS_HEADER_TABLE_SIZE, 4096)
                .setting(SettingsFrame.SETTINGS_ENABLE_PUSH, 0)
                .setting(SettingsFrame.SETTINGS_MAX_CONCURRENT_STREAMS, 100)
                .setting(SettingsFrame.SETTINGS_INITIAL_WINDOW_SIZE, 65535)
                .setting(SettingsFrame.SETTINGS_MAX_FRAME_SIZE, 16384)
                .build();
        writeFrame(rawOut, serverSettings);

        // ACK client settings
        writeFrame(rawOut, SettingsFrame.builder().setAck().build());

        // Create connection state (main loop will wait for client ACK)
        H2ConnectionState conn = new H2ConnectionState(proxyService, source, rawOut, clientSettings, executor);
        conn.mainLoop();
    }

    static void writeFrame(OutputStream out, Http2Frame frame) throws IOException {
        org.glassfish.grizzly.Buffer buf = frame.toBuffer(MitmHandler.MEM_MGR);
        byte[] bytes = new byte[buf.remaining()];
        buf.get(bytes);
        out.write(bytes);
        out.flush();
        buf.tryDispose();
    }
}
