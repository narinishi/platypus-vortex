package com.platypus.proxy.provider.warp;

import tech.kwik.core.QuicConnection;
import tech.kwik.flupke.HttpError;
import tech.kwik.flupke.impl.Http3ClientConnectionImpl;
import tech.kwik.flupke.impl.Http3Frame;
import tech.kwik.qpack.Decoder;
import tech.kwik.qpack.Encoder;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;

/**
 * Http3ClientConnectionImpl subclass that exposes protected members
 * defined by Http3ConnectionImpl, so callers can read raw H3 frames
 * and configure settings without reflection.
 */
public class WarpH3Connection extends Http3ClientConnectionImpl {

    public WarpH3Connection(QuicConnection quicConnection, ExecutorService executorService) {
        super(quicConnection, executorService);
    }

    public Http3Frame readFramePublic(InputStream input) throws IOException, HttpError {
        return readFrame(input);
    }

    public Map<Long, Long> getSettingsParameters() {
        return settingsParameters;
    }

    public Map<Long, Long> getPeerSettingsParameters() {
        return peerSettingsParameters;
    }

    public CountDownLatch getSettingsFrameReceived() {
        return settingsFrameReceived;
    }

    public Encoder getQpackEncoder() {
        return qpackEncoder;
    }

    public Decoder getQpackDecoder() {
        return qpackDecoder;
    }
}
