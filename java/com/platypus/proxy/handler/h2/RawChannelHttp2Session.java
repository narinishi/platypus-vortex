package com.platypus.proxy.handler.h2;

import org.glassfish.grizzly.Connection;
import org.glassfish.grizzly.http2.Http2BaseFilter;
import org.glassfish.grizzly.http2.Http2Session;
import org.glassfish.grizzly.http2.Http2SessionOutputSink;

/**
 * Custom HTTP/2 session that installs a {@link RawChannelOutputSink}
 * to prevent filter-chain recursion while preserving standard flow-control.
 *
 * <p>RFC 9113 §5.2 flow control -- standard window tracking preserved.
 */
public class RawChannelHttp2Session extends Http2Session {

    public RawChannelHttp2Session(Connection<?> connection, boolean isServer,
                                  Http2BaseFilter handlerFilter) {
        super(connection, isServer, handlerFilter);
    }

    @Override
    protected Http2SessionOutputSink newOutputSink() {
        return new RawChannelOutputSink(this);
    }

    /**
     * Convenience: use the output sink directly for control frames.
     * This is the only way to send frames outside of the standard
     * stream-based API while still going through the custom sink.
     */
    public void writeFrame(org.glassfish.grizzly.http2.frames.Http2Frame frame) {
        com.platypus.proxy.ProxyApplication.getLogger()
            .Debug("[RAW-SESSION] writeFrame: type=%s streamId=%d",
                frame.getType(), frame.getStreamId());
        ((RawChannelOutputSink)getOutputSink()).writeDownStream(frame);
    }
}
