package com.platypus.proxy.handler.h2;

import java.util.List;
import org.glassfish.grizzly.Buffer;
import org.glassfish.grizzly.CompletionHandler;
import org.glassfish.grizzly.WriteResult;
import org.glassfish.grizzly.asyncqueue.MessageCloner;
import org.glassfish.grizzly.http2.Http2Session;
import org.glassfish.grizzly.http2.Http2SessionOutputSink;
import org.glassfish.grizzly.http2.Http2Stream;
import org.glassfish.grizzly.http2.frames.Http2Frame;

/**
 * Output sink that writes every HTTP/2 frame through the Grizzly
 * {@link org.glassfish.grizzly.Connection} so that SSL encryption
 * is applied by the filter chain when running over TLS.
 *
 * <p>RFC 9113 §9.2 TLS features -- HTTP/2 frames MUST be encrypted
 * when running over TLS (https URIs).
 *
 * <p>Previously this wrote directly to the raw TCP socket via
 * {@link H2FrameWriter}, which bypassed the SSL filter.
 */
public class RawChannelOutputSink extends Http2SessionOutputSink {

    public RawChannelOutputSink(Http2Session session) {
        super(session);
    }

    @Override
    protected void writeDownStream(Http2Frame frame) {
        try {
            Buffer buf = frame.toBuffer(http2Session.getMemoryManager());
            if (buf != null && buf.remaining() > 0) {
                com.platypus.proxy.ProxyApplication.getLogger()
                    .Debug("[OUTPUT-SINK] Writing type=%s len=%d streamId=%d",
                        frame.getType(), buf.remaining(), frame.getStreamId());
                http2Session.getConnection().write(buf);
                com.platypus.proxy.ProxyApplication.getLogger()
                    .Debug("[OUTPUT-SINK] Wrote type=%s OK", frame.getType());
            }
        } catch (Exception e) {
            com.platypus.proxy.ProxyApplication.getLogger()
                .Error("[OUTPUT-SINK] writeDownStream FAILED type=%s: %s", frame.getType(), e.toString());
        }
    }

    @Override
    protected void writeDownStream(List<Http2Frame> frames) {
        for (Http2Frame f : frames) {
            writeDownStream(f);
        }
    }

    @SuppressWarnings("rawtypes")
    @Override
    protected <K> void writeDownStream(K anyMessage,
                                        CompletionHandler<WriteResult> completionHandler,
                                        MessageCloner<Buffer> messageCloner) {
        com.platypus.proxy.ProxyApplication.getLogger()
            .Debug("[OUTPUT-SINK] writeDownStream(K) called, msg type=%s",
                anyMessage != null ? anyMessage.getClass().getSimpleName() : "null");
        if (anyMessage instanceof Http2Frame) {
            writeDownStream((Http2Frame) anyMessage);
        } else if (anyMessage instanceof Buffer) {
            http2Session.getConnection().write((Buffer) anyMessage);
        }
        if (completionHandler != null) {
            completionHandler.completed(null);
        }
    }

    @SuppressWarnings("rawtypes")
    @Override
    protected void writeDataDownStream(Http2Stream stream,
                                        List<Http2Frame> headerFrames,
                                        Buffer data,
                                        CompletionHandler<WriteResult> completionHandler,
                                        MessageCloner<Buffer> messageCloner,
                                        boolean isLast) {
        com.platypus.proxy.ProxyApplication.getLogger()
            .Debug("[OUTPUT-SINK] writeDataDownStream streamId=%d isLast=%s",
                stream.getId(), isLast);
        if (headerFrames != null && !headerFrames.isEmpty()) {
            writeDownStream(headerFrames);
        }

        if (data != null && data.hasRemaining()) {
            http2Session.getConnection().write(data);
        }

        if (isLast && (data == null || !data.hasRemaining())) {
            org.glassfish.grizzly.http2.frames.DataFrame endFrame =
                    org.glassfish.grizzly.http2.frames.DataFrame.builder()
                            .streamId(stream.getId())
                            .endStream(true)
                            .build();
            writeDownStream(endFrame);
        }

        if (completionHandler != null) {
            completionHandler.completed(null);
        }
    }
}
