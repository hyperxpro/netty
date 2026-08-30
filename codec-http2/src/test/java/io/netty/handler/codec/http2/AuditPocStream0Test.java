/*
 * Copyright 2026 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.handler.codec.http2;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AsciiString;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AUDIT PoC for the claim: "a flow-control error on the connection stream (id 0) throws
 * {@link UnsupportedOperationException} from {@code ConnectionStream.resetSent()}; the mandated
 * GOAWAY is never sent; the connection is left open and loopable."
 *
 * <p><b>Result: the claim is REFUTED.</b> The {@code Http2Exception.streamError(id, ...)} factory
 * maps {@code id == CONNECTION_STREAM_ID (0)} to a <em>connection</em> error (a plain
 * {@link Http2Exception}, not a {@link Http2Exception.StreamException}). Therefore
 * {@code Http2ConnectionHandler.onError} routes it to {@code onConnectionError}, which emits the
 * RFC 9113 6.9.1 mandated {@code GOAWAY(FLOW_CONTROL_ERROR)} and closes the connection. The
 * {@code onStreamError -> resetStream -> ConnectionStream.resetSent()} (UnsupportedOperationException)
 * path is never entered, because it requires a {@code StreamException} carrying streamId 0, which the
 * factory never produces.
 *
 * <p>These tests assert the actual (correct) behavior for both proposed triggers and pass on the
 * unmodified codec.
 */
public class AuditPocStream0Test {

    private static final InternalLogger logger = InternalLoggerFactory.getInstance(AuditPocStream0Test.class);

    private static final int FRAME_HEADER_LENGTH = 9;
    private static final int FRAME_TYPE_RST_STREAM = 0x3;
    private static final int FRAME_TYPE_GOAWAY = 0x7;
    private static final int DEFAULT_MAX_FRAME_SIZE = 16384;
    private static final long FLOW_CONTROL_ERROR_CODE = 0x3L;

    private static final class CapturingHandler extends ChannelInboundHandlerAdapter {
        final List<Throwable> caught = new ArrayList<Throwable>();

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            caught.add(cause);
            logger.warn("[audit] exceptionCaught at application handler:", cause);
        }
    }

    private static EmbeddedChannel newDefaultServer(CapturingHandler app) {
        Http2FrameCodec codec = Http2FrameCodecBuilder.forServer().build();
        EmbeddedChannel channel = new EmbeddedChannel();
        channel.connect(new InetSocketAddress(0));
        channel.pipeline().addLast(codec);
        channel.pipeline().addLast(app);
        channel.pipeline().fireChannelActive();
        return channel;
    }

    private static void handshake(EmbeddedChannel channel, Http2FrameInboundWriter inbound) {
        channel.writeInbound(Http2CodecUtil.connectionPrefaceBuf());
        inbound.writeInboundSettings(new Http2Settings());
        inbound.writeInboundSettingsAck();
    }

    @Test
    public void triggerA_windowUpdateOverflowOnConnectionStream() {
        CapturingHandler app = new CapturingHandler();
        EmbeddedChannel channel = newDefaultServer(app);
        Http2FrameInboundWriter inbound = new Http2FrameInboundWriter(channel);
        try {
            handshake(channel, inbound);
            assertFalse(drainOutbound(channel).hasGoAway, "unexpected GOAWAY after handshake");

            // ATTACK: WINDOW_UPDATE on the connection stream (id 0) whose increment overflows the
            // connection send window: 65535 + 0x7FFFFFFF > Integer.MAX_VALUE.
            inbound.writeInboundWindowUpdate(0, Integer.MAX_VALUE);

            assertCorrectConnectionErrorHandling(channel, app, "Trigger A (WINDOW_UPDATE overflow)");
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    public void triggerB_inboundDataUnderflowsConnectionWindow() {
        CapturingHandler app = new CapturingHandler();
        EmbeddedChannel channel = newDefaultServer(app);
        Http2FrameInboundWriter inbound = new Http2FrameInboundWriter(channel);
        try {
            handshake(channel, inbound);
            assertFalse(drainOutbound(channel).hasGoAway, "unexpected GOAWAY after handshake");

            Http2Headers request = new DefaultHttp2Headers()
                    .method(new AsciiString("GET")).scheme(new AsciiString("https"))
                    .authority(new AsciiString("example.org")).path(new AsciiString("/"));
            inbound.writeInboundHeaders(3, request, 0, false);
            drainOutbound(channel);

            // ATTACK: flood unconsumed DATA. The default codec returns 0 from onDataRead (deferred
            // consume), so the connection receive window (initial 65535) is never refilled. Once the
            // unconsumed bytes exceed 65535 the connection-level receiveFlowControlledFrame underflows
            // and raises streamError(0) -> a connection error.
            for (int i = 0; i < 8 && app.caught.isEmpty(); i++) {
                ByteBuf data = Unpooled.wrappedBuffer(new byte[DEFAULT_MAX_FRAME_SIZE]);
                inbound.writeInboundData(3, data, 0, false);
            }

            assertCorrectConnectionErrorHandling(channel, app, "Trigger B (DATA connection-window underflow)");
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    /**
     * Asserts the RFC-correct outcome: a <em>connection</em> error (never an
     * {@link UnsupportedOperationException}), a {@code GOAWAY(FLOW_CONTROL_ERROR)} on the wire, and a
     * closed connection (i.e. NOT loopable).
     */
    private static void assertCorrectConnectionErrorHandling(EmbeddedChannel channel, CapturingHandler app,
                                                             String label) {
        // (1) The resetSent() UnsupportedOperationException path was NOT taken.
        assertNull(findCause(app.caught, UnsupportedOperationException.class),
                label + ": unexpected UnsupportedOperationException (resetSent path); caught=" + app.caught);

        // (2) A connection-level Http2Exception (not a StreamException) was surfaced to the app.
        Http2Exception http2Ex = (Http2Exception) findCause(app.caught, Http2Exception.class);
        assertNotNull(http2Ex, label + ": expected a connection Http2Exception; caught=" + app.caught);
        assertFalse(http2Ex instanceof Http2Exception.StreamException,
                label + ": stream-0 error must be a connection error, not a StreamException");
        assertTrue(Http2Error.FLOW_CONTROL_ERROR == http2Ex.error(),
                label + ": expected FLOW_CONTROL_ERROR, got " + http2Ex.error());

        // (3) RFC 9113 6.9.1: a GOAWAY with FLOW_CONTROL_ERROR was emitted, and no RST_STREAM on id 0.
        OutboundFrames out = drainOutbound(channel);
        assertTrue(out.hasGoAway, label + ": GOAWAY(FLOW_CONTROL_ERROR) was NOT sent. frames=" + out.types);
        assertTrue(FLOW_CONTROL_ERROR_CODE == out.goAwayErrorCode,
                label + ": GOAWAY error code expected 0x3 (FLOW_CONTROL_ERROR), got " + out.goAwayErrorCode);
        assertFalse(out.hasRstStreamOnStream0, label + ": must not RST_STREAM on stream 0");

        // (4) Connection is torn down -> NOT a wedged-open amplification loop.
        assertFalse(channel.isActive(), label + ": connection should be closed (not loopable)");
        assertFalse(channel.isOpen(), label + ": connection should be closed (not loopable)");

        logger.warn("[audit] {} REFUTED. observed: uoePresent={} exception={} isStreamException={} error={} "
                + "outboundFrameTypes={} hasGoAway={} goAwayErrorCode=0x{} rstStreamOnStream0={} "
                + "channelOpen={} channelActive={}",
                label,
                findCause(app.caught, UnsupportedOperationException.class) != null,
                http2Ex.getClass().getName(),
                http2Ex instanceof Http2Exception.StreamException,
                http2Ex.error(),
                out.types,
                out.hasGoAway,
                Long.toHexString(out.goAwayErrorCode),
                out.hasRstStreamOnStream0,
                channel.isOpen(),
                channel.isActive());
    }

    // ------------------------------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------------------------------

    private static Throwable findCause(List<Throwable> caught, Class<?> type) {
        for (Throwable t : caught) {
            for (Throwable c = t; c != null; c = c.getCause()) {
                if (type.isInstance(c)) {
                    return c;
                }
            }
        }
        return null;
    }

    private static final class OutboundFrames {
        final List<Integer> types = new ArrayList<Integer>();
        boolean hasGoAway;
        boolean hasRstStreamOnStream0;
        long goAwayErrorCode = -1L;
    }

    /**
     * Drains and parses every outbound HTTP/2 frame the server has flushed by walking 9-byte frame
     * headers. Records frame types, the first GOAWAY error code, and whether a stream-0 RST_STREAM
     * was present.
     */
    private static OutboundFrames drainOutbound(EmbeddedChannel channel) {
        ByteBuf agg = Unpooled.buffer();
        try {
            for (;;) {
                Object o = channel.readOutbound();
                if (o == null) {
                    break;
                }
                if (o instanceof ByteBuf) {
                    ByteBuf b = (ByteBuf) o;
                    agg.writeBytes(b);
                    b.release();
                } else {
                    ReferenceCountUtil.release(o);
                }
            }
            OutboundFrames frames = new OutboundFrames();
            while (agg.readableBytes() >= FRAME_HEADER_LENGTH) {
                int length = agg.readUnsignedMedium();
                int type = agg.readByte() & 0xFF;
                agg.readByte(); // flags
                int streamId = agg.readInt() & 0x7FFFFFFF;
                if (agg.readableBytes() < length) {
                    break; // partial frame - should not happen for flushed output
                }
                frames.types.add(type);
                if (type == FRAME_TYPE_GOAWAY) {
                    frames.hasGoAway = true;
                    // GOAWAY payload: lastStreamId (4) + errorCode (4) + debugData.
                    if (length >= 8) {
                        agg.skipBytes(4); // lastStreamId
                        frames.goAwayErrorCode = agg.readUnsignedInt();
                        agg.skipBytes(length - 8);
                    } else {
                        agg.skipBytes(length);
                    }
                } else {
                    if (type == FRAME_TYPE_RST_STREAM && streamId == 0) {
                        frames.hasRstStreamOnStream0 = true;
                    }
                    agg.skipBytes(length);
                }
            }
            return frames;
        } finally {
            agg.release();
        }
    }
}
