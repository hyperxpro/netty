/*
 * Copyright 2025 The Netty Project
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
package io.netty.handler.codec.http3;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.handler.codec.quic.QuicException;
import io.netty.handler.codec.quic.QuicStreamChannel;
import io.netty.handler.codec.quic.QuicStreamType;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.Test;

import static io.netty.handler.codec.http3.QpackUtil.MAX_UNSIGNED_INT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AUDIT PoC - propagation proof for Findings #1 / #7.
 *
 * Drives the malicious HEADERS frame end-to-end through a real {@link Http3FrameCodec} feeding a real
 * {@link Http3RequestStreamInboundHandler}, to answer: when the disabled {@code assert} lets a malformed QPACK
 * integer reach {@code new byte[-1]} / {@code getField(-1)}, does the resulting host-language exception become the
 * spec-mandated clean {@code QPACK_DECOMPRESSION_FAILED} connection error, or does it escape uncaught?
 *
 * Result: it escapes. {@link Http3FrameCodec#decodeHeaders} only catches Http3Exception / QpackException /
 * Http3HeadersValidationException; a NegativeArraySizeException / ArrayIndexOutOfBoundsException (or, under the
 * test JVM's {@code -ea}, an AssertionError) is none of those, so it propagates as an uncaught exception. It
 * reaches {@code Http3RequestStreamInboundHandler.exceptionCaught} (line 57) and falls through the {@code else}
 * branch (lines 62-63) to be re-fired to the pipeline tail. No QPACK_DECOMPRESSION_FAILED, no connection close.
 *
 * The CONTROL test feeds a properly-typed QpackException (static index == table length, the guarded upper bound)
 * through the SAME codec and shows it DOES produce a clean QPACK_DECOMPRESSION_FAILED + connection close - proving
 * the disabled-assert bug downgrades a spec-clean connection error into an uncaught/internal failure.
 */
public class AuditPocQpackPropagationTest {

    /** Records how Http3RequestStreamInboundHandler.exceptionCaught classified the failure. */
    private static final class RecordingInboundHandler extends Http3RequestStreamInboundHandler {
        Http3Exception http3Exception;
        QuicException quicException;

        @Override
        protected void channelRead(ChannelHandlerContext ctx, Http3HeadersFrame frame) {
            ReferenceCountUtil.release(frame);
        }

        @Override
        protected void channelRead(ChannelHandlerContext ctx, Http3DataFrame frame) {
            ReferenceCountUtil.release(frame);
        }

        @Override
        protected void channelInputClosed(ChannelHandlerContext ctx) {
        }

        @Override
        protected void handleHttp3Exception(ChannelHandlerContext ctx, Http3Exception exception) {
            this.http3Exception = exception;   // the clean branch
        }

        @Override
        protected void handleQuicException(ChannelHandlerContext ctx, QuicException exception) {
            this.quicException = exception;
        }
    }

    /** Captures anything re-fired past the inbound handler (i.e. the uncaught `else` branch). */
    private static final class TailRecorder extends ChannelInboundHandlerAdapter {
        Throwable cause;

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            this.cause = cause;   // swallow: do not propagate to EmbeddedChannel's own tail
        }
    }

    private EmbeddedQuicChannel parent;
    private RecordingInboundHandler app;
    private TailRecorder tail;

    private EmbeddedQuicStreamChannel newRequestStream() throws Exception {
        parent = new EmbeddedQuicChannel(true);
        // Dynamic table DISABLED -> the HEADERS decode path runs without needing a QPACK decoder stream,
        // matching a default server that advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0.
        QpackAttributes qpackAttributes = new QpackAttributes(parent, true);
        Http3.setQpackAttributes(parent, qpackAttributes);

        QpackDecoder decoder = new QpackDecoder(MAX_UNSIGNED_INT, 0);
        QpackEncoder encoder = new QpackEncoder();
        final Http3FrameCodec codec = new Http3FrameCodec(
                Http3FrameTypeValidator.NO_VALIDATION, decoder, 1024, encoder,
                new Http3RequestStreamEncodeStateValidator(),
                new Http3RequestStreamDecodeStateValidator(),
                (id, v) -> false);
        app = new RecordingInboundHandler();
        tail = new TailRecorder();

        return (EmbeddedQuicStreamChannel) parent.createStream(QuicStreamType.BIDIRECTIONAL,
                new ChannelInitializer<QuicStreamChannel>() {
                    @Override
                    protected void initChannel(QuicStreamChannel ch) {
                        ch.pipeline().addLast(codec);
                        ch.pipeline().addLast(app);
                        ch.pipeline().addLast(tail);
                    }
                }).get();
    }

    private static Throwable rootCause(Throwable t) {
        Throwable r = t;
        while (r.getCause() != null && r.getCause() != r) {
            r = r.getCause();
        }
        return r;
    }

    /** Finding #1: HEADERS frame 01 04 | 00 00 27 FF (literal name length truncates to -1). */
    @Test
    public void negativeLengthEscapesUncaught_notQpackDecompressionFailed() throws Exception {
        EmbeddedQuicStreamChannel ch = newRequestStream();
        try {
            // 01=HEADERS type, 04=length, then the QPACK field section 00 00 27 FF.
            ch.writeInbound(Unpooled.wrappedBuffer(new byte[]{0x01, 0x04, 0x00, 0x00, 0x27, (byte) 0xFF}));

            assertPropagatedUncaught("#1 negative length");
        } finally {
            quietClose(ch);
        }
    }

    /** Finding #7: HEADERS frame 01 04 | 00 00 FF FF (static index truncates to -1). */
    @Test
    public void negativeIndexEscapesUncaught_notQpackDecompressionFailed() throws Exception {
        EmbeddedQuicStreamChannel ch = newRequestStream();
        try {
            ch.writeInbound(Unpooled.wrappedBuffer(new byte[]{0x01, 0x04, 0x00, 0x00, (byte) 0xFF, (byte) 0xFF}));

            assertPropagatedUncaught("#7 negative index");
        } finally {
            quietClose(ch);
        }
    }

    /**
     * CONTROL: HEADERS frame 01 04 | 00 00 FF 24 - an Indexed Field Line referencing static index 99, which
     * equals the table length and so trips the GUARDED upper-bound check -> a real QpackException. The SAME codec
     * converts this into a clean QPACK_DECOMPRESSION_FAILED connection error + close. This is exactly the path the
     * #1/#7 host-language exceptions bypass.
     */
    @Test
    public void properQpackExceptionBecomesCleanQpackDecompressionFailed() throws Exception {
        EmbeddedQuicStreamChannel ch = newRequestStream();
        try {
            ch.writeInbound(Unpooled.wrappedBuffer(new byte[]{0x01, 0x04, 0x00, 0x00, (byte) 0xFF, 0x24}));

            // Clean branch taken: handleHttp3Exception fired with the spec error code; nothing leaked to the tail.
            assertNotNull(app.http3Exception, "expected a clean Http3Exception at exceptionCaught");
            assertEquals(Http3ErrorCode.QPACK_DECOMPRESSION_FAILED, app.http3Exception.errorCode());
            assertNull(tail.cause, "clean path must not re-fire to the tail");
            // And the connection is closed with QPACK_DECOMPRESSION_FAILED (0x200).
            assertTrue(parent.closeFuture().isDone() || !parent.isActive(),
                    "clean connection error should close the connection");
            System.out.println("[CONTROL] proper QpackException -> Http3Exception errorCode="
                    + app.http3Exception.errorCode() + " (0x" + Integer.toHexString((int) app.http3Exception
                    .errorCode().code) + "), connection closed=" + (!parent.isActive()));
        } finally {
            quietClose(ch);
        }
    }

    private void assertPropagatedUncaught(String label) {
        // The cause did NOT match the QuicException/Http3Exception branches of
        // Http3RequestStreamInboundHandler.exceptionCaught, so the clean handlers never ran ...
        assertNull(app.http3Exception, label + ": must NOT be classified as a clean Http3Exception");
        assertNull(app.quicException, label + ": must NOT be classified as a QuicException");
        // ... and instead it was re-fired through the `else` branch (lines 62-63) to the tail.
        assertNotNull(tail.cause, label + ": expected an uncaught exception re-fired to the pipeline tail");

        Throwable root = rootCause(tail.cause);
        System.out.println("[" + label + "] reached Http3RequestStreamInboundHandler.exceptionCaught -> else -> tail; "
                + "outer=" + tail.cause.getClass().getName() + " root=" + root.getClass().getName()
                + " : " + root.getMessage());

        // The load-bearing claim: it is NOT the typed QpackException/Http3Exception that maps to
        // QPACK_DECOMPRESSION_FAILED - so no clean connection error is produced.
        assertFalse(root instanceof QpackException, label + ": root must not be a QpackException");
        assertFalse(root instanceof Http3Exception, label + ": root must not be an Http3Exception");
        assertFalse(tail.cause instanceof Http3Exception, label + ": tail cause must not be an Http3Exception");

        // The connection was NOT cleanly closed by a QPACK_DECOMPRESSION_FAILED connection error.
        assertTrue(parent.isActive(),
                label + ": connection was left open (no clean QPACK_DECOMPRESSION_FAILED close)");
    }

    private void quietClose(EmbeddedQuicStreamChannel ch) {
        try {
            ch.finishAndReleaseAll();
        } catch (Throwable ignore) {
            // ignore
        }
        try {
            if (parent != null) {
                parent.finishAndReleaseAll();
            }
        } catch (Throwable ignore) {
            // ignore
        }
    }
}
