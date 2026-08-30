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
import io.netty.channel.ChannelInitializer;
import io.netty.handler.codec.quic.QuicStreamChannel;
import io.netty.handler.codec.quic.QuicStreamType;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AUDIT PoC - Finding #3 (HIGH).
 *
 * {@link Http3FrameCodec} reads the variable-length-integer payload field of CANCEL_PUSH / GO_AWAY /
 * MAX_PUSH_ID / SETTINGS using {@code numBytesForVariableLengthInteger(firstByte)} - the width announced by the
 * first payload byte's 2-bit prefix - and is bounded only by {@code enforceMaxPayloadLength} (payLoadLength &le;
 * max and readableBytes &ge; payLoadLength). It never checks that the inner varint width fits within the declared
 * frame {@code Length}. A CANCEL_PUSH with {@code Length = 1} whose single payload byte announces an 8-byte
 * varint therefore reads 7 bytes beyond the frame boundary.
 *
 * RFC 9114 Section 7.1: "A frame payload that contains additional bytes after the identified fields or a frame
 * payload that terminates before the end of the identified fields MUST be treated as a connection error of type
 * H3_FRAME_ERROR." Netty instead either throws an uncaught {@code IndexOutOfBoundsException} (wrapped in a
 * DecoderException) or silently desyncs the frame stream.
 */
public class AuditPocH3FrameVarintTest {

    private static EmbeddedQuicStreamChannel newChannel() throws Exception {
        EmbeddedQuicChannel parent = new EmbeddedQuicChannel(true);
        QpackAttributes qpackAttributes = new QpackAttributes(parent, false);
        Http3.setQpackAttributes(parent, qpackAttributes);

        QpackDecoder decoder = new QpackDecoder(1024L, 0);
        QpackEncoder encoder = new QpackEncoder();
        final Http3FrameCodec codec = new Http3FrameCodec(
                Http3FrameTypeValidator.NO_VALIDATION, decoder, 1024, encoder,
                new Http3RequestStreamEncodeStateValidator(),
                new Http3RequestStreamDecodeStateValidator(),
                (id, v) -> false);

        return (EmbeddedQuicStreamChannel) parent.createStream(QuicStreamType.BIDIRECTIONAL,
                new ChannelInitializer<QuicStreamChannel>() {
                    @Override
                    protected void initChannel(QuicStreamChannel ch) {
                        ch.pipeline().addLast(codec);
                    }
                }).get();
    }

    /**
     * CANCEL_PUSH, Length = 1, single payload byte 0xC0 (announces an 8-byte varint). The reader pulls 8 bytes
     * though only 1 is present in the (last) frame -> uncaught IndexOutOfBoundsException, NOT a clean
     * H3_FRAME_ERROR connection error.
     */
    @Test
    public void varintWiderThanDeclaredLengthThrowsUncaughtException() throws Exception {
        EmbeddedQuicStreamChannel channel = newChannel();
        Throwable captured = null;
        try {
            // type=0x03 (CANCEL_PUSH), length=0x01, payload=0xC0 (2-bit prefix 0b11 -> 8-byte varint).
            ByteBuf buf = Unpooled.wrappedBuffer(new byte[]{0x03, 0x01, (byte) 0xC0});

            // ByteToMessageDecoder records the exception on the channel rather than rethrowing from
            // writeInbound; checkException() surfaces it - mirroring the existing Http3FrameCodecTest pattern.
            channel.writeInbound(buf);
            channel.checkException();
        } catch (Throwable t) {
            captured = t;
        } finally {
            // Drain/close WITHOUT rethrowing the recorded exception.
            try {
                channel.finishAndReleaseAll();
            } catch (Throwable ignore) {
                // expected: the error state may resurface here; not part of the assertion.
            }
        }

        assertNotNull(captured, "expected an uncaught exception from reading past the declared frame length");
        Throwable root = captured;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        System.out.println("[Finding #3a] outer=" + captured.getClass().getName()
                + "  root=" + root.getClass().getName() + " : " + root.getMessage());

        // A raw IndexOutOfBoundsException (wrapped in DecoderException) escapes - NOT the spec-mandated clean
        // H3_FRAME_ERROR connection close. Confirm it is not a controlled Http3 error.
        assertTrue(root instanceof IndexOutOfBoundsException,
                "expected IndexOutOfBoundsException at root, got " + root.getClass().getName());
        assertFalse(root instanceof Http3Exception,
                "the over-read produced an uncaught exception, not a clean H3_FRAME_ERROR");
    }

    /**
     * CANCEL_PUSH, Length = 1, payload byte 0x40 (announces a 2-byte varint) immediately followed by a complete
     * GO_AWAY frame (07 01 05). The reader consumes the GO_AWAY's 0x07 type byte as the second byte of the push
     * id (-> id 7) and the rest of the GO_AWAY is misframed: the GO_AWAY frame is destroyed and never decoded.
     */
    @Test
    public void varintStealsBytesFromNextFrameCausingDesync() throws Exception {
        EmbeddedQuicStreamChannel channel = newChannel();
        try {
            ByteBuf buf = Unpooled.wrappedBuffer(new byte[]{
                    0x03, 0x01, 0x40,   // CANCEL_PUSH, len=1, payload 0x40 (announces 2-byte varint)
                    0x07, 0x01, 0x05    // intended next frame: GO_AWAY, len=1, id=5
            });
            channel.writeInbound(buf);

            Http3CancelPushFrame cancelPush = channel.readInbound();
            assertNotNull(cancelPush, "CANCEL_PUSH frame should be produced");
            // id == 7 proves the decoder read the next frame's type byte (0x07) as part of the push id,
            // i.e. it read past the 1-byte declared payload.
            System.out.println("[Finding #3b] CANCEL_PUSH id decoded across frame boundary = " + cancelPush.id());
            assertEquals(7L, cancelPush.id());
            ReferenceCountUtil.release(cancelPush);

            // The intended GO_AWAY(5) frame has been swallowed/misframed: no second frame is produced.
            Object next = channel.readInbound();
            System.out.println("[Finding #3b] next decoded frame after desync = " + next + " (GO_AWAY was destroyed)");
            assertNull(next, "intended GO_AWAY frame must have been destroyed by the over-read (desync)");
        } finally {
            channel.finishAndReleaseAll();
        }
    }
}
