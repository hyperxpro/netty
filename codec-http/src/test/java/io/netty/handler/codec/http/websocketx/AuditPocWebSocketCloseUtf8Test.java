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
package io.netty.handler.codec.http.websocketx;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RedCell audit PoC for Finding #8.
 *
 * <p>A Close frame's reason is UTF-8 (RFC 6455 §5.5.1/§7.1.6) and invalid UTF-8 anywhere in a frame
 * MUST fail the connection with status 1007 (§8.1). {@code WebSocket08FrameDecoder.checkCloseFrameBody}
 * validates the reason with {@code new Utf8Validator().check(...)} but never calls
 * {@code Utf8Validator.finish()}. {@code check()} only streams bytes through the DFA and throws solely
 * on the {@code UTF8_REJECT} state; a reason that ends in the MIDDLE of a multi-byte sequence leaves the
 * DFA in a non-ACCEPT intermediate state that ONLY {@code finish()} would flag. The text-frame path
 * ({@code Utf8FrameValidator}) does call {@code finish()} - but it explicitly SKIPS control frames - so
 * the close reason is end-checked nowhere. Result: a truncated trailing sequence in a close reason is
 * accepted instead of rejected.
 */
public class AuditPocWebSocketCloseUtf8Test {

    // FIN + opcode CLOSE (0x88), unmasked. Payload = status 1000 (0x03E8) + reason bytes.
    private static ByteBuf closeFrame(int... reason) {
        ByteBuf buf = Unpooled.buffer();
        buf.writeByte(0x88);
        buf.writeByte(2 + reason.length); // top (mask) bit = 0 -> unmasked
        buf.writeByte(0x03).writeByte(0xE8); // status code 1000 (NORMAL_CLOSURE)
        for (int b : reason) {
            buf.writeByte(b);
        }
        return buf;
    }

    // expectMaskedFrames=false so we can feed raw unmasked frames straight into the decoder.
    private static EmbeddedChannel ws08() {
        return new EmbeddedChannel(new WebSocket08FrameDecoder(false, false, 65535, false));
    }

    private static EmbeddedChannel ws13() {
        return new EmbeddedChannel(new WebSocket13FrameDecoder(false, false, 65535, false));
    }

    /**
     * THE BUG: a lone UTF-8 lead byte 0xC2 (start of a 2-byte sequence, continuation missing) at the
     * end of the close reason is accepted - the DFA ends in a non-ACCEPT state that only finish() checks.
     */
    @Test
    public void closeReasonLoneLeadByteIsWronglyAccepted() {
        EmbeddedChannel ch = ws08();
        boolean produced = ch.writeInbound(closeFrame(0xC2));
        assertTrue(produced);
        assertTrue(ch.isActive(), "BUG: connection still open; truncated-UTF-8 close reason accepted");

        CloseWebSocketFrame frame = ch.readInbound();
        assertNotNull(frame, "BUG: invalid-UTF-8 close frame emitted instead of failing with 1007");
        try {
            assertEquals(1000, frame.statusCode());
            ByteBuf content = frame.content();
            // payload = 2 status bytes + the lone 0xC2 reason byte
            assertEquals(3, content.readableBytes());
            assertEquals((byte) 0xC2, content.getByte(content.readerIndex() + 2));
            System.out.printf("[AuditPoc#8] WS08 close reason=0xC2 (lone lead byte) -> writeInbound=%b,"
                            + " channelActive=%b, emitted=%s statusCode=%d (ACCEPTED = BUG)%n",
                    produced, ch.isActive(), frame.getClass().getSimpleName(), frame.statusCode());
        } finally {
            frame.release();
        }
        ch.finishAndReleaseAll();
    }

    /**
     * THE BUG: the first three bytes of a 4-byte emoji (F0 9F 98 ..) with the final byte missing are
     * accepted in the close reason.
     */
    @Test
    public void closeReasonTruncatedEmojiIsWronglyAccepted() {
        EmbeddedChannel ch = ws08();
        assertTrue(ch.writeInbound(closeFrame(0xF0, 0x9F, 0x98)));
        assertTrue(ch.isActive(), "BUG: truncated 4-byte sequence accepted in close reason");

        CloseWebSocketFrame frame = ch.readInbound();
        assertNotNull(frame, "BUG: truncated-UTF-8 close frame emitted instead of failing with 1007");
        frame.release();
        ch.finishAndReleaseAll();
    }

    /** Same defect via the WebSocket13 decoder (it inherits checkCloseFrameBody from 08). */
    @Test
    public void closeReasonLoneLeadByteIsWronglyAcceptedWs13() {
        EmbeddedChannel ch = ws13();
        assertTrue(ch.writeInbound(closeFrame(0xC2)));
        assertTrue(ch.isActive());
        CloseWebSocketFrame frame = ch.readInbound();
        assertNotNull(frame, "BUG: WebSocket13 also accepts a truncated close reason");
        frame.release();
        ch.finishAndReleaseAll();
    }

    /**
     * CONTROL (already handled correctly): 0xC2 0x28 is a COMPLETE invalid sequence (bad continuation),
     * so the DFA reaches UTF8_REJECT mid-stream and {@code process()} throws. This proves the validator
     * DOES catch non-truncated invalid UTF-8; the gap is purely the missing end-of-input finish() check.
     */
    @Test
    public void closeReasonInvalidContinuationIsCorrectlyRejected() {
        final EmbeddedChannel ch = ws08();
        CorruptedWebSocketFrameException ex = assertThrows(CorruptedWebSocketFrameException.class,
                () -> ch.writeInbound(closeFrame(0xC2, 0x28)));
        assertEquals(WebSocketCloseStatus.INVALID_PAYLOAD_DATA, ex.closeStatus()); // 1007
        assertFalse(ch.isActive(), "connection failed closed on invalid UTF-8");
        System.out.printf("[AuditPoc#8] CONTROL WS08 close reason=0xC2 0x28 (complete invalid) -> threw %s"
                        + " closeStatus=%d, channelActive=%b (REJECTED = validator works)%n",
                ex.getClass().getSimpleName(), ex.closeStatus().code(), ch.isActive());
        ch.finishAndReleaseAll();
    }

    /** CONTROL (already handled correctly): a valid ASCII reason "Hi" is accepted. */
    @Test
    public void closeReasonValidUtf8IsAccepted() {
        EmbeddedChannel ch = ws08();
        assertTrue(ch.writeInbound(closeFrame('H', 'i')));
        CloseWebSocketFrame frame = ch.readInbound();
        assertNotNull(frame);
        try {
            assertEquals(1000, frame.statusCode());
            assertEquals("Hi", frame.reasonText());
        } finally {
            frame.release();
        }
        ch.finishAndReleaseAll();
    }
}
