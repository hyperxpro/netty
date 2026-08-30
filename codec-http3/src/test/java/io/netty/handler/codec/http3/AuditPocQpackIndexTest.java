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
 * AUDIT PoC - Finding #7 (MEDIUM, sibling of #1).
 *
 * A QPACK Indexed Field Line referencing the static table with a truncated index decodes to the -1 sentinel.
 * {@link QpackDecoder#decodeIndexed} only checks {@code idx >= QpackStaticTable.length} (upper bound); the
 * lower-bound {@code assert idx >= 0} is a disabled no-op, so {@code QpackStaticTable.getField(-1)} reaches
 * {@code Arrays.asList(...).get(-1)} and throws {@link ArrayIndexOutOfBoundsException} (a RuntimeException),
 * not a {@link QpackException}.
 */
public class AuditPocQpackIndexTest {

    @Test
    public void truncatedStaticTableIndexEscapesAsArrayIndexOutOfBounds() {
        QpackDecoder decoder = new QpackDecoder(MAX_UNSIGNED_INT, 0);
        EmbeddedQuicChannel parent = new EmbeddedQuicChannel(true);
        QpackAttributes attributes = new QpackAttributes(parent, false);

        // Encoded field section:
        //   00  Required Insert Count = 0
        //   00  Delta Base           = 0
        //   FF  Indexed Field Line, T=1 (static table): bits 0b11, Index 6-bit prefix = 0b111111 (=63 == max)
        //       -> continuation required.
        //   FF  continuation byte that runs off the end -> decodePrefixedInteger returns -1 -> idx = -1.
        byte[] block = {0x00, 0x00, (byte) 0xFF, (byte) 0xFF};
        ByteBuf in = Unpooled.wrappedBuffer(block);
        BiConsumer<CharSequence, CharSequence> sink = (n, v) -> { };

        try {
            Throwable t = assertThrows(Throwable.class,
                    () -> decoder.decode(attributes, 0L, in, block.length, sink, () -> { }));

            System.out.println("[Finding #7] escaping exception = " + t.getClass().getName()
                    + " : " + t.getMessage());
            for (StackTraceElement e : t.getStackTrace()) {
                if (e.getClassName().contains("Qpack")) {
                    System.out.println("    at " + e);
                }
            }

            // Core invariant (both modes): NOT a QpackException -> never mapped to QPACK_DECOMPRESSION_FAILED.
            assertFalse(t instanceof QpackException, "must NOT be a clean QpackException");

            // Only guard before QpackStaticTable.getField(idx) is `assert idx >= 0`.
            //  - Production (-da): idx == -1 reaches Arrays.asList(...).get(-1) -> ArrayIndexOutOfBoundsException.
            //  - Test JVM (-ea:io.netty...): the disabled-in-prod assert fires first -> AssertionError.
            boolean assertionsEnabled = false;
            assert assertionsEnabled = true;
            if (assertionsEnabled) {
                assertTrue(t instanceof AssertionError,
                        "with -ea the disabled-in-prod assert fires; got " + t.getClass().getName());
                System.out.println("[Finding #7] (-ea) AssertionError at the disabled guard; "
                        + "production (-da) reaches getField(-1) -> ArrayIndexOutOfBoundsException");
            } else {
                assertTrue(t instanceof IndexOutOfBoundsException,
                        "production path expected (Array)IndexOutOfBoundsException; got " + t.getClass().getName());
            }
        } finally {
            in.release();
            parent.close();
        }
    }
}
