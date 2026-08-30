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
package io.netty.handler.codec.dns.dnssec;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.dns.DnsRecordType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnsTypeBitmapTest {

    /**
     * The type bit maps octets of the NSEC RR example in
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-4.3">RFC 4034, section 4.3</a>, copied verbatim
     * from the RDATA encoding published there. The owner name {@code alfa.example.com.} has A (1), MX (15),
     * RRSIG (46), NSEC (47) and TYPE1234.
     */
    private static final byte[] RFC4034_EXAMPLE = {
            // Window block 0, six octets of bitmap. 0x40 sets bit 1 (A), 0x01 sets bit 15 (MX) and 0x03 sets
            // bits 46 and 47 (RRSIG and NSEC).
            0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03,
            // Window block 4, 27 octets of bitmap, with only bit 2 of the 27th octet set:
            // 4 * 256 + 26 * 8 + 2 == 1234.
            0x04, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20,
    };

    @Test
    public void testDecodeRfc4034Example() {
        ByteBuf in = Unpooled.wrappedBuffer(RFC4034_EXAMPLE);
        try {
            DnsTypeBitmap bitmap = DnsTypeBitmap.decode(in, RFC4034_EXAMPLE.length);
            assertArrayEquals(new int[] { 1, 15, 46, 47, 1234 }, bitmap.types());
            assertEquals(5, bitmap.size());
            assertFalse(bitmap.isEmpty());
            assertTrue(bitmap.contains(DnsRecordType.A));
            assertTrue(bitmap.contains(DnsRecordType.MX));
            assertTrue(bitmap.contains(DnsRecordType.RRSIG));
            assertTrue(bitmap.contains(DnsRecordType.NSEC));
            assertTrue(bitmap.contains(1234));
            assertFalse(bitmap.contains(DnsRecordType.AAAA));
            assertFalse(bitmap.contains(DnsRecordType.SOA));
            assertFalse(bitmap.contains(1233));
            assertFalse(bitmap.contains(1235));
            // The presentation form RFC 4034, section 4.3 prints for this very record.
            assertEquals("A MX RRSIG NSEC TYPE1234", bitmap.toString());
            assertEquals(0, in.readableBytes());
        } finally {
            in.release();
        }
    }

    @Test
    public void testDecodeConsumesExactlyTheAnnouncedLength() {
        ByteBuf in = Unpooled.buffer();
        try {
            in.writeBytes(RFC4034_EXAMPLE).writeByte(0xff).writeByte(0xff);
            DnsTypeBitmap bitmap = DnsTypeBitmap.decode(in, RFC4034_EXAMPLE.length);
            assertEquals(5, bitmap.size());
            assertEquals(2, in.readableBytes());
        } finally {
            in.release();
        }
    }

    @Test
    public void testWriteToReproducesTheInputOctetForOctet() {
        // The field sits inside RDATA that an RRSIG covers, so re-encoding it has to be an identity.
        ByteBuf in = Unpooled.wrappedBuffer(RFC4034_EXAMPLE);
        ByteBuf out = Unpooled.buffer();
        try {
            DnsTypeBitmap bitmap = DnsTypeBitmap.decode(in, RFC4034_EXAMPLE.length);
            assertEquals(RFC4034_EXAMPLE.length, bitmap.wireLength());
            bitmap.writeTo(out);
            byte[] written = new byte[out.readableBytes()];
            out.readBytes(written);
            assertArrayEquals(RFC4034_EXAMPLE, written);
        } finally {
            in.release();
            out.release();
        }
    }

    @Test
    public void testEmptyBitmapIsLegal() {
        // RFC 6840, section 6.4 corrects the RFC 5155 grammar to (...)*, and an NSEC3 for an empty non-terminal
        // carries no window block at all.
        ByteBuf in = Unpooled.buffer();
        ByteBuf out = Unpooled.buffer();
        try {
            DnsTypeBitmap bitmap = DnsTypeBitmap.decode(in, 0);
            assertSame(DnsTypeBitmap.EMPTY, bitmap);
            assertTrue(bitmap.isEmpty());
            assertEquals(0, bitmap.size());
            assertEquals(0, bitmap.wireLength());
            assertEquals(0, bitmap.types().length);
            assertFalse(bitmap.contains(DnsRecordType.A));
            assertEquals("", bitmap.toString());
            bitmap.writeTo(out);
            assertEquals(0, out.readableBytes());
        } finally {
            in.release();
            out.release();
        }
    }

    @Test
    public void testDecodeSetsEveryBitOfAFullWindow() {
        byte[] wire = new byte[2 + 32];
        wire[0] = 0;
        wire[1] = 32;
        for (int i = 2; i < wire.length; i++) {
            wire[i] = (byte) 0xff;
        }
        DnsTypeBitmap bitmap = decode(wire);
        assertEquals(256, bitmap.size());
        for (int type = 0; type < 256; type++) {
            assertTrue(bitmap.contains(type), "type " + type + " should be present");
        }
        assertFalse(bitmap.contains(256));
    }

    @Test
    public void testDecodeReachesTheHighestWindowAndType() {
        byte[] wire = new byte[2 + 32];
        wire[0] = (byte) 255;
        wire[1] = 32;
        wire[wire.length - 1] = 0x01;
        DnsTypeBitmap bitmap = decode(wire);
        assertArrayEquals(new int[] { 65535 }, bitmap.types());
        assertTrue(bitmap.contains(65535));
    }

    @Test
    public void testDecodeAcceptsTheMaximumNumberOfWindowBlocks() {
        // Window numbers are a single octet and have to strictly ascend, so 256 blocks is the most a well-formed
        // field can hold; the explicit block cap must not reject it.
        byte[] wire = new byte[256 * 3];
        for (int window = 0; window < 256; window++) {
            wire[window * 3] = (byte) window;
            wire[window * 3 + 1] = 1;
            wire[window * 3 + 2] = (byte) 0x80;
        }
        DnsTypeBitmap bitmap = decode(wire);
        assertEquals(256, bitmap.size());
        assertTrue(bitmap.contains(0));
        assertTrue(bitmap.contains(0xff00));
    }

    @Test
    public void testDecodeAcceptsTrailingZeroOctetsInsideABlock() {
        // A producer must omit them, but they carry no types, they cannot hide one either, and the whole field is
        // covered by a signature, so rejecting them would only turn a sloppy signer into a BOGUS zone.
        DnsTypeBitmap padded = decode(new byte[] { 0x00, 0x04, 0x40, 0x00, 0x00, 0x00 });
        DnsTypeBitmap minimal = decode(new byte[] { 0x00, 0x01, 0x40 });
        assertArrayEquals(new int[] { 1 }, padded.types());
        assertEquals(minimal, padded);
        assertEquals(minimal.hashCode(), padded.hashCode());
        // The two are still distinguishable on the wire, which is what the signature is computed over.
        assertNotEquals(minimal.wireLength(), padded.wireLength());
    }

    @Test
    public void testDecodeRejectsAnAllZeroBlock() {
        assertDecodeFails(new byte[] { 0x00, 0x01, 0x00 });
        assertDecodeFails(new byte[] { 0x00, 0x01, 0x40, 0x01, 0x02, 0x00, 0x00 });
    }

    @Test
    public void testDecodeRejectsRepeatedOrDescendingWindows() {
        // A repeated window is how a bit is smuggled past a reader that keeps only the first or only the last block
        // it sees for a given window.
        assertDecodeFails(new byte[] { 0x00, 0x01, 0x40, 0x00, 0x01, 0x01 });
        assertDecodeFails(new byte[] { 0x01, 0x01, 0x40, 0x00, 0x01, 0x40 });
    }

    @Test
    public void testDecodeRejectsAnOutOfRangeBitmapLength() {
        assertDecodeFails(new byte[] { 0x00, 0x00 });
        assertDecodeFails(new byte[] { 0x00, 0x21, 0x40 });
    }

    @Test
    public void testDecodeRejectsATruncatedField() {
        assertDecodeFails(new byte[] { 0x00 });
        assertDecodeFails(new byte[] { 0x00, 0x02, 0x40 });
        assertDecodeFails(new byte[] { 0x00, 0x01, 0x40, 0x01 });
    }

    @Test
    public void testDecodeRejectsALengthLongerThanTheBuffer() {
        ByteBuf in = Unpooled.wrappedBuffer(new byte[] { 0x00, 0x01, 0x40 });
        try {
            assertThrows(CorruptedFrameException.class, () -> DnsTypeBitmap.decode(in, 4));
            assertEquals(3, in.readableBytes(), "a rejected field must not consume anything");
        } finally {
            in.release();
        }
    }

    @Test
    public void testDecodeRejectsANegativeLength() {
        ByteBuf in = Unpooled.buffer();
        try {
            assertThrows(IllegalArgumentException.class, () -> DnsTypeBitmap.decode(in, -1));
        } finally {
            in.release();
        }
    }

    @Test
    public void testContainsRejectsSomethingThatIsNotAnRrType() {
        DnsTypeBitmap bitmap = decode(new byte[] { 0x00, 0x01, 0x40 });
        assertThrows(IllegalArgumentException.class, () -> bitmap.contains(-1));
        assertThrows(IllegalArgumentException.class, () -> bitmap.contains(0x10000));
        assertThrows(NullPointerException.class, () -> bitmap.contains((DnsRecordType) null));
    }

    @Test
    public void testTypesIsADefensiveCopy() {
        DnsTypeBitmap bitmap = decode(new byte[] { 0x00, 0x01, 0x40 });
        bitmap.types()[0] = 99;
        assertArrayEquals(new int[] { 1 }, bitmap.types());
        assertFalse(bitmap.contains(99));
    }

    @Test
    public void testEqualsAndHashCode() {
        DnsTypeBitmap a = decode(new byte[] { 0x00, 0x01, 0x40 });
        DnsTypeBitmap b = decode(new byte[] { 0x00, 0x01, 0x40 });
        DnsTypeBitmap other = decode(new byte[] { 0x00, 0x01, 0x20 });
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, other);
        assertNotEquals(a, DnsTypeBitmap.EMPTY);
        assertNotEquals(a, "A");
        assertFalse(a.equals(null));
    }

    @Test
    public void testToStringNamesUnknownTypesInTheRfc3597Form() {
        assertEquals("TYPE0 A", decode(new byte[] { 0x00, 0x01, (byte) 0xc0 }).toString());
    }

    private static DnsTypeBitmap decode(byte[] wire) {
        ByteBuf in = Unpooled.wrappedBuffer(wire);
        try {
            return DnsTypeBitmap.decode(in, wire.length);
        } finally {
            in.release();
        }
    }

    private static void assertDecodeFails(byte[] wire) {
        ByteBuf in = Unpooled.wrappedBuffer(wire);
        try {
            assertThrows(CorruptedFrameException.class, () -> DnsTypeBitmap.decode(in, wire.length));
        } finally {
            in.release();
        }
    }
}
