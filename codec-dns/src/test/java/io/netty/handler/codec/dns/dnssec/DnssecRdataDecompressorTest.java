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
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsPtrRecord;
import io.netty.handler.codec.dns.DnsRawRecord;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordDecoder;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Expansion of the compressed domain names that RFC 3597, section 4 allows inside the {@code RDATA} of a fixed set
 * of types, and the pass-through of everything else.
 */
public class DnssecRdataDecompressorTest {

    /**
     * A DNS message header is 12 octets, so the first name in a message is at offset 12 and a pointer to it is
     * {@code 0xc0 0x0c}.
     */
    private static final int POINTER_TARGET = 12;

    private static final byte[] POINTER = { (byte) 0xc0, (byte) POINTER_TARGET };

    private static final byte[] SOA_NUMBERS = {
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00,
            0x01, 0x2c, 0x00, 0x36, (byte) 0xee, (byte) 0x80, 0x00, 0x00, 0x0e, 0x10
    };

    /**
     * Lays out a message whose first name is {@code target}, so that {@code 0xc0 0x0c} inside the RDATA that
     * follows expands to it. The reader index is left at the start of the record.
     */
    private static ByteBuf message(String target, DnsRecordType type, byte[] rdata) {
        ByteBuf buf = Unpooled.buffer();
        buf.writeZero(POINTER_TARGET);
        DnsName.fromString(target).writeTo(buf);
        int recordOffset = buf.writerIndex();
        DnsName.fromString("owner.example.").writeTo(buf);
        buf.writeShort(type.intValue());
        buf.writeShort(DnsRecord.CLASS_IN);
        buf.writeInt(3600);
        buf.writeShort(rdata.length);
        buf.writeBytes(rdata);
        buf.readerIndex(recordOffset);
        return buf;
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] joined = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, joined, offset, part.length);
            offset += part.length;
        }
        return joined;
    }

    /**
     * Decodes one record and asserts what its RDATA came out as. {@code sharesTheMessage} says whether the RDATA
     * was passed through, which is observable as a second reference on the message buffer: an expanded RDATA lives
     * in a buffer of its own, an untouched one is a retained duplicate of the message.
     */
    private static void assertRdata(ByteBuf message, byte[] expected, boolean sharesTheMessage) throws Exception {
        DnsRecord record = DnssecDnsRecordDecoder.INSTANCE.decodeRecord(message);
        try {
            assertArrayEquals(expected, ByteBufUtil.getBytes(((DnssecRecord) record).content()));
            assertEquals(DnsName.fromString("owner.example."), ((DnssecRecord) record).owner());
            assertEquals(sharesTheMessage ? 2 : 1, message.refCnt(),
                    sharesTheMessage ? "the RDATA should have been passed through"
                            : "the RDATA should have been expanded into its own buffer");
        } finally {
            ReferenceCountUtil.release(record);
            message.release();
        }
    }

    @Test
    public void testExpandsACompressedCname() throws Exception {
        ByteBuf message = message("a.example.", DnsRecordType.CNAME, POINTER);
        assertRdata(message, DnsName.fromString("a.example.").toWireBytes(), false);
    }

    @Test
    public void testExpandsBothNamesOfASoa() throws Exception {
        ByteBuf message = message("a.example.", DnsRecordType.SOA,
                concat(POINTER, POINTER, SOA_NUMBERS));
        byte[] name = DnsName.fromString("a.example.").toWireBytes();
        assertRdata(message, concat(name, name, SOA_NUMBERS), false);
    }

    @Test
    public void testExpandsAnMxAfterItsPreference() throws Exception {
        ByteBuf message = message("a.example.", DnsRecordType.MX,
                concat(new byte[] { 0x00, 0x0a }, POINTER));
        assertRdata(message, concat(new byte[] { 0x00, 0x0a },
                DnsName.fromString("a.example.").toWireBytes()), false);
    }

    @Test
    public void testExpandsAnSrvAfterItsSixFixedOctets() throws Exception {
        ByteBuf message = message("a.example.", DnsRecordType.SRV,
                concat(new byte[] { 0x00, 0x01, 0x00, 0x02, 0x1f, 0x40 }, POINTER));
        assertRdata(message, concat(new byte[] { 0x00, 0x01, 0x00, 0x02, 0x1f, 0x40 },
                DnsName.fromString("a.example.").toWireBytes()), false);
    }

    /**
     * NAPTR puts three character-strings of its own between the fixed fields and the replacement name, so the name
     * cannot be found at a fixed offset.
     */
    @Test
    public void testExpandsANaptrPastItsCharacterStrings() throws Exception {
        byte[] prefix = { 0x00, 0x0a, 0x00, 0x14, 0x01, 'u', 0x02, 'x', 'y', 0x00 };
        ByteBuf message = message("a.example.", DnsRecordType.NAPTR, concat(prefix, POINTER));
        assertRdata(message, concat(prefix, DnsName.fromString("a.example.").toWireBytes()), false);
    }

    /**
     * The superclass expands a CNAME by rendering the name as text and encoding the text again, which loses any
     * octet that is not printable ASCII. Expanding the octets directly does not.
     */
    @Test
    public void testExpansionKeepsOctetsThatAreNotAscii() throws Exception {
        // One label holding 0xC3 0xA9, which is "e with an acute accent" in UTF-8.
        DnsName target = DnsName.fromString("\\195\\169.");
        ByteBuf message = message("\\195\\169.", DnsRecordType.CNAME, POINTER);
        byte[] ours;
        DnsRecord record = DnssecDnsRecordDecoder.INSTANCE.decodeRecord(message);
        try {
            ours = ByteBufUtil.getBytes(((DnssecRecord) record).content());
            assertArrayEquals(target.toWireBytes(), ours);
        } finally {
            ReferenceCountUtil.release(record);
        }

        message.readerIndex(POINTER_TARGET + target.wireLength());
        DnsRecord viaSuperclass = DnsRecordDecoder.DEFAULT.decodeRecord(message);
        try {
            byte[] theirs = ByteBufUtil.getBytes(((DnsRawRecord) viaSuperclass).content());
            assertFalse(Arrays.equals(ours, theirs),
                    "the superclass is expected to lose these octets, which is why this expander exists");
        } finally {
            ReferenceCountUtil.release(viaSuperclass);
            message.release();
        }
    }

    /**
     * A PTR keeps its {@link DnsPtrRecord} interface, and gains the RDATA and owner name that canonicalisation
     * needs.
     */
    @Test
    public void testPtrIsBothAPointerRecordAndADnssecRecord() throws Exception {
        ByteBuf message = message("a.example.", DnsRecordType.PTR, POINTER);
        DnsRecord record = DnssecDnsRecordDecoder.INSTANCE.decodeRecord(message);
        try {
            assertSame(DefaultDnssecPtrRecord.class, record.getClass());
            assertTrue(record instanceof DnsPtrRecord);
            assertEquals("a.example.", ((DnsPtrRecord) record).hostname());
            assertArrayEquals(DnsName.fromString("a.example.").toWireBytes(),
                    ByteBufUtil.getBytes(((DnssecRecord) record).content()));
        } finally {
            ReferenceCountUtil.release(record);
            message.release();
        }
    }

    /**
     * A compressible type that is not actually compressed is left exactly as it arrived, which keeps the common
     * case free of a copy and keeps the record byte-identical on the way back out.
     */
    @Test
    public void testUncompressedRdataIsPassedThrough() throws Exception {
        byte[] rdata = DnsName.fromString("a.example.").toWireBytes();
        assertRdata(message("other.example.", DnsRecordType.CNAME, rdata), rdata, true);
    }

    /**
     * RFC 3597, section 4 forbids compression in the RDATA of any type it does not list, so an octet that looks
     * like a pointer there is data. Expanding it would let two wire encodings share one canonical form.
     */
    @Test
    public void testRdataOfANonCompressibleTypeIsNeverExpanded() throws Exception {
        byte[] looksLikeAPointer = { 0x03, (byte) 0xc0, (byte) POINTER_TARGET, 0x21 };
        assertRdata(message("a.example.", DnsRecordType.TXT, looksLikeAPointer), looksLikeAPointer, true);
        assertRdata(message("a.example.", DnsRecordType.valueOf(0xff00), POINTER), POINTER, true);
        assertRdata(message("a.example.", DnsRecordType.AAAA, POINTER), POINTER, true);
    }

    /**
     * An RRSIG signer's name and an NSEC next domain name are never expanded either: they are in the
     * non-compressible set, and their own parsers reject a pointer outright.
     */
    @Test
    public void testDnssecTypesAreNotInTheCompressibleSet() throws Exception {
        ByteBuf message = message("example.", DnsRecordType.RRSIG,
                concat(Arrays.copyOf(DnssecTestVectors.RFC4035_RRSIG, 18), POINTER));
        try {
            assertThrows(CorruptedFrameException.class,
                    () -> DnssecDnsRecordDecoder.INSTANCE.decodeRecord(message));
            assertEquals(1, message.refCnt());
        } finally {
            message.release();
        }
    }

    /**
     * A record whose RDATA does not fit the layout of its type but holds no compression pointer needs no
     * expansion: its octets are already the ones a signature would cover. Refusing to decode the whole message
     * over one broken record would be a worse trade than passing it through.
     */
    @Test
    public void testMalformedButUncompressedRdataIsPassedThrough() throws Exception {
        byte[] shortSoa = concat(DnsName.fromString("a.example.").toWireBytes(),
                DnsName.fromString("b.example.").toWireBytes(), new byte[19]);
        assertRdata(message("other.example.", DnsRecordType.SOA, shortSoa), shortSoa, true);

        byte[] truncatedMx = { 0x00 };
        assertRdata(message("other.example.", DnsRecordType.MX, truncatedMx), truncatedMx, true);
    }

    /**
     * When the RDATA is both compressed and malformed there is no way to produce a canonical form, and guessing at
     * one would be worse than failing.
     */
    @Test
    public void testMalformedAndCompressedRdataIsRejected() throws Exception {
        ByteBuf message = message("a.example.", DnsRecordType.SOA, concat(POINTER, POINTER, new byte[19]));
        try {
            CorruptedFrameException e = assertThrows(CorruptedFrameException.class,
                    () -> DnssecDnsRecordDecoder.INSTANCE.decodeRecord(message));
            assertTrue(e.getMessage().contains("cannot be expanded"));
            assertEquals(1, message.refCnt(), "a rejected record must not keep a reference to the message");
        } finally {
            message.release();
        }
    }

    /**
     * A name that starts inside the RDATA but reaches past its end would be read out of the following record.
     */
    @Test
    public void testANameRunningPastTheRdataIsRejectedWhenCompressed() throws Exception {
        ByteBuf message = message("a.example.", DnsRecordType.CNAME, new byte[] { (byte) 0xc0 });
        try {
            assertThrows(CorruptedFrameException.class,
                    () -> DnssecDnsRecordDecoder.INSTANCE.decodeRecord(message));
        } finally {
            message.release();
        }
    }

    /**
     * Expanding changes the RDLENGTH, so a record that arrived compressed goes back out longer than it came in.
     * It goes back out identical to the same record sent uncompressed, which is the form a signature covers.
     */
    @Test
    public void testACompressedRecordReEncodesToItsUncompressedForm() throws Exception {
        ByteBuf compressed = message("a.example.", DnsRecordType.CNAME, POINTER);
        ByteBuf expected = message("other.example.", DnsRecordType.CNAME,
                DnsName.fromString("a.example.").toWireBytes());
        ByteBuf out = Unpooled.buffer();
        DnsRecord record = DnssecDnsRecordDecoder.INSTANCE.decodeRecord(compressed);
        try {
            DnssecDnsRecordEncoder.INSTANCE.encodeRecord(record, out);
            byte[] uncompressedRecord = ByteBufUtil.getBytes(expected, expected.readerIndex(),
                    expected.writerIndex() - expected.readerIndex());
            assertArrayEquals(uncompressedRecord, ByteBufUtil.getBytes(out));
        } finally {
            ReferenceCountUtil.release(record);
            out.release();
            compressed.release();
            expected.release();
        }
    }
}
