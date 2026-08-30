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
import io.netty.handler.codec.dns.DefaultDnsRawRecord;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordEncoder;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.Test;

import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnssecDnsRecordCodecTest {

    /**
     * The 12 octets of a DNS message header, which is what every offset in a message is measured from and what
     * makes a compression pointer to offset 12 point at the first name in the message.
     */
    private static final int HEADER_LENGTH = 12;

    /**
     * Lays out one resource record after a message header, so that the decoder sees the same absolute offsets it
     * would see in a real answer. The reader index is left at the start of the record.
     */
    private static ByteBuf message(DnsName owner, DnsRecordType type, long timeToLive, byte[] rdata) {
        ByteBuf buf = Unpooled.buffer();
        buf.writeZero(HEADER_LENGTH);
        owner.writeTo(buf);
        buf.writeShort(type.intValue());
        buf.writeShort(DnsRecord.CLASS_IN);
        buf.writeInt((int) timeToLive);
        buf.writeShort(rdata.length);
        buf.writeBytes(rdata);
        buf.readerIndex(HEADER_LENGTH);
        return buf;
    }

    /**
     * Decodes one record and encodes it again, and requires the octets to come back unchanged. That is the property
     * the whole design of these records rests on: an RRSIG covers the RDATA of the records it signs, so a record
     * that does not survive a decode and an encode cannot be verified after it has been through this codec.
     */
    private static void assertRoundTrips(DnsName owner, DnsRecordType type, byte[] rdata,
                                         Class<? extends DnssecRecord> expected,
                                         Consumer<DnssecRecord> checks) throws Exception {
        ByteBuf message = message(owner, type, 3600, rdata);
        byte[] encoded = ByteBufUtil.getBytes(message, HEADER_LENGTH, message.writerIndex() - HEADER_LENGTH);
        DnsRecord record = DnssecDnsRecordDecoder.INSTANCE.decodeRecord(message);
        try {
            assertSame(expected, record.getClass());
            assertEquals(owner, ((DnssecRecord) record).owner());
            assertEquals(type, record.type());
            assertEquals(3600L, record.timeToLive());
            assertEquals(DnsRecord.CLASS_IN, record.dnsClass());
            assertArrayEquals(rdata, ByteBufUtil.getBytes(((DnssecRecord) record).content()));
            assertEquals(0, message.readableBytes(), "the decoder must consume exactly the record");

            ByteBuf out = Unpooled.buffer();
            try {
                DnssecDnsRecordEncoder.INSTANCE.encodeRecord(record, out);
                assertArrayEquals(encoded, ByteBufUtil.getBytes(out));
            } finally {
                out.release();
            }
            checks.accept((DnssecRecord) record);
        } finally {
            ReferenceCountUtil.release(record);
            message.release();
        }
    }

    @Test
    public void testDnskeyRoundTrip() throws Exception {
        assertRoundTrips(DnsName.fromString("example."), DnsRecordType.DNSKEY,
                DnssecTestVectors.RFC4035_DNSKEY_ZSK, DnsDnskeyRecord.class,
                record -> assertEquals(38519, ((DnsDnskeyRecord) record).keyTag()));
    }

    @Test
    public void testCdnskeyRoundTrip() throws Exception {
        assertRoundTrips(DnsName.fromString("example."), DnsRecordType.CDNSKEY,
                DnssecTestVectors.RFC4035_DNSKEY_KSK, DnsDnskeyRecord.class,
                record -> assertEquals(9465, ((DnsDnskeyRecord) record).keyTag()));
    }

    @Test
    public void testDsRoundTrip() throws Exception {
        assertRoundTrips(DnsName.fromString("a.example."), DnsRecordType.DS, DnssecTestVectors.RFC4035_DS,
                DnsDsRecord.class, record -> assertEquals(57855, ((DnsDsRecord) record).keyTag()));
    }

    @Test
    public void testCdsRoundTrip() throws Exception {
        assertRoundTrips(DnsName.fromString("a.example."), DnsRecordType.CDS, DnssecTestVectors.RFC4035_DS,
                DnsDsRecord.class, record -> assertSame(DnssecDigestType.SHA1, ((DnsDsRecord) record).digestType()));
    }

    @Test
    public void testRrsigRoundTrip() throws Exception {
        assertRoundTrips(DnsName.fromString("example."), DnsRecordType.RRSIG, DnssecTestVectors.RFC4035_RRSIG,
                DnsRrsigRecord.class,
                record -> assertEquals(DnsName.fromString("example."), ((DnsRrsigRecord) record).signerName()));
    }

    @Test
    public void testNsecRoundTrip() throws Exception {
        assertRoundTrips(DnsName.fromString("alfa.example.com."), DnsRecordType.NSEC,
                DnssecTestVectors.RFC4034_NSEC, DnsNsecRecord.class,
                record -> assertEquals(DnsName.fromString("host.example.com."),
                        ((DnsNsecRecord) record).nextDomainName()));
    }

    @Test
    public void testNsec3RoundTrip() throws Exception {
        assertRoundTrips(DnsName.fromString("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example."), DnsRecordType.NSEC3,
                DnssecTestVectors.RFC5155_NSEC3, DnsNsec3Record.class,
                record -> assertTrue(((DnsNsec3Record) record).isOptOut()));
    }

    @Test
    public void testNsec3ParamRoundTrip() throws Exception {
        assertRoundTrips(DnsName.fromString("example."), DnsRecordType.NSEC3PARAM,
                DnssecTestVectors.RFC5155_NSEC3PARAM, DnsNsec3ParamRecord.class,
                record -> assertEquals(12, ((DnsNsec3ParamRecord) record).iterations()));
    }

    /**
     * The owner name of an answer record is nearly always a compression pointer back into the question section, so
     * the owner has to be read against the whole message rather than against the RDATA.
     */
    @Test
    public void testOwnerNameIsResolvedThroughACompressionPointer() throws Exception {
        ByteBuf message = Unpooled.buffer();
        try {
            message.writeZero(HEADER_LENGTH);
            DnsName.fromString("example.").writeTo(message);
            message.writeShort(DnsRecordType.DNSKEY.intValue());
            message.writeShort(DnsRecord.CLASS_IN);
            int recordOffset = message.writerIndex();
            message.writeByte(0xc0).writeByte(HEADER_LENGTH);
            message.writeShort(DnsRecordType.DNSKEY.intValue());
            message.writeShort(DnsRecord.CLASS_IN);
            message.writeInt(3600);
            message.writeShort(DnssecTestVectors.RFC4035_DNSKEY_ZSK.length);
            message.writeBytes(DnssecTestVectors.RFC4035_DNSKEY_ZSK);
            message.readerIndex(recordOffset);

            DnsRecord record = DnssecDnsRecordDecoder.INSTANCE.decodeRecord(message);
            try {
                assertSame(DnsDnskeyRecord.class, record.getClass());
                assertEquals(DnsName.fromString("example."), ((DnssecRecord) record).owner());
                assertEquals(38519, ((DnsDnskeyRecord) record).keyTag());
            } finally {
                ReferenceCountUtil.release(record);
            }
        } finally {
            message.release();
        }
    }

    /**
     * A compression pointer inside the RDATA is rejected even when it would expand to a perfectly good name. Two
     * encodings that expand to the same signer's name would otherwise both be accepted under one signature, which
     * is a way to rewrite signed octets without breaking the signature.
     */
    @Test
    public void testCompressedSignerNameIsRejectedEvenWhenItWouldExpand() throws Exception {
        byte[] rdata = new byte[20];
        System.arraycopy(DnssecTestVectors.RFC4035_RRSIG, 0, rdata, 0, 18);
        rdata[18] = (byte) 0xc0;
        rdata[19] = (byte) HEADER_LENGTH;

        ByteBuf message = Unpooled.buffer();
        try {
            message.writeZero(HEADER_LENGTH);
            DnsName.fromString("example.").writeTo(message);
            message.writeShort(DnsRecordType.RRSIG.intValue());
            message.writeShort(DnsRecord.CLASS_IN);
            int recordOffset = message.writerIndex();
            message.writeByte(0xc0).writeByte(HEADER_LENGTH);
            message.writeShort(DnsRecordType.RRSIG.intValue());
            message.writeShort(DnsRecord.CLASS_IN);
            message.writeInt(3600);
            message.writeShort(rdata.length);
            message.writeBytes(rdata);
            message.readerIndex(recordOffset);

            assertThrows(CorruptedFrameException.class,
                    () -> DnssecDnsRecordDecoder.INSTANCE.decodeRecord(message));
            assertEquals(1, message.refCnt(), "a rejected record must not keep a reference to the message");
        } finally {
            message.release();
        }
    }

    /**
     * The retained duplicate the decoder takes of the message has to go back when the RDATA turns out to be
     * malformed, or every corrupt answer leaks a buffer.
     */
    @Test
    public void testMalformedRdataDoesNotLeakTheMessage() throws Exception {
        ByteBuf message = message(DnsName.fromString("example."), DnsRecordType.DNSKEY, 3600,
                new byte[] { 0x01, 0x00 });
        try {
            assertThrows(CorruptedFrameException.class,
                    () -> DnssecDnsRecordDecoder.INSTANCE.decodeRecord(message));
            assertEquals(1, message.refCnt());
        } finally {
            message.release();
        }
    }

    /**
     * An RRSIG covers ordinary types, so an A record needs an owner name in wire form just as much as a DNSKEY
     * does. Its RDATA is opaque and is passed through untouched.
     */
    @Test
    public void testOrdinaryTypesAlsoCarryTheOwnerNameInWireForm() throws Exception {
        assertRoundTrips(DnsName.fromString("www.example."), DnsRecordType.A,
                new byte[] { (byte) 192, 0, 2, 1 }, DefaultDnssecRawRecord.class,
                record -> assertEquals("www.example.", record.name()));
    }

    @Test
    public void testOptPseudoRecordIsAlsoWrapped() throws Exception {
        ByteBuf message = message(DnsName.ROOT, DnsRecordType.OPT, 0, new byte[0]);
        DnsRecord record = DnssecDnsRecordDecoder.INSTANCE.decodeRecord(message);
        try {
            assertSame(DefaultDnssecRawRecord.class, record.getClass());
            assertTrue(((DnssecRecord) record).owner().isRoot());
        } finally {
            ReferenceCountUtil.release(record);
            message.release();
        }
    }

    /**
     * RFC 4034, section 6.2 down-cases the owner name of every type when canonicalising, so a corpus of
     * lower-case owners never exercises that path. The decoder itself must not fold anything: it hands over the
     * octets it read, and the case decision belongs to the canonicaliser.
     */
    @Test
    public void testOwnerNameKeepsItsCase() throws Exception {
        DnsName mixedCase = DnsName.fromString("ExAmPlE.");
        assertRoundTrips(mixedCase, DnsRecordType.DS, DnssecTestVectors.RFC4035_DS, DnsDsRecord.class,
                record -> assertArrayEquals(mixedCase.toWireBytes(), record.owner().toWireBytes()));
    }

    /**
     * The other half of the RFC 6840, section 5.1 asymmetry: an RRSIG signer's name <em>is</em> down-cased when
     * canonicalising, but not by the decoder, which reports what arrived.
     */
    @Test
    public void testRrsigSignerNameKeepsItsCaseOnTheWire() throws Exception {
        byte[] rdata = DnssecTestVectors.RFC4035_RRSIG.clone();
        // The signer's name starts at octet 18 and is "\007example\000"; upper-case its first two label octets.
        rdata[19] = 'E';
        rdata[20] = 'X';
        assertRoundTrips(DnsName.fromString("example."), DnsRecordType.RRSIG, rdata, DnsRrsigRecord.class,
                record -> {
                    DnsName signer = ((DnsRrsigRecord) record).signerName();
                    assertArrayEquals(DnsName.fromString("EXample.").toWireBytes(), signer.toWireBytes());
                    assertArrayEquals(DnsName.fromString("example.").toWireBytes(),
                            signer.toLowerCase().toWireBytes());
                });
    }

    /**
     * The base decoder returns {@code null} and rewinds when a record does not fit in what has been read; that has
     * to keep working for the DNSSEC types too.
     */
    @Test
    public void testTruncatedMessageIsReportedAsIncomplete() throws Exception {
        ByteBuf message = message(DnsName.fromString("example."), DnsRecordType.DS, 3600,
                DnssecTestVectors.RFC4035_DS);
        try {
            message.writerIndex(message.writerIndex() - 1);
            int readerIndex = message.readerIndex();
            assertNull(DnssecDnsRecordDecoder.INSTANCE.decodeRecord(message));
            assertEquals(readerIndex, message.readerIndex());
            assertEquals(1, message.refCnt());
        } finally {
            message.release();
        }
    }

    /**
     * A label may hold any octet, and DNSSEC signs those octets. {@link io.netty.handler.codec.dns.DnsRecord#name()}
     * has been through a UTF-8 decode and {@link java.net.IDN#toASCII(String)}, so the base encoder cannot write
     * such a name back; the DNSSEC encoder writes {@link DnssecRecord#owner()} instead.
     */
    @Test
    public void testOwnerNameOctetsSurviveAnEncodeTheBaseEncoderWouldMangle() throws Exception {
        // A single label holding the two octets 0xC3 0xA9, which is "e with an acute accent" in UTF-8.
        DnsName owner = DnsName.fromString("\\195\\169.");
        ByteBuf message = message(owner, DnsRecordType.DS, 3600, DnssecTestVectors.RFC4035_DS);
        byte[] encoded = ByteBufUtil.getBytes(message, HEADER_LENGTH, message.writerIndex() - HEADER_LENGTH);
        DnsRecord record = DnssecDnsRecordDecoder.INSTANCE.decodeRecord(message);
        try {
            assertEquals(owner, ((DnssecRecord) record).owner());

            ByteBuf ours = Unpooled.buffer();
            ByteBuf base = Unpooled.buffer();
            try {
                DnssecDnsRecordEncoder.INSTANCE.encodeRecord(record, ours);
                assertArrayEquals(encoded, ByteBufUtil.getBytes(ours));

                DnsRecordEncoder.DEFAULT.encodeRecord(record, base);
                assertFalse(ByteBufUtil.equals(ours, base),
                        "the base encoder is expected to lose these octets, which is why this class exists");
            } finally {
                ours.release();
                base.release();
            }
        } finally {
            ReferenceCountUtil.release(record);
            message.release();
        }
    }

    /**
     * The same property for an ordinary type, which goes through {@link DefaultDnssecRawRecord} rather than
     * through a typed record. This is the case that matters most: an {@code RRSIG} over an {@code A} RRset is
     * verified against the owner name's octets, and this is the path that carries them.
     */
    @Test
    public void testOrdinaryTypeAlsoKeepsAnOwnerNameTheBaseEncoderWouldMangle() throws Exception {
        DnsName owner = DnsName.fromString("\\195\\169.example.");
        byte[] rdata = { (byte) 192, 0, 2, 1 };
        ByteBuf message = message(owner, DnsRecordType.A, 3600, rdata);
        byte[] encoded = ByteBufUtil.getBytes(message, HEADER_LENGTH, message.writerIndex() - HEADER_LENGTH);
        DnsRecord record = DnssecDnsRecordDecoder.INSTANCE.decodeRecord(message);
        try {
            assertSame(DefaultDnssecRawRecord.class, record.getClass());
            assertArrayEquals(owner.toWireBytes(), ((DnssecRecord) record).owner().toWireBytes());
            assertArrayEquals(rdata, ByteBufUtil.getBytes(((DnssecRecord) record).content()));

            ByteBuf ours = Unpooled.buffer();
            ByteBuf base = Unpooled.buffer();
            try {
                DnssecDnsRecordEncoder.INSTANCE.encodeRecord(record, ours);
                assertArrayEquals(encoded, ByteBufUtil.getBytes(ours));

                DnsRecordEncoder.DEFAULT.encodeRecord(record, base);
                assertFalse(ByteBufUtil.equals(ours, base),
                        "the base encoder is expected to lose these octets, which is why the owner name is"
                                + " carried separately");
            } finally {
                ours.release();
                base.release();
            }
        } finally {
            ReferenceCountUtil.release(record);
            message.release();
        }
    }

    @Test
    public void testEncoderLeavesOtherRecordsToTheSuperclass() throws Exception {
        ByteBuf rdata = Unpooled.wrappedBuffer(new byte[] { (byte) 192, 0, 2, 1 });
        DefaultDnsRawRecord record = new DefaultDnsRawRecord("example.", DnsRecordType.A, 3600, rdata);
        ByteBuf ours = Unpooled.buffer();
        ByteBuf base = Unpooled.buffer();
        try {
            DnssecDnsRecordEncoder.INSTANCE.encodeRecord(record, ours);
            DnsRecordEncoder.DEFAULT.encodeRecord(record, base);
            assertTrue(ByteBufUtil.equals(ours, base));
        } finally {
            ours.release();
            base.release();
            record.release();
        }
    }
}
