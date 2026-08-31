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
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnsNsecRecordTest {

    private static final DnsName OWNER = DnsName.fromString("alfa.example.com.");

    private static DnsNsecRecord newRecord(byte[] rdata) {
        return new DnsNsecRecord("alfa.example.com.", DnsRecordType.NSEC, DnsRecord.CLASS_IN, 86400, OWNER,
                Unpooled.wrappedBuffer(rdata));
    }

    /**
     * The record whose encoding RFC 4034, section 4.3 spells out octet by octet.
     */
    @Test
    public void testDecodeRfc4034Example() {
        DnsNsecRecord record = newRecord(DnssecTestVectors.RFC4034_NSEC);
        try {
            assertEquals(DnsName.fromString("host.example.com."), record.nextDomainName());
            assertArrayEquals(new int[] { 1, 15, 46, 47, 1234 }, record.types().types());
            assertTrue(record.types().contains(DnsRecordType.A));
            assertTrue(record.types().contains(DnsRecordType.MX));
            assertTrue(record.types().contains(DnsRecordType.RRSIG));
            assertTrue(record.types().contains(DnsRecordType.NSEC));
            assertTrue(record.types().contains(1234));
            assertFalse(record.types().contains(DnsRecordType.AAAA));
            assertEquals(OWNER, record.owner());
            assertArrayEquals(DnssecTestVectors.RFC4034_NSEC, ByteBufUtil.getBytes(record.content()));
        } finally {
            record.release();
        }
    }

    @Test
    public void testDecodeRfc4035ZoneApex() {
        DnsNsecRecord record = new DnsNsecRecord("example.", DnsRecordType.NSEC, DnsRecord.CLASS_IN, 3600,
                DnsName.fromString("example."), Unpooled.wrappedBuffer(DnssecTestVectors.RFC4035_NSEC));
        try {
            assertEquals(DnsName.fromString("a.example."), record.nextDomainName());
            assertArrayEquals(new int[] { 2, 6, 15, 46, 47, 48 }, record.types().types());
        } finally {
            record.release();
        }
    }

    @Test
    public void testRejectsAnUnrelatedType() {
        ByteBuf content = Unpooled.wrappedBuffer(DnssecTestVectors.RFC4034_NSEC);
        try {
            assertThrows(IllegalArgumentException.class, () -> new DnsNsecRecord(
                    "alfa.example.com.", DnsRecordType.NSEC3, DnsRecord.CLASS_IN, 86400, OWNER, content));
        } finally {
            content.release();
        }
    }

    /**
     * RFC 4034, section 4.1.1 requires the next domain name to be uncompressed, and RFC 3597, section 4 says the
     * same for the RDATA of any type a server does not know. Expanding a pointer here would make two different
     * encodings of one NSEC verify under the same signature.
     */
    @Test
    public void testRejectsACompressedNextDomainName() {
        ByteBuf content = Unpooled.buffer().writeByte(0xc0).writeByte(0x00).writeByte(0x00).writeByte(0x01)
                .writeByte(0x40);
        try {
            CorruptedFrameException e = assertThrows(CorruptedFrameException.class, () -> new DnsNsecRecord(
                    "alfa.example.com.", DnsRecordType.NSEC, DnsRecord.CLASS_IN, 86400, OWNER, content));
            assertTrue(e.getMessage().contains("compressed"));
        } finally {
            content.release();
        }
    }

    @Test
    public void testRejectsTruncationInsideTheNextDomainName() {
        for (int length = 0; length < 18; length++) {
            ByteBuf content = Unpooled.wrappedBuffer(DnssecTestVectors.RFC4034_NSEC, 0, length);
            try {
                assertThrows(CorruptedFrameException.class, () -> new DnsNsecRecord(
                        "alfa.example.com.", DnsRecordType.NSEC, DnsRecord.CLASS_IN, 86400, OWNER, content));
            } finally {
                content.release();
            }
        }
    }

    @Test
    public void testRejectsATruncatedTypeBitMap() {
        // "a." followed by a window that announces four octets but only carries three.
        ByteBuf content = Unpooled.buffer().writeByte(0x01).writeByte('a').writeByte(0x00)
                .writeByte(0x00).writeByte(0x04).writeByte(0x40).writeByte(0x00).writeByte(0x00);
        try {
            assertThrows(CorruptedFrameException.class, () -> new DnsNsecRecord(
                    "alfa.example.com.", DnsRecordType.NSEC, DnsRecord.CLASS_IN, 86400, OWNER, content));
        } finally {
            content.release();
        }
    }

    /**
     * The RDATA of an NSEC whose next name is the root and which asserts nothing. RFC 4034, section 4.1.2 writes
     * the field as one or more blocks, so this is outside the grammar, but nothing is gained by refusing to decode
     * it: an empty bitmap asserts no type, which is what a validator will conclude either way.
     */
    @Test
    public void testAcceptsAnEmptyTypeBitMap() {
        DnsNsecRecord record = newRecord(new byte[] { 0x00 });
        try {
            assertTrue(record.nextDomainName().isRoot());
            assertSame(DnsTypeBitmap.EMPTY, record.types());
            assertTrue(record.types().isEmpty());
        } finally {
            record.release();
        }
    }

    /**
     * RFC 6840, section 5.1 withdrew the down-casing of names inside RDATA that RFC 4034, section 6.2 had
     * required, so the next domain name keeps the case it arrived with.
     */
    @Test
    public void testNextDomainNameKeepsItsCase() {
        DnsNsecRecord record = newRecord(new byte[] { 0x02, 'A', 'b', 0x00 });
        try {
            assertArrayEquals(new byte[] { 0x02, 'A', 'b', 0x00 }, record.nextDomainName().toWireBytes());
        } finally {
            record.release();
        }
    }

    @Test
    public void testCopyKeepsTheConcreteType() {
        DnsNsecRecord record = newRecord(DnssecTestVectors.RFC4034_NSEC);
        try {
            DnsNsecRecord copy = record.copy();
            try {
                assertEquals(record.nextDomainName(), copy.nextDomainName());
                assertEquals(record.types(), copy.types());
            } finally {
                copy.release();
            }
            DnsNsecRecord duplicate = record.duplicate();
            assertEquals(record.nextDomainName(), duplicate.nextDomainName());
            DnsNsecRecord retained = record.retainedDuplicate();
            try {
                assertEquals(record.types(), retained.types());
            } finally {
                retained.release();
            }
        } finally {
            record.release();
        }
    }

    /**
     * {@code copy}, {@code duplicate} and {@code retainedDuplicate} must keep working once a caller has read from
     * {@code content()}, the way they do on {@code DefaultDnsRawRecord}. Routing them through {@code replace},
     * which re-parses, made them throw on a perfectly valid record, and because {@code duplicate()} shares this
     * record's reference count the release-on-failure then freed a live record's buffer.
     */
    @Test
    public void testCopyOfAConsumedRecordKeepsTheParsedFields() {
        DnsNsecRecord record = newRecord(DnssecTestVectors.RFC4034_NSEC);
        try {
            ByteBuf content = record.content();
            content.skipBytes(content.readableBytes());

            DnsNsecRecord copy = record.copy();
            try {
                assertSame(DnsNsecRecord.class, copy.getClass());
                assertEquals(record.nextDomainName(), copy.nextDomainName());
                assertEquals(record.types(), copy.types());
            } finally {
                copy.release();
            }
            DnsNsecRecord duplicate = record.duplicate();
            assertSame(DnsNsecRecord.class, duplicate.getClass());
            assertEquals(record.nextDomainName(), duplicate.nextDomainName());
            assertEquals(1, record.refCnt());
            DnsNsecRecord retained = record.retainedDuplicate();
            try {
                assertSame(DnsNsecRecord.class, retained.getClass());
                assertEquals(record.types(), retained.types());
            } finally {
                retained.release();
            }

            assertEquals(1, record.refCnt());
            content.readerIndex(0);
            assertArrayEquals(DnssecTestVectors.RFC4034_NSEC, ByteBufUtil.getBytes(content));
        } finally {
            record.release();
        }
    }
}
