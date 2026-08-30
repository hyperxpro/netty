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

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnsNsec3RecordTest {

    private static final String NAME = "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.";

    private static final DnsName OWNER = DnsName.fromString(NAME);

    private static final byte[] SALT = { (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd };

    private static DnsNsec3Record newRecord(byte[] rdata) {
        return new DnsNsec3Record(NAME, DnsRecordType.NSEC3, DnsRecord.CLASS_IN, 3600, OWNER,
                Unpooled.wrappedBuffer(rdata));
    }

    @Test
    public void testDecodeZoneApex() {
        DnsNsec3Record record = newRecord(DnssecTestVectors.RFC5155_NSEC3);
        try {
            assertEquals(1, record.hashAlgorithm());
            assertEquals(1, record.flags());
            assertTrue(record.isOptOut());
            assertEquals(12, record.iterations());
            assertArrayEquals(SALT, record.salt());
            assertEquals(20, record.nextHashedOwnerName().length);
            assertArrayEquals(Arrays.copyOfRange(DnssecTestVectors.RFC5155_NSEC3, 10, 30),
                    record.nextHashedOwnerName());
            // MX DNSKEY NS SOA NSEC3PARAM RRSIG
            assertArrayEquals(new int[] { 2, 6, 15, 46, 48, 51 }, record.types().types());
            assertTrue(record.types().contains(DnsRecordType.NSEC3PARAM));
            assertEquals(OWNER, record.owner());
            assertArrayEquals(DnssecTestVectors.RFC5155_NSEC3, ByteBufUtil.getBytes(record.content()));
        } finally {
            record.release();
        }
    }

    /**
     * An NSEC3 that matches an empty non-terminal has no types at all. RFC 6840, section 6.4 corrects the grammar
     * of RFC 5155, section 3.2.1 so that this is inside the specification.
     */
    @Test
    public void testDecodeEmptyNonTerminal() {
        DnsNsec3Record record = newRecord(DnssecTestVectors.RFC5155_NSEC3_EMPTY_NON_TERMINAL);
        try {
            assertTrue(record.isOptOut());
            assertSame(DnsTypeBitmap.EMPTY, record.types());
            assertEquals(20, record.nextHashedOwnerName().length);
        } finally {
            record.release();
        }
    }

    @Test
    public void testOptOutIsTheLeastSignificantFlagBit() {
        byte[] rdata = DnssecTestVectors.RFC5155_NSEC3.clone();
        rdata[1] = (byte) 0xfe;
        DnsNsec3Record record = newRecord(rdata);
        try {
            assertEquals(0xfe, record.flags());
            assertFalse(record.isOptOut());
        } finally {
            record.release();
        }
    }

    @Test
    public void testRejectsAnUnrelatedType() {
        ByteBuf content = Unpooled.wrappedBuffer(DnssecTestVectors.RFC5155_NSEC3);
        try {
            assertThrows(IllegalArgumentException.class, () -> new DnsNsec3Record(
                    NAME, DnsRecordType.NSEC3PARAM, DnsRecord.CLASS_IN, 3600, OWNER, content));
        } finally {
            content.release();
        }
    }

    /**
     * Every prefix short of the complete next hashed owner name has a declared length running past the end of the
     * RDATA, and every one of them is a hard error.
     */
    @Test
    public void testRejectsTruncationAtEveryFieldBoundary() {
        for (int length = 0; length < 30; length++) {
            final int prefix = length;
            ByteBuf content = Unpooled.wrappedBuffer(DnssecTestVectors.RFC5155_NSEC3, 0, prefix);
            try {
                assertThrows(CorruptedFrameException.class, () -> new DnsNsec3Record(
                        NAME, DnsRecordType.NSEC3, DnsRecord.CLASS_IN, 3600, OWNER, content),
                        "an NSEC3 of " + prefix + " octets must not decode");
            } finally {
                content.release();
            }
        }
    }

    @Test
    public void testRejectsASaltThatRunsPastTheRdata() {
        ByteBuf content = Unpooled.buffer()
                .writeByte(0x01).writeByte(0x00).writeShort(12).writeByte(0xff)
                .writeBytes(SALT);
        try {
            assertThrows(CorruptedFrameException.class, () -> new DnsNsec3Record(
                    NAME, DnsRecordType.NSEC3, DnsRecord.CLASS_IN, 3600, OWNER, content));
        } finally {
            content.release();
        }
    }

    @Test
    public void testRejectsAHashThatRunsPastTheRdata() {
        ByteBuf content = Unpooled.buffer()
                .writeByte(0x01).writeByte(0x00).writeShort(12).writeByte(SALT.length)
                .writeBytes(SALT).writeByte(0x14).writeByte(0x00).writeByte(0x01);
        try {
            assertThrows(CorruptedFrameException.class, () -> new DnsNsec3Record(
                    NAME, DnsRecordType.NSEC3, DnsRecord.CLASS_IN, 3600, OWNER, content));
        } finally {
            content.release();
        }
    }

    @Test
    public void testRejectsAMissingHashLengthOctet() {
        ByteBuf content = Unpooled.buffer()
                .writeByte(0x01).writeByte(0x00).writeShort(12).writeByte(SALT.length).writeBytes(SALT);
        try {
            assertThrows(CorruptedFrameException.class, () -> new DnsNsec3Record(
                    NAME, DnsRecordType.NSEC3, DnsRecord.CLASS_IN, 3600, OWNER, content));
        } finally {
            content.release();
        }
    }

    /**
     * RFC 5155, section 3.1.5 omits the salt entirely when its length is zero, which is what RFC 9276, section 3.1
     * now recommends zones do.
     */
    @Test
    public void testAcceptsAnAbsentSalt() {
        ByteBuf content = Unpooled.buffer()
                .writeByte(0x01).writeByte(0x00).writeShort(0).writeByte(0x00)
                .writeByte(0x04).writeBytes(new byte[] { 1, 2, 3, 4 });
        DnsNsec3Record record = new DnsNsec3Record(NAME, DnsRecordType.NSEC3, DnsRecord.CLASS_IN, 3600, OWNER,
                content);
        try {
            assertEquals(0, record.salt().length);
            assertEquals(0, record.iterations());
            assertArrayEquals(new byte[] { 1, 2, 3, 4 }, record.nextHashedOwnerName());
            assertTrue(record.types().isEmpty());
        } finally {
            record.release();
        }
    }

    @Test
    public void testAcceptsTheLargestSaltAndHash() {
        byte[] salt = new byte[255];
        Arrays.fill(salt, (byte) 0x5a);
        byte[] hash = new byte[255];
        Arrays.fill(hash, (byte) 0xa5);
        ByteBuf content = Unpooled.buffer()
                .writeByte(0x01).writeByte(0x01).writeShort(0xffff).writeByte(0xff).writeBytes(salt)
                .writeByte(0xff).writeBytes(hash);
        DnsNsec3Record record = new DnsNsec3Record(NAME, DnsRecordType.NSEC3, DnsRecord.CLASS_IN, 3600, OWNER,
                content);
        try {
            assertEquals(65535, record.iterations());
            assertArrayEquals(salt, record.salt());
            assertArrayEquals(hash, record.nextHashedOwnerName());
        } finally {
            record.release();
        }
    }

    @Test
    public void testCopyKeepsTheConcreteType() {
        DnsNsec3Record record = newRecord(DnssecTestVectors.RFC5155_NSEC3);
        try {
            DnsNsec3Record copy = record.copy();
            try {
                assertArrayEquals(record.salt(), copy.salt());
                assertArrayEquals(record.nextHashedOwnerName(), copy.nextHashedOwnerName());
                assertEquals(record.types(), copy.types());
            } finally {
                copy.release();
            }
            DnsNsec3Record duplicate = record.duplicate();
            assertEquals(12, duplicate.iterations());
            DnsNsec3Record retained = record.retainedDuplicate();
            try {
                assertTrue(retained.isOptOut());
            } finally {
                retained.release();
            }
        } finally {
            record.release();
        }
    }
}
