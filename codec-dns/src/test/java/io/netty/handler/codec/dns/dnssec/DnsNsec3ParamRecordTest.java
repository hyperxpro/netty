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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnsNsec3ParamRecordTest {

    private static final DnsName OWNER = DnsName.fromString("example.");

    private static final byte[] SALT = { (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd };

    private static DnsNsec3ParamRecord newRecord(byte[] rdata) {
        return new DnsNsec3ParamRecord("example.", DnsRecordType.NSEC3PARAM, DnsRecord.CLASS_IN, 0, OWNER,
                Unpooled.wrappedBuffer(rdata));
    }

    @Test
    public void testDecode() {
        DnsNsec3ParamRecord record = newRecord(DnssecTestVectors.RFC5155_NSEC3PARAM);
        try {
            assertEquals(1, record.hashAlgorithm());
            assertEquals(0, record.flags());
            assertEquals(12, record.iterations());
            assertArrayEquals(SALT, record.salt());
            assertEquals(OWNER, record.owner());
            assertArrayEquals(DnssecTestVectors.RFC5155_NSEC3PARAM, ByteBufUtil.getBytes(record.content()));
        } finally {
            record.release();
        }
    }

    @Test
    public void testRejectsAnUnrelatedType() {
        ByteBuf content = Unpooled.wrappedBuffer(DnssecTestVectors.RFC5155_NSEC3PARAM);
        try {
            assertThrows(IllegalArgumentException.class, () -> new DnsNsec3ParamRecord(
                    "example.", DnsRecordType.NSEC3, DnsRecord.CLASS_IN, 0, OWNER, content));
        } finally {
            content.release();
        }
    }

    @Test
    public void testRejectsTruncationAtEveryFieldBoundary() {
        for (int length = 0; length < DnssecTestVectors.RFC5155_NSEC3PARAM.length; length++) {
            final int prefix = length;
            ByteBuf content = Unpooled.wrappedBuffer(DnssecTestVectors.RFC5155_NSEC3PARAM, 0, prefix);
            try {
                assertThrows(CorruptedFrameException.class, () -> new DnsNsec3ParamRecord(
                        "example.", DnsRecordType.NSEC3PARAM, DnsRecord.CLASS_IN, 0, OWNER, content),
                        "an NSEC3PARAM of " + prefix + " octets must not decode");
            } finally {
                content.release();
            }
        }
    }

    /**
     * Every field of an NSEC3PARAM has a declared length, so an octet after the salt is not something to skip: it
     * is covered by the RRSIG over this record, and a reader that ignores it disagrees with one that does not.
     */
    @Test
    public void testRejectsTrailingData() {
        ByteBuf content = Unpooled.buffer()
                .writeBytes(DnssecTestVectors.RFC5155_NSEC3PARAM).writeByte(0x00);
        try {
            CorruptedFrameException e = assertThrows(CorruptedFrameException.class,
                    () -> new DnsNsec3ParamRecord("example.", DnsRecordType.NSEC3PARAM, DnsRecord.CLASS_IN, 0,
                            OWNER, content));
            assertTrue(e.getMessage().contains("trailing"));
        } finally {
            content.release();
        }
    }

    @Test
    public void testAcceptsAnAbsentSalt() {
        DnsNsec3ParamRecord record = newRecord(new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00 });
        try {
            assertEquals(0, record.salt().length);
            assertEquals(0, record.iterations());
        } finally {
            record.release();
        }
    }

    @Test
    public void testCopyKeepsTheConcreteType() {
        DnsNsec3ParamRecord record = newRecord(DnssecTestVectors.RFC5155_NSEC3PARAM);
        try {
            DnsNsec3ParamRecord copy = record.copy();
            try {
                assertArrayEquals(record.salt(), copy.salt());
                assertEquals(record.iterations(), copy.iterations());
            } finally {
                copy.release();
            }
            DnsNsec3ParamRecord duplicate = record.duplicate();
            assertEquals(1, duplicate.hashAlgorithm());
            DnsNsec3ParamRecord retained = record.retainedDuplicate();
            try {
                assertArrayEquals(SALT, retained.salt());
            } finally {
                retained.release();
            }
        } finally {
            record.release();
        }
    }
}
