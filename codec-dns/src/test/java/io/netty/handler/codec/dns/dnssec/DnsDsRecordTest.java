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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class DnsDsRecordTest {

    private static final DnsName OWNER = DnsName.fromString("a.example.");

    private static DnsDsRecord newRecord(DnsRecordType type, byte[] rdata) {
        return new DnsDsRecord("a.example.", type, DnsRecord.CLASS_IN, 3600, OWNER, Unpooled.wrappedBuffer(rdata));
    }

    @Test
    public void testDecode() {
        DnsDsRecord record = newRecord(DnsRecordType.DS, DnssecTestVectors.RFC4035_DS);
        try {
            assertEquals(57855, record.keyTag());
            assertSame(DnssecAlgorithm.RSASHA1, record.algorithm());
            assertSame(DnssecDigestType.SHA1, record.digestType());
            assertArrayEquals(Arrays.copyOfRange(DnssecTestVectors.RFC4035_DS, 4,
                    DnssecTestVectors.RFC4035_DS.length), record.digest());
            assertEquals(20, record.digest().length);
            assertEquals(record.digestType().digestLength(), record.digest().length);
            assertEquals(OWNER, record.owner());
            assertArrayEquals(DnssecTestVectors.RFC4035_DS, ByteBufUtil.getBytes(record.content()));
        } finally {
            record.release();
        }
    }

    @Test
    public void testCdsUsesTheSameLayout() {
        DnsDsRecord record = newRecord(DnsRecordType.CDS, DnssecTestVectors.RFC4035_DS);
        try {
            assertEquals(DnsRecordType.CDS, record.type());
            assertEquals(57855, record.keyTag());
        } finally {
            record.release();
        }
    }

    @Test
    public void testRejectsAnUnrelatedType() {
        ByteBuf content = Unpooled.wrappedBuffer(DnssecTestVectors.RFC4035_DS);
        try {
            assertThrows(IllegalArgumentException.class, () -> new DnsDsRecord(
                    "a.example.", DnsRecordType.DNSKEY, DnsRecord.CLASS_IN, 3600, OWNER, content));
        } finally {
            content.release();
        }
    }

    @Test
    public void testRejectsTruncatedFixedFields() {
        for (int length = 0; length < 4; length++) {
            ByteBuf content = Unpooled.wrappedBuffer(DnssecTestVectors.RFC4035_DS, 0, length);
            try {
                assertThrows(CorruptedFrameException.class, () -> new DnsDsRecord(
                        "a.example.", DnsRecordType.DS, DnsRecord.CLASS_IN, 3600, OWNER, content));
            } finally {
                content.release();
            }
        }
    }

    /**
     * The digest of an unknown digest type has an unknown length, so the length is not checked at all rather than
     * only for the types this implementation happens to know. A digest of the wrong length matches no DNSKEY.
     */
    @Test
    public void testDoesNotCheckTheDigestAgainstItsType() {
        DnsDsRecord record = newRecord(DnsRecordType.DS, new byte[] { (byte) 0xe1, (byte) 0xff, 0x05, 0x02, 0x00 });
        try {
            assertSame(DnssecDigestType.SHA256, record.digestType());
            assertEquals(1, record.digest().length);
        } finally {
            record.release();
        }
    }

    @Test
    public void testAcceptsAnEmptyDigest() {
        DnsDsRecord record = newRecord(DnsRecordType.DS, new byte[] { (byte) 0xe1, (byte) 0xff, 0x05, 0x01 });
        try {
            assertEquals(0, record.digest().length);
        } finally {
            record.release();
        }
    }

    @Test
    public void testCopyKeepsTheConcreteType() {
        DnsDsRecord record = newRecord(DnsRecordType.DS, DnssecTestVectors.RFC4035_DS);
        try {
            DnsDsRecord copy = record.copy();
            try {
                assertEquals(57855, copy.keyTag());
                assertArrayEquals(record.digest(), copy.digest());
                assertEquals(OWNER, copy.owner());
            } finally {
                copy.release();
            }
            DnsDsRecord duplicate = record.duplicate();
            assertEquals(57855, duplicate.keyTag());
            DnsDsRecord retained = record.retainedDuplicate();
            try {
                assertEquals(DnsRecordType.DS, retained.type());
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
        DnsDsRecord record = newRecord(DnsRecordType.DS, DnssecTestVectors.RFC4035_DS);
        try {
            ByteBuf content = record.content();
            content.skipBytes(content.readableBytes());

            DnsDsRecord copy = record.copy();
            try {
                assertSame(DnsDsRecord.class, copy.getClass());
                assertEquals(57855, copy.keyTag());
                assertArrayEquals(record.digest(), copy.digest());
                assertEquals(OWNER, copy.owner());
            } finally {
                copy.release();
            }
            DnsDsRecord duplicate = record.duplicate();
            assertSame(DnsDsRecord.class, duplicate.getClass());
            assertEquals(57855, duplicate.keyTag());
            assertEquals(1, record.refCnt());
            DnsDsRecord retained = record.retainedDuplicate();
            try {
                assertSame(DnsDsRecord.class, retained.getClass());
                assertArrayEquals(record.digest(), retained.digest());
            } finally {
                retained.release();
            }

            assertEquals(1, record.refCnt());
            content.readerIndex(0);
            assertArrayEquals(DnssecTestVectors.RFC4035_DS, ByteBufUtil.getBytes(content));
        } finally {
            record.release();
        }
    }
}
