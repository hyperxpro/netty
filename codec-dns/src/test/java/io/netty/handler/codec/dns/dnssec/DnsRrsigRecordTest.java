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
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnsRrsigRecordTest {

    private static final DnsName OWNER = DnsName.fromString("example.");

    /**
     * Everything before the signer's name: type covered, algorithm, labels, original TTL, expiration, inception
     * and key tag.
     */
    private static final int FIXED_LENGTH = 18;

    private static DnsRrsigRecord newRecord(byte[] rdata) {
        return new DnsRrsigRecord("example.", DnsRecordType.RRSIG, DnsRecord.CLASS_IN, 3600, OWNER,
                Unpooled.wrappedBuffer(rdata));
    }

    /**
     * The fixed fields of the RFC 4035 vector followed by {@code tail}, which stands in for the signer's name and
     * the signature.
     */
    private static byte[] withTail(byte... tail) {
        byte[] rdata = new byte[FIXED_LENGTH + tail.length];
        System.arraycopy(DnssecTestVectors.RFC4035_RRSIG, 0, rdata, 0, FIXED_LENGTH);
        System.arraycopy(tail, 0, rdata, FIXED_LENGTH, tail.length);
        return rdata;
    }

    @Test
    public void testDecode() {
        DnsRrsigRecord record = newRecord(DnssecTestVectors.RFC4035_RRSIG);
        try {
            assertEquals(DnsRecordType.NSEC, record.typeCovered());
            assertSame(DnssecAlgorithm.RSASHA1, record.algorithm());
            assertEquals(1, record.labels());
            assertEquals(3600L, record.originalTtl());
            // 20040509183619 and 20040409183619 UTC.
            assertEquals(1084127779L, record.expiration());
            assertEquals(1081535779L, record.inception());
            assertEquals(38519, record.keyTag());
            assertEquals(DnsName.fromString("example."), record.signerName());
            assertEquals(128, record.signature().length);
            assertArrayEquals(Arrays.copyOfRange(DnssecTestVectors.RFC4035_RRSIG, FIXED_LENGTH + 9,
                    DnssecTestVectors.RFC4035_RRSIG.length), record.signature());
            assertEquals(OWNER, record.owner());
            assertArrayEquals(DnssecTestVectors.RFC4035_RRSIG, ByteBufUtil.getBytes(record.content()));
        } finally {
            record.release();
        }
    }

    /**
     * The timestamps are 32-bit unsigned seconds, so they run past {@link Integer#MAX_VALUE} in 2038 and must not
     * come back negative.
     */
    @Test
    public void testTimestampsAreUnsigned() {
        DnsRrsigRecord record = newRecord(withTail(
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00));
        try {
            assertEquals(0x409e7a23L, record.expiration());
        } finally {
            record.release();
        }
        byte[] rdata = DnssecTestVectors.RFC4035_RRSIG.clone();
        Arrays.fill(rdata, 4, 16, (byte) 0xff);
        DnsRrsigRecord maxima = newRecord(rdata);
        try {
            assertEquals(0xffffffffL, maxima.originalTtl());
            assertEquals(0xffffffffL, maxima.expiration());
            assertEquals(0xffffffffL, maxima.inception());
        } finally {
            maxima.release();
        }
    }

    @Test
    public void testRejectsAnUnrelatedType() {
        ByteBuf content = Unpooled.wrappedBuffer(DnssecTestVectors.RFC4035_RRSIG);
        try {
            assertThrows(IllegalArgumentException.class, () -> new DnsRrsigRecord(
                    "example.", DnsRecordType.NSEC, DnsRecord.CLASS_IN, 3600, OWNER, content));
        } finally {
            content.release();
        }
    }

    /**
     * Every prefix of the record that stops before the signer's name is complete is a hard error. Stopping early
     * and reporting the fields that did fit would hand a validator a record no signature covers.
     */
    @Test
    public void testRejectsTruncationAtEveryFieldBoundary() {
        for (int length = 0; length <= FIXED_LENGTH + 8; length++) {
            final int prefix = length;
            ByteBuf content = Unpooled.wrappedBuffer(DnssecTestVectors.RFC4035_RRSIG, 0, prefix);
            try {
                assertThrows(CorruptedFrameException.class, () -> new DnsRrsigRecord(
                        "example.", DnsRecordType.RRSIG, DnsRecord.CLASS_IN, 3600, OWNER, content),
                        "an RRSIG of " + prefix + " octets must not decode");
            } finally {
                content.release();
            }
        }
    }

    /**
     * RFC 4034, section 3.1.7 says the signer's name is not compressed, and RFC 3597, section 4 forbids compression
     * in the RDATA of these types generally. Expanding a pointer anyway would give two wire encodings that a single
     * signature covers, so the pointer is rejected.
     */
    @Test
    public void testRejectsACompressedSignerName() {
        byte[] rdata = withTail((byte) 0xc0, (byte) 0x00);
        ByteBuf content = Unpooled.wrappedBuffer(rdata);
        try {
            CorruptedFrameException e = assertThrows(CorruptedFrameException.class, () -> new DnsRrsigRecord(
                    "example.", DnsRecordType.RRSIG, DnsRecord.CLASS_IN, 3600, OWNER, content));
            assertTrue(e.getMessage().contains("compressed"));
        } finally {
            content.release();
        }
    }

    @Test
    public void testRejectsAReservedLabelTypeInTheSignerName() {
        for (int labelType : new int[] { 0x40, 0x80 }) {
            byte[] rdata = withTail((byte) labelType, (byte) 0x00);
            ByteBuf content = Unpooled.wrappedBuffer(rdata);
            try {
                assertThrows(CorruptedFrameException.class, () -> new DnsRrsigRecord(
                        "example.", DnsRecordType.RRSIG, DnsRecord.CLASS_IN, 3600, OWNER, content));
            } finally {
                content.release();
            }
        }
    }

    @Test
    public void testRejectsASignerNameThatRunsPastTheRdata() {
        byte[] rdata = withTail((byte) 0x07, (byte) 'e', (byte) 'x', (byte) 'a');
        ByteBuf content = Unpooled.wrappedBuffer(rdata);
        try {
            assertThrows(CorruptedFrameException.class, () -> new DnsRrsigRecord(
                    "example.", DnsRecordType.RRSIG, DnsRecord.CLASS_IN, 3600, OWNER, content));
        } finally {
            content.release();
        }
    }

    @Test
    public void testRejectsAnUnterminatedSignerName() {
        byte[] rdata = withTail((byte) 0x01, (byte) 'a');
        ByteBuf content = Unpooled.wrappedBuffer(rdata);
        try {
            assertThrows(CorruptedFrameException.class, () -> new DnsRrsigRecord(
                    "example.", DnsRecordType.RRSIG, DnsRecord.CLASS_IN, 3600, OWNER, content));
        } finally {
            content.release();
        }
    }

    /**
     * The root as a signer's name is one octet and leaves the rest of the RDATA to the signature.
     */
    @Test
    public void testAcceptsTheRootAsSignerName() {
        DnsRrsigRecord record = newRecord(withTail((byte) 0x00, (byte) 0x2a, (byte) 0x2b));
        try {
            assertTrue(record.signerName().isRoot());
            assertArrayEquals(new byte[] { 0x2a, 0x2b }, record.signature());
        } finally {
            record.release();
        }
    }

    @Test
    public void testAcceptsAnEmptySignature() {
        DnsRrsigRecord record = newRecord(withTail((byte) 0x00));
        try {
            assertEquals(0, record.signature().length);
        } finally {
            record.release();
        }
    }

    @Test
    public void testCopyKeepsTheConcreteType() {
        DnsRrsigRecord record = newRecord(DnssecTestVectors.RFC4035_RRSIG);
        try {
            DnsRrsigRecord copy = record.copy();
            try {
                assertEquals(38519, copy.keyTag());
                assertEquals(record.signerName(), copy.signerName());
                assertArrayEquals(record.signature(), copy.signature());
            } finally {
                copy.release();
            }
            DnsRrsigRecord duplicate = record.duplicate();
            assertEquals(DnsRecordType.NSEC, duplicate.typeCovered());
            DnsRrsigRecord retained = record.retainedDuplicate();
            try {
                assertEquals(1084127779L, retained.expiration());
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
        DnsRrsigRecord record = newRecord(DnssecTestVectors.RFC4035_RRSIG);
        try {
            ByteBuf content = record.content();
            content.skipBytes(content.readableBytes());

            DnsRrsigRecord copy = record.copy();
            try {
                assertSame(DnsRrsigRecord.class, copy.getClass());
                assertEquals(38519, copy.keyTag());
                assertEquals(record.signerName(), copy.signerName());
                assertArrayEquals(record.signature(), copy.signature());
            } finally {
                copy.release();
            }
            DnsRrsigRecord duplicate = record.duplicate();
            assertSame(DnsRrsigRecord.class, duplicate.getClass());
            assertEquals(DnsRecordType.NSEC, duplicate.typeCovered());
            assertEquals(1, record.refCnt());
            DnsRrsigRecord retained = record.retainedDuplicate();
            try {
                assertSame(DnsRrsigRecord.class, retained.getClass());
                assertEquals(1084127779L, retained.expiration());
            } finally {
                retained.release();
            }

            assertEquals(1, record.refCnt());
            content.readerIndex(0);
            assertArrayEquals(DnssecTestVectors.RFC4035_RRSIG, ByteBufUtil.getBytes(content));
        } finally {
            record.release();
        }
    }
}
