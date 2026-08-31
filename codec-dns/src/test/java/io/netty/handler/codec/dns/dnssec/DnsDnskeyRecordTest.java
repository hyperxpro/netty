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

public class DnsDnskeyRecordTest {

    private static final DnsName OWNER = DnsName.fromString("example.");

    private static DnsDnskeyRecord newRecord(byte[] rdata) {
        return newRecord(DnsRecordType.DNSKEY, rdata);
    }

    private static DnsDnskeyRecord newRecord(DnsRecordType type, byte[] rdata) {
        return new DnsDnskeyRecord("example.", type, DnsRecord.CLASS_IN, 3600, OWNER,
                Unpooled.wrappedBuffer(rdata));
    }

    @Test
    public void testDecodeZoneSigningKey() {
        DnsDnskeyRecord record = newRecord(DnssecTestVectors.RFC4035_DNSKEY_ZSK);
        try {
            assertEquals(256, record.flags());
            assertEquals(3, record.protocol());
            assertSame(DnssecAlgorithm.RSASHA1, record.algorithm());
            assertEquals(38519, record.keyTag());
            assertTrue(record.isZoneKey());
            assertFalse(record.isSecureEntryPoint());
            assertFalse(record.isRevoked());
            assertArrayEquals(Arrays.copyOfRange(DnssecTestVectors.RFC4035_DNSKEY_ZSK, 4,
                    DnssecTestVectors.RFC4035_DNSKEY_ZSK.length), record.publicKey());
            assertEquals(OWNER, record.owner());
            assertEquals(DnsRecordType.DNSKEY, record.type());
        } finally {
            record.release();
        }
    }

    @Test
    public void testDecodeKeySigningKey() {
        DnsDnskeyRecord record = newRecord(DnssecTestVectors.RFC4035_DNSKEY_KSK);
        try {
            assertEquals(257, record.flags());
            assertEquals(9465, record.keyTag());
            assertTrue(record.isZoneKey());
            assertTrue(record.isSecureEntryPoint());
            assertFalse(record.isRevoked());
        } finally {
            record.release();
        }
    }

    /**
     * RFC 5011, section 2.1 puts the REVOKE bit inside the key tag calculation, so revoking a key changes the tag
     * it is referred to by.
     */
    @Test
    public void testRevokedKeyHasADifferentKeyTag() {
        byte[] revoked = DnssecTestVectors.RFC4035_DNSKEY_ZSK.clone();
        revoked[1] |= (byte) DnsDnskeyRecord.FLAG_REVOKE;
        DnsDnskeyRecord record = newRecord(revoked);
        try {
            assertTrue(record.isRevoked());
            assertTrue(record.isZoneKey());
            assertEquals(38519 + DnsDnskeyRecord.FLAG_REVOKE, record.keyTag());
        } finally {
            record.release();
        }
    }

    @Test
    public void testCdnskeyUsesTheSameLayout() {
        DnsDnskeyRecord record = newRecord(DnsRecordType.CDNSKEY, DnssecTestVectors.RFC4035_DNSKEY_ZSK);
        try {
            assertEquals(DnsRecordType.CDNSKEY, record.type());
            assertEquals(38519, record.keyTag());
        } finally {
            record.release();
        }
    }

    @Test
    public void testRejectsAnUnrelatedType() {
        ByteBuf content = Unpooled.wrappedBuffer(DnssecTestVectors.RFC4035_DNSKEY_ZSK);
        try {
            assertThrows(IllegalArgumentException.class, () -> new DnsDnskeyRecord(
                    "example.", DnsRecordType.DS, DnsRecord.CLASS_IN, 3600, OWNER, content));
        } finally {
            content.release();
        }
    }

    @Test
    public void testRejectsTruncatedFixedFields() {
        for (int length = 0; length < 4; length++) {
            ByteBuf content = Unpooled.wrappedBuffer(DnssecTestVectors.RFC4035_DNSKEY_ZSK, 0, length);
            try {
                assertThrows(CorruptedFrameException.class, () -> new DnsDnskeyRecord(
                        "example.", DnsRecordType.DNSKEY, DnsRecord.CLASS_IN, 3600, OWNER, content));
            } finally {
                content.release();
            }
        }
    }

    /**
     * A DNSKEY with no key material at all is not useful, but it is not a framing error either: the public key is
     * the rest of the RDATA, so there is nothing to run past the end. Rejecting it is the job of
     * {@link DnssecPublicKeys}.
     */
    @Test
    public void testAcceptsAnEmptyPublicKey() {
        DnsDnskeyRecord record = newRecord(new byte[] { 0x01, 0x00, 0x03, 0x08 });
        try {
            assertEquals(0, record.publicKey().length);
            assertSame(DnssecAlgorithm.RSASHA256, record.algorithm());
        } finally {
            record.release();
        }
    }

    @Test
    public void testUnknownAlgorithmIsReportedRatherThanRejected() {
        DnsDnskeyRecord record = newRecord(new byte[] { 0x01, 0x00, 0x03, (byte) 0xfd, 0x2a });
        try {
            assertEquals(253, record.algorithm().intValue());
            assertEquals(1, record.publicKey().length);
        } finally {
            record.release();
        }
    }

    /**
     * RFC 4034, appendix B.1 gives RSAMD5 its own key tag calculation, which is not implemented.
     */
    @Test
    public void testKeyTagOfRsaMd5IsRejected() {
        DnsDnskeyRecord record = newRecord(new byte[] { 0x01, 0x00, 0x03, 0x01, 0x2a, 0x2b });
        try {
            assertSame(DnssecAlgorithm.RSAMD5, record.algorithm());
            assertThrows(DnssecUnsupportedAlgorithmException.class, record::keyTag);
        } finally {
            record.release();
        }
    }

    /**
     * A protocol other than 3 makes the key invalid for verification, but that is a validator's decision; the
     * decoder reports what it read.
     */
    @Test
    public void testUnexpectedProtocolIsReportedRatherThanRejected() {
        DnsDnskeyRecord record = newRecord(new byte[] { 0x01, 0x00, 0x02, 0x08, 0x2a });
        try {
            assertEquals(2, record.protocol());
        } finally {
            record.release();
        }
    }

    @Test
    public void testContentIsTheUntouchedRdata() {
        DnsDnskeyRecord record = newRecord(DnssecTestVectors.RFC4035_DNSKEY_ZSK);
        try {
            assertArrayEquals(DnssecTestVectors.RFC4035_DNSKEY_ZSK, ByteBufUtil.getBytes(record.content()));
        } finally {
            record.release();
        }
    }

    @Test
    public void testCopyKeepsTheConcreteType() {
        DnsDnskeyRecord record = newRecord(DnssecTestVectors.RFC4035_DNSKEY_ZSK);
        try {
            DnsDnskeyRecord copy = record.copy();
            try {
                assertEquals(38519, copy.keyTag());
                assertEquals(OWNER, copy.owner());
                assertArrayEquals(record.publicKey(), copy.publicKey());
            } finally {
                copy.release();
            }
            DnsDnskeyRecord duplicate = record.duplicate();
            assertEquals(38519, duplicate.keyTag());
            DnsDnskeyRecord retained = record.retainedDuplicate();
            try {
                assertEquals(38519, retained.keyTag());
            } finally {
                retained.release();
            }
        } finally {
            record.release();
        }
    }

    /**
     * {@code replace} parses what it is handed, so it cannot hand back a record whose accessors disagree with its
     * content. A buffer it rejects is released rather than leaked, because the caller has given it away.
     */
    @Test
    public void testReplaceRejectsAndReleasesUnparseableContent() {
        DnsDnskeyRecord record = newRecord(DnssecTestVectors.RFC4035_DNSKEY_ZSK);
        try {
            ByteBuf broken = Unpooled.buffer().writeByte(1).writeByte(0);
            assertThrows(CorruptedFrameException.class, () -> record.replace(broken));
            assertEquals(0, broken.refCnt());
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
        DnsDnskeyRecord record = newRecord(DnssecTestVectors.RFC4035_DNSKEY_ZSK);
        try {
            ByteBuf content = record.content();
            content.skipBytes(content.readableBytes());

            DnsDnskeyRecord copy = record.copy();
            try {
                assertSame(DnsDnskeyRecord.class, copy.getClass());
                assertEquals(38519, copy.keyTag());
                assertArrayEquals(record.publicKey(), copy.publicKey());
                assertEquals(OWNER, copy.owner());
            } finally {
                copy.release();
            }
            DnsDnskeyRecord duplicate = record.duplicate();
            assertSame(DnsDnskeyRecord.class, duplicate.getClass());
            assertEquals(38519, duplicate.keyTag());
            assertEquals(1, record.refCnt());
            DnsDnskeyRecord retained = record.retainedDuplicate();
            try {
                assertSame(DnsDnskeyRecord.class, retained.getClass());
                assertArrayEquals(record.publicKey(), retained.publicKey());
            } finally {
                retained.release();
            }

            assertEquals(1, record.refCnt());
            content.readerIndex(0);
            assertArrayEquals(DnssecTestVectors.RFC4035_DNSKEY_ZSK, ByteBufUtil.getBytes(content));
        } finally {
            record.release();
        }
    }
}
