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
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DefaultDnssecPtrRecordTest {

    private static final DnsName OWNER = DnsName.fromString("1.0.0.10.in-addr.arpa.");

    private static final byte[] RDATA = DnsName.fromString("ptr.example.").toWireBytes();

    private static DefaultDnssecPtrRecord newRecord() {
        return new DefaultDnssecPtrRecord("1.0.0.10.in-addr.arpa.", DnsRecord.CLASS_IN, 3600, OWNER,
                Unpooled.wrappedBuffer(RDATA));
    }

    @Test
    public void testDecode() {
        DefaultDnssecPtrRecord record = newRecord();
        try {
            assertEquals("ptr.example.", record.hostname());
            assertEquals(DnsRecordType.PTR, record.type());
            assertEquals(OWNER, record.owner());
            assertTrue(record instanceof DnsPtrRecord);
            assertArrayEquals(RDATA, ByteBufUtil.getBytes(record.content()));
        } finally {
            record.release();
        }
    }

    /**
     * {@code copy}, {@code duplicate} and {@code retainedDuplicate} must keep working once a caller has read from
     * {@code content()}, the way they do on {@code DefaultDnsRawRecord}. Routing them through {@code replace},
     * which re-parses, made them report the hostname of whatever was left in the buffer: a fully read PTR decoded
     * as the root name, because {@code DnsCodecUtil} answers an empty buffer with {@code "."} rather than failing.
     */
    @Test
    public void testCopyOfAConsumedRecordKeepsTheParsedFields() {
        DefaultDnssecPtrRecord record = newRecord();
        try {
            ByteBuf content = record.content();
            content.skipBytes(content.readableBytes());

            DefaultDnssecPtrRecord copy = record.copy();
            try {
                assertSame(DefaultDnssecPtrRecord.class, copy.getClass());
                assertEquals("ptr.example.", copy.hostname());
                assertEquals(OWNER, copy.owner());
            } finally {
                copy.release();
            }
            DefaultDnssecPtrRecord duplicate = record.duplicate();
            assertSame(DefaultDnssecPtrRecord.class, duplicate.getClass());
            assertEquals("ptr.example.", duplicate.hostname());
            assertEquals(1, record.refCnt());
            DefaultDnssecPtrRecord retained = record.retainedDuplicate();
            try {
                assertSame(DefaultDnssecPtrRecord.class, retained.getClass());
                assertEquals("ptr.example.", retained.hostname());
            } finally {
                retained.release();
            }

            assertEquals(1, record.refCnt());
            content.readerIndex(0);
            assertArrayEquals(RDATA, ByteBufUtil.getBytes(content));
        } finally {
            record.release();
        }
    }

    /**
     * The reader index left inside a label makes the re-parse fail rather than mis-decode, and {@code duplicate()}
     * shares this record's reference count, so releasing on that failure freed the buffer of a record that is still
     * alive.
     */
    @Test
    public void testCopyOfAPartiallyReadRecordDoesNotFreeTheContent() {
        DefaultDnssecPtrRecord record = newRecord();
        try {
            ByteBuf content = record.content();
            content.skipBytes(1);

            DefaultDnssecPtrRecord copy = record.copy();
            try {
                assertEquals("ptr.example.", copy.hostname());
            } finally {
                copy.release();
            }
            DefaultDnssecPtrRecord duplicate = record.duplicate();
            assertEquals("ptr.example.", duplicate.hostname());
            assertEquals(1, record.refCnt());
            DefaultDnssecPtrRecord retained = record.retainedDuplicate();
            try {
                assertEquals("ptr.example.", retained.hostname());
            } finally {
                retained.release();
            }

            assertEquals(1, record.refCnt());
            content.readerIndex(0);
            assertArrayEquals(RDATA, ByteBufUtil.getBytes(content));
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
        DefaultDnssecPtrRecord record = newRecord();
        try {
            ByteBuf broken = Unpooled.buffer().writeByte(3).writeByte('p');
            assertThrows(CorruptedFrameException.class, () -> record.replace(broken));
            assertEquals(0, broken.refCnt());
            assertEquals(1, record.refCnt());
        } finally {
            record.release();
        }
    }

    @Test
    public void testReplaceKeepsTheConcreteType() {
        DefaultDnssecPtrRecord record = newRecord();
        try {
            DefaultDnssecPtrRecord replaced = record.replace(
                    Unpooled.wrappedBuffer(DnsName.fromString("other.example.").toWireBytes()));
            try {
                assertSame(DefaultDnssecPtrRecord.class, replaced.getClass());
                assertEquals("other.example.", replaced.hostname());
                assertEquals(OWNER, replaced.owner());
            } finally {
                replaced.release();
            }
        } finally {
            record.release();
        }
    }
}
