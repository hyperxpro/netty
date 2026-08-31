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
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

public class DefaultDnssecRawRecordTest {

    private static final DnsName OWNER = DnsName.fromString("www.example.");

    private static final byte[] RDATA = { 10, 0, 0, 1 };

    private static DefaultDnssecRawRecord newRecord() {
        return new DefaultDnssecRawRecord("www.example.", DnsRecordType.A, DnsRecord.CLASS_IN, 3600, OWNER,
                Unpooled.wrappedBuffer(RDATA));
    }

    @Test
    public void testCarriesTheOwnerNameBesideTheUntouchedRdata() {
        DefaultDnssecRawRecord record = newRecord();
        try {
            assertEquals(OWNER, record.owner());
            assertEquals(DnsRecordType.A, record.type());
            assertEquals("www.example.", record.name());
            assertEquals(3600, record.timeToLive());
            assertArrayEquals(RDATA, ByteBufUtil.getBytes(record.content()));
        } finally {
            record.release();
        }
    }

    /**
     * Nothing here parses the {@code RDATA}, so {@code copy}, {@code duplicate} and {@code retainedDuplicate} are
     * unaffected by what a caller has read. This pins that, because the typed records in this package route those
     * three past {@code replace} for exactly the case this asserts.
     */
    @Test
    public void testCopyOfAConsumedRecordKeepsTheParsedFields() {
        DefaultDnssecRawRecord record = newRecord();
        try {
            ByteBuf content = record.content();
            content.skipBytes(content.readableBytes());

            DefaultDnssecRawRecord copy = record.copy();
            try {
                assertSame(DefaultDnssecRawRecord.class, copy.getClass());
                assertEquals(OWNER, copy.owner());
                assertEquals(DnsRecordType.A, copy.type());
                assertEquals("www.example.", copy.name());
            } finally {
                copy.release();
            }
            DefaultDnssecRawRecord duplicate = record.duplicate();
            assertSame(DefaultDnssecRawRecord.class, duplicate.getClass());
            assertEquals(OWNER, duplicate.owner());
            assertEquals(1, record.refCnt());
            DefaultDnssecRawRecord retained = record.retainedDuplicate();
            try {
                assertSame(DefaultDnssecRawRecord.class, retained.getClass());
                assertEquals(OWNER, retained.owner());
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

    @Test
    public void testReplaceKeepsTheConcreteType() {
        DefaultDnssecRawRecord record = newRecord();
        try {
            DefaultDnssecRawRecord replaced = record.replace(Unpooled.wrappedBuffer(new byte[] { 10, 0, 0, 2 }));
            try {
                assertSame(DefaultDnssecRawRecord.class, replaced.getClass());
                assertEquals(OWNER, replaced.owner());
                assertArrayEquals(new byte[] { 10, 0, 0, 2 }, ByteBufUtil.getBytes(replaced.content()));
            } finally {
                replaced.release();
            }
        } finally {
            record.release();
        }
    }
}
