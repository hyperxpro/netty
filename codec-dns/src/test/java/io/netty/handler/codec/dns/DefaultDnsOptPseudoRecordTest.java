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
package io.netty.handler.codec.dns;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DefaultDnsOptPseudoRecordTest {

    @Test
    public void testDnssecOkIsTheTopBitOfTheFlagsField() {
        DefaultDnsOptPseudoRecord record = DefaultDnsOptPseudoRecord.withDnssecOk(4096);

        assertTrue(record.isDnssecOk());
        assertEquals(0x8000, record.flags());
        assertEquals(0, record.extendedRcode());
        assertEquals(0, record.version());
        // RFC 6891 section 6.1.2: the CLASS field carries the requestor's UDP payload size.
        assertEquals(4096, record.dnsClass());
        assertEquals(DnsRecordType.OPT, record.type());
    }

    @Test
    public void testDnssecOkIsClearByDefault() {
        DefaultDnsOptPseudoRecord record = new DefaultDnsOptPseudoRecord(512);

        assertFalse(record.isDnssecOk());
        assertEquals(0, record.flags());
        assertEquals(0, record.timeToLive());
    }

    /**
     * RFC 6891 section 6.1.3 lays the OPT TTL out as EXTENDED-RCODE(8) | VERSION(8) | DO(1) Z(15). Distinct,
     * asymmetric values are used for each field so that a swap or a mask of the wrong width is detectable.
     */
    @Test
    public void testFieldsArePackedIntoTheTtlInTheRightOrder() {
        DefaultDnsOptPseudoRecord record = new DefaultDnsOptPseudoRecord(1280, 0x12, 0x34, 0x8001);

        assertEquals(0x12, record.extendedRcode());
        assertEquals(0x34, record.version());
        assertEquals(0x8001, record.flags());
        assertTrue(record.isDnssecOk());
        assertEquals(0x12348001L, record.timeToLive());
    }

    @Test
    public void testDnssecOkSurvivesEncoding() throws Exception {
        ByteBuf out = Unpooled.buffer();
        try {
            DnsRecordEncoder.DEFAULT.encodeRecord(DefaultDnsOptPseudoRecord.withDnssecOk(4096), out);

            // Wire layout of an OPT RR with no options: root NAME(1) TYPE(2) CLASS(2) TTL(4) RDLENGTH(2).
            assertEquals(11, out.readableBytes());
            assertEquals(0, out.getUnsignedByte(0));                    // root name
            assertEquals(DnsRecordType.OPT.intValue(), out.getUnsignedShort(1));
            assertEquals(4096, out.getUnsignedShort(3));                // payload size in CLASS
            assertEquals(0x00008000L, out.getUnsignedInt(5));           // DO set, nothing else
            assertEquals(0, out.getUnsignedShort(9));                   // no options
        } finally {
            out.release();
        }
    }
}
