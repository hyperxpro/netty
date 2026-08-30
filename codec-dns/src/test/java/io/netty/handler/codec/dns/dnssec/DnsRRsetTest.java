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

import io.netty.buffer.Unpooled;
import io.netty.handler.codec.dns.DefaultDnsRawRecord;
import io.netty.handler.codec.dns.DefaultDnsResponse;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.handler.codec.dns.DnsResponse;
import io.netty.handler.codec.dns.DnsSection;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.EXAMPLE;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.hex;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.releaseAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnsRRsetTest {

    private static DnssecRecord a(DnsName owner, String rdata) {
        return DnssecRRsetFixtures.rawRecord(owner, DnsRecordType.A, 3600, hex(rdata));
    }

    @Test
    public void testGroupSplitsBySectionOwnerTypeAndClass() {
        DnsResponse response = new DefaultDnsResponse(1);
        try {
            DnsName www = DnsName.fromString("www.example.");
            response.addRecord(DnsSection.ANSWER, a(www, "C0000201"));
            response.addRecord(DnsSection.ANSWER, a(www, "C0000202"));
            response.addRecord(DnsSection.ANSWER,
                    DnssecRRsetFixtures.rawRecord(www, DnsRecordType.AAAA, 3600,
                            hex("20010DB8000000000000000000000001")));
            response.addRecord(DnsSection.ANSWER, a(DnsName.fromString("other.example."), "C0000203"));

            List<DnsRRset> rrsets = DnsRRset.group(response, DnsSection.ANSWER, DnssecLimits.defaults());
            assertEquals(3, rrsets.size());
            assertEquals(www, rrsets.get(0).owner());
            assertEquals(DnsRecordType.A, rrsets.get(0).type());
            assertEquals(DnsRecord.CLASS_IN, rrsets.get(0).dnsClass());
            assertEquals(2, rrsets.get(0).size());
            assertEquals(DnsRecordType.AAAA, rrsets.get(1).type());
            assertEquals(1, rrsets.get(1).size());
            assertEquals(DnsName.fromString("other.example."), rrsets.get(2).owner());
        } finally {
            response.release();
        }
    }

    /**
     * The trap this class exists to avoid. {@code equals} and {@code hashCode} come from {@code AbstractDnsRecord},
     * which compares the name, type, class and TTL and not the {@code RDATA}, so the two members of an RRset are
     * equal to each other. Deduplicating with a {@link Set} would collapse them into one and the RRset would then
     * fail to validate against its own signature, with nothing about the failure pointing at the cause.
     */
    @Test
    public void testDistinctRdataSurvivesEvenThoughTheRecordsCompareEqual() {
        DnsName www = DnsName.fromString("www.example.");
        DnssecRecord first = a(www, "C0000201");
        DnssecRecord second = a(www, "C0000202");
        try {
            assertEquals(first, second);
            assertEquals(first.hashCode(), second.hashCode());
            Set<DnsRecord> asSet = new HashSet<DnsRecord>(Arrays.asList(first, second));
            assertEquals(1, asSet.size(), "the premise of this test no longer holds");

            DnsRRset rrset = new DnsRRset(www, DnsRecordType.A, DnsRecord.CLASS_IN,
                    Arrays.asList(first, second), Collections.<DnsRrsigRecord>emptyList());
            assertEquals(2, rrset.size());
            assertSame(first, rrset.records().get(0));
            assertSame(second, rrset.records().get(1));
        } finally {
            releaseAll(first, second);
        }
    }

    @Test
    public void testRepeatedRdataIsRemoved() {
        // RFC 4034, section 6.3: an RRset must not contain duplicates, and an implementation that is liberal in
        // what it accepts "MUST remove all but one" before computing the canonical form.
        DnsName www = DnsName.fromString("www.example.");
        DnssecRecord first = a(www, "C0000201");
        DnssecRecord repeat = a(www, "C0000201");
        DnssecRecord other = a(www, "C0000202");
        try {
            DnsRRset rrset = new DnsRRset(www, DnsRecordType.A, DnsRecord.CLASS_IN,
                    Arrays.asList(first, repeat, other), Collections.<DnsRrsigRecord>emptyList());
            assertEquals(2, rrset.size());
            assertSame(first, rrset.records().get(0));
            assertSame(other, rrset.records().get(1));
        } finally {
            releaseAll(first, repeat, other);
        }
    }

    @Test
    public void testRrsigsAreAttachedToTheRrsetTheyCover() {
        DnsResponse response = new DefaultDnsResponse(1);
        try {
            response.addRecord(DnsSection.ANSWER, DnssecRRsetFixtures.apexNsec("a.example."));
            response.addRecord(DnsSection.ANSWER, DnssecRRsetFixtures.apexNsecRrsig());

            List<DnsRRset> rrsets = DnsRRset.group(response, DnsSection.ANSWER, DnssecLimits.defaults());
            assertEquals(1, rrsets.size());
            assertEquals(DnsRecordType.NSEC, rrsets.get(0).type());
            assertEquals(1, rrsets.get(0).size());
            assertEquals(1, rrsets.get(0).signatures().size());
            assertEquals(DnsRecordType.NSEC, rrsets.get(0).signatures().get(0).typeCovered());
        } finally {
            response.release();
        }
    }

    @Test
    public void testAnRrsigCoveringNothingIsDropped() {
        DnsResponse response = new DefaultDnsResponse(1);
        try {
            response.addRecord(DnsSection.ANSWER, DnssecRRsetFixtures.apexNsecRrsig());
            assertTrue(DnsRRset.group(response, DnsSection.ANSWER, DnssecLimits.defaults()).isEmpty());
        } finally {
            response.release();
        }
    }

    @Test
    public void testOwnerNamesAreGroupedCaseInsensitively() {
        // RFC 4034, section 6.1: names compare case-insensitively, and the owner is downcased before signing, so
        // the two spellings are one RRset and must not become two that each fail to validate.
        DnsResponse response = new DefaultDnsResponse(1);
        try {
            response.addRecord(DnsSection.ANSWER, a(DnsName.fromString("www.example."), "C0000201"));
            response.addRecord(DnsSection.ANSWER, a(DnsName.fromString("WWW.EXAMPLE."), "C0000202"));

            List<DnsRRset> rrsets = DnsRRset.group(response, DnsSection.ANSWER, DnssecLimits.defaults());
            assertEquals(1, rrsets.size());
            assertEquals(2, rrsets.get(0).size());
        } finally {
            response.release();
        }
    }

    @Test
    public void testOptIsSkipped() {
        // RFC 6891, section 6.1.1: OPT belongs to the message and to no zone, so it is not part of any RRset.
        DnsResponse response = new DefaultDnsResponse(1);
        try {
            response.addRecord(DnsSection.ADDITIONAL,
                    new DefaultDnsRawRecord("", DnsRecordType.OPT, 4096, 0, Unpooled.EMPTY_BUFFER));
            assertTrue(DnsRRset.group(response, DnsSection.ADDITIONAL, DnssecLimits.defaults()).isEmpty());
        } finally {
            response.release();
        }
    }

    @Test
    public void testRecordWithoutAWireOwnerNameIsRefused() {
        DnsResponse response = new DefaultDnsResponse(1);
        try {
            response.addRecord(DnsSection.ANSWER, new DefaultDnsRawRecord("www.example.", DnsRecordType.A,
                    DnsRecord.CLASS_IN, 3600, Unpooled.wrappedBuffer(hex("C0000201"))));
            DnssecCanonicalizationException e = assertThrows(DnssecCanonicalizationException.class,
                    () -> DnsRRset.group(response, DnsSection.ANSWER, DnssecLimits.defaults()));
            assertSame(DnssecFailureReason.NAME_NOT_REPRESENTABLE, e.reason());
            assertSame(DnssecStatus.BOGUS, e.reason().impliedStatus());
        } finally {
            response.release();
        }
    }

    @Test
    public void testUnparsedRrsigIsRefused() {
        DnsResponse response = new DefaultDnsResponse(1);
        try {
            response.addRecord(DnsSection.ANSWER, new DefaultDnsRawRecord("example.", DnsRecordType.RRSIG,
                    DnsRecord.CLASS_IN, 3600, Unpooled.wrappedBuffer(hex("00"))));
            DnssecCanonicalizationException e = assertThrows(DnssecCanonicalizationException.class,
                    () -> DnsRRset.group(response, DnsSection.ANSWER, DnssecLimits.defaults()));
            assertSame(DnssecFailureReason.NAME_NOT_REPRESENTABLE, e.reason());
        } finally {
            response.release();
        }
    }

    @Test
    public void testMaxRecordsPerSectionIsEnforced() {
        DnsResponse response = new DefaultDnsResponse(1);
        try {
            DnsName www = DnsName.fromString("www.example.");
            for (int i = 0; i < 4; i++) {
                response.addRecord(DnsSection.ANSWER, a(www, "C000020" + i));
            }
            DnssecLimits limits = DnssecLimits.newBuilder().maxRecordsPerSection(3).build();
            DnssecLimitExceededException e = assertThrows(DnssecLimitExceededException.class,
                    () -> DnsRRset.group(response, DnsSection.ANSWER, limits));
            assertEquals("maxRecordsPerSection", e.limitName());
            assertEquals(3, e.limit());
        } finally {
            response.release();
        }
    }

    @Test
    public void testMaxDnskeysPerRrsetIsEnforced() {
        DnsResponse response = new DefaultDnsResponse(1);
        try {
            for (int i = 0; i < 3; i++) {
                response.addRecord(DnsSection.ANSWER, DnssecRRsetFixtures.distinctKey(EXAMPLE, i));
            }
            DnssecLimits limits = DnssecLimits.newBuilder().maxDnskeysPerRrset(2).build();
            DnssecLimitExceededException e = assertThrows(DnssecLimitExceededException.class,
                    () -> DnsRRset.group(response, DnsSection.ANSWER, limits));
            assertEquals("maxDnskeysPerRrset", e.limitName());
        } finally {
            response.release();
        }
    }

    @Test
    public void testRrsigIsNotItselfAnRrsetMember() {
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.apexNsecRrsig();
        try {
            assertThrows(IllegalArgumentException.class, () -> new DnsRRset(EXAMPLE, DnsRecordType.RRSIG,
                    DnsRecord.CLASS_IN, Collections.<DnssecRecord>emptyList(), Collections.singletonList(rrsig)));
        } finally {
            rrsig.release();
        }
    }

    @Test
    public void testRecordsAndSignaturesAreUnmodifiable() {
        DnsNsecRecord nsec = DnssecRRsetFixtures.apexNsec("a.example.");
        try {
            DnsRRset rrset = new DnsRRset(EXAMPLE, DnsRecordType.NSEC, DnsRecord.CLASS_IN,
                    Collections.singletonList(nsec), Collections.<DnsRrsigRecord>emptyList());
            assertThrows(UnsupportedOperationException.class, () -> rrset.records().clear());
            assertThrows(UnsupportedOperationException.class, () -> rrset.signatures().clear());
            assertTrue(rrset.toString().contains("NSEC"), rrset.toString());
        } finally {
            nsec.release();
        }
    }
}
