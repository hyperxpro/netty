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
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecordType;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.concat;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.hex;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.releaseAll;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.wireName;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnssecCanonicalizerTest {

    private static byte[] canonicalRdata(DnsRecordType type, byte[] rdata) {
        ByteBuf in = Unpooled.wrappedBuffer(rdata);
        ByteBuf out = Unpooled.buffer();
        try {
            DnssecCanonicalizer.writeCanonicalRdata(type, in, out);
            // Canonicalisation must never move the indices of the RDATA it reads.
            assertEquals(rdata.length, in.readableBytes());
            return ByteBufUtil.getBytes(out);
        } finally {
            in.release();
            out.release();
        }
    }

    // RFC 6840, section 5.1. This is the pair that a lower-case fixture cannot tell apart, so it is asserted
    // structurally here and behaviourally in DnssecSignatureVerifierTest.

    @Test
    public void testNsecNextDomainNameIsNotDowncased() {
        byte[] rdata = concat(wireName("A.EXAMPLE."), hex("000722010000000380"));
        assertFalse(DnssecCanonicalizer.downcasesRdataNames(DnsRecordType.NSEC));
        assertArrayEquals(rdata, canonicalRdata(DnsRecordType.NSEC, rdata));
    }

    @Test
    public void testRrsigSignerNameIsDowncased() {
        byte[] fixed = hex("002F050100000E10409E7A234076ED239677");
        byte[] signature = hex("0102030405");
        byte[] rdata = concat(fixed, wireName("EXAMPLE."), signature);
        assertTrue(DnssecCanonicalizer.downcasesRdataNames(DnsRecordType.RRSIG));
        assertArrayEquals(concat(fixed, wireName("example."), signature),
                canonicalRdata(DnsRecordType.RRSIG, rdata));
    }

    @Test
    public void testHinfoIsNotDowncased() {
        // RFC 4034 erratum 1062: section 6.2 lists HINFO twice although it holds no domain name at all, so its
        // character strings must survive canonicalisation untouched.
        byte[] rdata = hex("034341540750444C312D3830");
        assertFalse(DnssecCanonicalizer.downcasesRdataNames(DnsRecordType.valueOf(13)));
        assertArrayEquals(rdata, canonicalRdata(DnsRecordType.valueOf(13), rdata));
    }

    @Test
    public void testTypesStandardisedAfterRfc3597AreNeverDowncased() {
        // RFC 3597, section 7 closes the list, so a name-bearing RDATA of a newer type stays as it is.
        DnsRecordType[] types = {
                DnsRecordType.SVCB, DnsRecordType.HTTPS, DnsRecordType.TLSA, DnsRecordType.SMIMEA,
                DnsRecordType.CAA, DnsRecordType.NSEC3, DnsRecordType.DNSKEY, DnsRecordType.DS
        };
        for (DnsRecordType type : types) {
            assertFalse(DnssecCanonicalizer.downcasesRdataNames(type), type.toString());
        }
        byte[] svcb = concat(hex("0001"), wireName("Foo.Example."));
        assertArrayEquals(svcb, canonicalRdata(DnsRecordType.SVCB, svcb));
    }

    @Test
    public void testSingleNameTypesAreDowncased() {
        // NS, MD, MF, CNAME, MB, MG, MR, PTR, NXT and DNAME all start with one domain name.
        int[] types = { 2, 3, 4, 5, 7, 8, 9, 12, 30, 39 };
        for (int type : types) {
            DnsRecordType recordType = DnsRecordType.valueOf(type);
            assertTrue(DnssecCanonicalizer.downcasesRdataNames(recordType), recordType.toString());
            assertArrayEquals(wireName("ns1.example."),
                    canonicalRdata(recordType, wireName("NS1.EXAMPLE.")));
        }
    }

    @Test
    public void testSoaDowncasesBothNamesAndKeepsTheTrailingFields() {
        byte[] timers = hex("00000001000000020000000300000004 00000005");
        byte[] rdata = concat(wireName("NS1.Example."), wireName("Bugs.X.W.example."), timers);
        assertArrayEquals(concat(wireName("ns1.example."), wireName("bugs.x.w.example."), timers),
                canonicalRdata(DnsRecordType.SOA, rdata));
    }

    @Test
    public void testMxSkipsItsPreference() {
        byte[] rdata = concat(hex("0001"), wireName("AI.Example."));
        assertArrayEquals(concat(hex("0001"), wireName("ai.example.")),
                canonicalRdata(DnsRecordType.MX, rdata));
    }

    @Test
    public void testSrvSkipsSixOctets() {
        byte[] rdata = concat(hex("000100020035"), wireName("Old-Slow-Box.Example.Com."));
        assertArrayEquals(concat(hex("000100020035"), wireName("old-slow-box.example.com.")),
                canonicalRdata(DnsRecordType.SRV, rdata));
    }

    @Test
    public void testNaptrSkipsItsThreeCharacterStrings() {
        byte[] head = concat(hex("00640032"), hex("01" + "55"), hex("07" + "45325520737472"), hex("00"));
        byte[] rdata = concat(head, wireName("Foo.Example."));
        assertArrayEquals(concat(head, wireName("foo.example.")),
                canonicalRdata(DnsRecordType.NAPTR, rdata));
    }

    @Test
    public void testA6WithAPrefixLengthOfZeroHasNoName() {
        // RFC 2874, section 3.1.1: prefix length 0 means the whole address is present and no prefix name follows.
        byte[] rdata = concat(hex("00"), hex("20010DB8000000000000000000000001"));
        assertArrayEquals(rdata, canonicalRdata(DnsRecordType.valueOf(38), rdata));
    }

    @Test
    public void testA6DowncasesItsPrefixName() {
        // Prefix length 64, so eight octets of address suffix and then a prefix name.
        byte[] rdata = concat(hex("40"), hex("0000000000000001"), wireName("Sub.Example."));
        assertArrayEquals(concat(hex("40"), hex("0000000000000001"), wireName("sub.example.")),
                canonicalRdata(DnsRecordType.valueOf(38), rdata));
    }

    @Test
    public void testCompressedRdataIsRefused() {
        byte[] rdata = concat(hex("0001"), hex("C00C"));
        DnssecCanonicalizationException e = assertThrows(DnssecCanonicalizationException.class,
                () -> canonicalRdata(DnsRecordType.MX, rdata));
        assertSame(DnssecFailureReason.COMPRESSED_RDATA, e.reason());
        assertSame(DnssecStatus.BOGUS, e.reason().impliedStatus());
    }

    @Test
    public void testReservedLabelTypeIsRefused() {
        byte[] rdata = concat(hex("0001"), hex("4100"));
        DnssecCanonicalizationException e = assertThrows(DnssecCanonicalizationException.class,
                () -> canonicalRdata(DnsRecordType.MX, rdata));
        assertSame(DnssecFailureReason.COMPRESSED_RDATA, e.reason());
    }

    @Test
    public void testTruncatedNameIsRefused() {
        assertThrows(DnssecCanonicalizationException.class,
                () -> canonicalRdata(DnsRecordType.MX, concat(hex("0001"), hex("0361"))));
        assertThrows(DnssecCanonicalizationException.class,
                () -> canonicalRdata(DnsRecordType.MX, hex("00")));
        assertThrows(DnssecCanonicalizationException.class,
                () -> canonicalRdata(DnsRecordType.NAPTR, hex("0064003201")));
    }

    @Test
    public void testUnknownTypeRdataIsCopiedThrough() {
        byte[] rdata = hex("C0000201");
        assertArrayEquals(rdata, canonicalRdata(DnsRecordType.A, rdata));
    }

    // RFC 4035, section 5.3.2, the "name" calculation.

    @Test
    public void testSignedOwnerIsTheOwnerWhenTheLabelCountsAgree() {
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.wildcardMxRrsig(4);
        try {
            assertSame(DnssecRRsetFixtures.A_Z_W_EXAMPLE,
                    DnssecCanonicalizer.signedOwner(rrsig, DnssecRRsetFixtures.A_Z_W_EXAMPLE));
            assertFalse(DnssecCanonicalizer.isWildcardExpansion(rrsig, DnssecRRsetFixtures.A_Z_W_EXAMPLE));
        } finally {
            rrsig.release();
        }
    }

    @Test
    public void testSignedOwnerIsRebuiltAsAWildcard() {
        // RFC 4035, appendix B.6: a.z.w.example. has four labels and the RRSIG says two, so the signature was made
        // over *.w.example.
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.wildcardMxRrsig(2);
        try {
            assertEquals(DnsName.fromString("*.w.example."),
                    DnssecCanonicalizer.signedOwner(rrsig, DnssecRRsetFixtures.A_Z_W_EXAMPLE));
            assertTrue(DnssecCanonicalizer.isWildcardExpansion(rrsig, DnssecRRsetFixtures.A_Z_W_EXAMPLE));
        } finally {
            rrsig.release();
        }
    }

    @Test
    public void testSignedOwnerRejectsALabelCountAboveTheOwner() {
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.wildcardMxRrsig(5);
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> DnssecCanonicalizer.signedOwner(rrsig, DnssecRRsetFixtures.A_Z_W_EXAMPLE));
        } finally {
            rrsig.release();
        }
    }

    @Test
    public void testOwnerLabelCountExcludesALeadingWildcardLabel() {
        // RFC 4034, section 3.1.3: the Labels field counts neither the root label nor the "*".
        assertEquals(3, DnssecCanonicalizer.ownerLabelCount(DnsName.fromString("a.w.example.")));
        assertEquals(2, DnssecCanonicalizer.ownerLabelCount(DnsName.fromString("*.w.example.")));
        assertEquals(0, DnssecCanonicalizer.ownerLabelCount(DnsName.ROOT));

        // So a wildcard owner signed with a matching Labels field keeps its "*", per RFC 4034, section 6.2 item 4.
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.wildcardMxRrsig(2);
        try {
            DnsName wildcard = DnsName.fromString("*.w.example.");
            assertSame(wildcard, DnssecCanonicalizer.signedOwner(rrsig, wildcard));
            assertFalse(DnssecCanonicalizer.isWildcardExpansion(rrsig, wildcard));
        } finally {
            rrsig.release();
        }
    }

    // RFC 4035, section 5.3.2, the signed data itself.

    @Test
    public void testSignedDataLayout() {
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.apexNsecRrsig();
        DnsNsecRecord nsec = DnssecRRsetFixtures.apexNsec("a.example.");
        DnsRRset rrset = new DnsRRset(DnssecRRsetFixtures.EXAMPLE, DnsRecordType.NSEC, 1,
                Collections.singletonList(nsec), Collections.singletonList(rrsig));
        ByteBuf signedData = DnssecCanonicalizer.signedData(ByteBufAllocator.DEFAULT, rrsig, rrset);
        try {
            byte[] rrsigRdata = ByteBufUtil.getBytes(rrsig.content());
            byte[] expected = concat(
                    // RRSIG RDATA up to and including the signer's name, with the Signature field excluded.
                    Arrays.copyOfRange(rrsigRdata, 0, 18 + wireName("example.").length),
                    wireName("example."), hex("002F"), hex("0001"), hex("00000E10"),
                    hex("0014"), ByteBufUtil.getBytes(nsec.content()));
            assertArrayEquals(expected, ByteBufUtil.getBytes(signedData));
            // Fixed capacity: the buffer is sized from the records and must not have needed to grow.
            assertEquals(signedData.readableBytes(), signedData.capacity());
        } finally {
            signedData.release();
            releaseAll(nsec, rrsig);
        }
    }

    @Test
    public void testSignedDataUsesTheRrsigOriginalTtlAndNotTheReceivedOne() {
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.rrsig(DnssecRRsetFixtures.EXAMPLE, DnsRecordType.NSEC,
                DnssecAlgorithm.RSASHA1, 1, 86400, DnssecRRsetFixtures.RFC4035_EXPIRATION,
                DnssecRRsetFixtures.RFC4035_INCEPTION, 38519, wireName("example."), hex("00"));
        DnsNsecRecord nsec = DnssecRRsetFixtures.apexNsec("a.example.");
        DnsRRset rrset = new DnsRRset(DnssecRRsetFixtures.EXAMPLE, DnsRecordType.NSEC, 1,
                Collections.singletonList(nsec), Collections.singletonList(rrsig));
        ByteBuf signedData = DnssecCanonicalizer.signedData(ByteBufAllocator.DEFAULT, rrsig, rrset);
        try {
            // The record was received with a TTL of 3600; RFC 4034, section 3.1.4 says the signature covers the
            // Original TTL of the RRSIG, here 86400.
            int ttlOffset = 18 + wireName("example.").length + wireName("example.").length + 4;
            assertEquals(86400, signedData.getUnsignedInt(ttlOffset));
        } finally {
            signedData.release();
            releaseAll(nsec, rrsig);
        }
    }

    @Test
    public void testSignedDataSortsAndDeduplicatesTheRrset() {
        // RFC 4034, section 6.3: sorted by the RDATA of the canonical form as unsigned octets, with duplicates
        // removed. The three records here arrive in the wrong order and one of them twice.
        DnssecRecord high = DnssecRRsetFixtures.rawRecord(DnssecRRsetFixtures.EXAMPLE, DnsRecordType.A, 3600,
                hex("C0000203"));
        DnssecRecord low = DnssecRRsetFixtures.rawRecord(DnssecRRsetFixtures.EXAMPLE, DnsRecordType.A, 3600,
                hex("C0000201"));
        DnssecRecord duplicate = DnssecRRsetFixtures.rawRecord(DnssecRRsetFixtures.EXAMPLE, DnsRecordType.A, 3600,
                hex("C0000203"));
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.rrsig(DnssecRRsetFixtures.EXAMPLE, DnsRecordType.A,
                DnssecAlgorithm.RSASHA1, 1, 3600, DnssecRRsetFixtures.RFC4035_EXPIRATION,
                DnssecRRsetFixtures.RFC4035_INCEPTION, 38519, wireName("example."), hex("00"));
        DnsRRset rrset = new DnsRRset(DnssecRRsetFixtures.EXAMPLE, DnsRecordType.A, 1,
                Arrays.asList(high, low, duplicate), Collections.singletonList(rrsig));
        ByteBuf signedData = DnssecCanonicalizer.signedData(ByteBufAllocator.DEFAULT, rrsig, rrset);
        try {
            byte[] prefix = concat(hex("0001050100000E10409E7A234076ED239677"), wireName("example."));
            byte[] expected = concat(prefix,
                    wireName("example."), hex("0001"), hex("0001"), hex("00000E10"), hex("0004"), hex("C0000201"),
                    wireName("example."), hex("0001"), hex("0001"), hex("00000E10"), hex("0004"), hex("C0000203"));
            assertArrayEquals(expected, ByteBufUtil.getBytes(signedData));
        } finally {
            signedData.release();
            releaseAll(high, low, duplicate, rrsig);
        }
    }

    @Test
    public void testSignedDataDowncasesTheOwnerName() {
        DnsName mixedCase = DnsName.fromString("EXAMPLE.");
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.rrsig(mixedCase, DnsRecordType.NSEC, DnssecAlgorithm.RSASHA1, 1,
                3600, DnssecRRsetFixtures.RFC4035_EXPIRATION, DnssecRRsetFixtures.RFC4035_INCEPTION, 38519,
                wireName("EXAMPLE."), hex("00"));
        DnsNsecRecord nsec = DnssecRRsetFixtures.apexNsec("a.example.");
        DnsRRset rrset = new DnsRRset(mixedCase, DnsRecordType.NSEC, 1,
                Collections.singletonList(nsec), Collections.singletonList(rrsig));
        ByteBuf signedData = DnssecCanonicalizer.signedData(ByteBufAllocator.DEFAULT, rrsig, rrset);
        try {
            byte[] lowerCase = wireName("example.");
            // Both the RRSIG signer's name and the RR owner name come out downcased, per RFC 4034, section 6.2
            // item 2 and RFC 4035, section 5.3.2.
            assertArrayEquals(lowerCase, ByteBufUtil.getBytes(signedData.slice(18, lowerCase.length)));
            assertArrayEquals(lowerCase,
                    ByteBufUtil.getBytes(signedData.slice(18 + lowerCase.length, lowerCase.length)));
        } finally {
            signedData.release();
            releaseAll(nsec, rrsig);
        }
    }

    @Test
    public void testSignedDataRejectsAnEmptyRrset() {
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.apexNsecRrsig();
        try {
            DnsRRset rrset = new DnsRRset(DnssecRRsetFixtures.EXAMPLE, DnsRecordType.NSEC, 1,
                    Collections.<DnssecRecord>emptyList(), Collections.singletonList(rrsig));
            assertThrows(IllegalArgumentException.class,
                    () -> DnssecCanonicalizer.signedData(ByteBufAllocator.DEFAULT, rrsig, rrset));
        } finally {
            rrsig.release();
        }
    }
}
