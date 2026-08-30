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

import io.netty.handler.codec.dns.DnsRecordType;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The two per-type sets, pinned over the whole 16-bit type space. {@link DnssecRdataDecompressor} and
 * {@link DnssecCanonicalizer} used to hold a table each; they now share one, and what these tests defend is that
 * the sets stayed different where the RFCs make them different.
 */
public class DnssecRdataLayoutTest {

    /**
     * RFC 3597, section 4: the RFC 1035 types that carry a domain name, plus the eight it names explicitly.
     * {@code HINFO} is well-known but holds no name, so there is nothing in it to expand.
     */
    private static final int[] COMPRESSIBLE = {
            2,   // NS
            3,   // MD
            4,   // MF
            5,   // CNAME
            6,   // SOA
            7,   // MB
            8,   // MG
            9,   // MR
            12,  // PTR
            14,  // MINFO
            15,  // MX
            17,  // RP
            18,  // AFSDB
            21,  // RT
            24,  // SIG
            26,  // PX
            30,  // NXT
            33,  // SRV
            35   // NAPTR
    };

    /**
     * Item 3 of RFC 4034, section 6.2, which is the RFC 3597, section 7 list plus {@code RRSIG} and {@code NSEC},
     * less {@code HINFO} (erratum 1062) and less {@code NSEC} (RFC 6840, section 5.1).
     */
    private static final int[] DOWNCASED = {
            2, 3, 4, 5, 6, 7, 8, 9, 12, 14, 15, 17, 18, 21, 24, 26, 30, 33, 35,
            36,  // KX
            38,  // A6
            39,  // DNAME
            46   // RRSIG
    };

    private static final int HINFO = 13;
    private static final int NSEC = 47;

    private static boolean contains(int[] types, int type) {
        for (int candidate : types) {
            if (candidate == type) {
                return true;
            }
        }
        return false;
    }

    @Test
    public void testTheCompressibleSetIsExactlyTheRfc3597Section4List() {
        for (int type = 0; type <= 0xffff; type++) {
            DnsRecordType recordType = DnsRecordType.valueOf(type);
            assertEquals(contains(COMPRESSIBLE, type), DnssecRdataLayout.isCompressible(recordType),
                    recordType.toString());
        }
    }

    @Test
    public void testTheDowncaseSetIsExactlyTheRfc4034Item3ListAsAmended() {
        for (int type = 0; type <= 0xffff; type++) {
            DnsRecordType recordType = DnsRecordType.valueOf(type);
            assertEquals(contains(DOWNCASED, type), DnssecRdataLayout.downcasesNames(recordType),
                    recordType.toString());
            // The public view of the same set must not drift from it.
            assertEquals(DnssecRdataLayout.downcasesNames(recordType),
                    DnssecCanonicalizer.downcasesRdataNames(recordType), recordType.toString());
        }
    }

    /**
     * The asymmetries the two sets exist to express. Collapsing either set into the other would break exactly
     * these four types and nothing else, which is why they are asserted one by one.
     */
    @Test
    public void testTheSetsDifferWhereTheRfcsMakeThemDiffer() {
        // RFC 4034, section 3.1.7 forbids compressing an RRSIG signer's name, but the name is still downcased.
        assertDowncasedButNotCompressible(DnsRecordType.RRSIG);
        // KX, A6 and DNAME postdate RFC 1035 and RFC 3597, section 4 does not list them.
        assertDowncasedButNotCompressible(DnsRecordType.KX);
        assertDowncasedButNotCompressible(DnsRecordType.valueOf(38));
        assertDowncasedButNotCompressible(DnsRecordType.DNAME);

        // RFC 6840, section 5.1 takes NSEC out of the downcase set; RFC 4034, section 4.1.1 keeps its Next Domain
        // Name out of the compressible one. It is in neither, and so is HINFO, which holds no name at all.
        assertInNeitherSet(DnsRecordType.valueOf(NSEC));
        assertInNeitherSet(DnsRecordType.valueOf(HINFO));

        // The forerunners of those two are in both: RFC 3597, section 4 has a receiver expand SIG and NXT.
        assertTrue(DnssecRdataLayout.isCompressible(DnsRecordType.SIG));
        assertTrue(DnssecRdataLayout.downcasesNames(DnsRecordType.SIG));
        assertTrue(DnssecRdataLayout.isCompressible(DnsRecordType.valueOf(30)));
        assertTrue(DnssecRdataLayout.downcasesNames(DnsRecordType.valueOf(30)));
    }

    /**
     * The point of one table: where a type is in both sets, the expander and the canonicaliser see the same field
     * positions, so the octets a record decodes to and the octets its signature covers cannot drift apart.
     */
    @Test
    public void testBothSetsSeeTheSameLayoutForATypeInBoth() {
        for (int type : COMPRESSIBLE) {
            DnsRecordType recordType = DnsRecordType.valueOf(type);
            DnssecRdataLayout layout = DnssecRdataLayout.compressibleLayoutOf(recordType);
            assertNotNull(layout, recordType.toString());
            assertSame(layout, DnssecRdataLayout.downcasedLayoutOf(recordType), recordType.toString());
        }
    }

    @Test
    public void testAnUnknownTypeHasNoLayout() {
        DnsRecordType unknown = DnsRecordType.valueOf(0xff00);
        assertNull(DnssecRdataLayout.compressibleLayoutOf(unknown));
        assertNull(DnssecRdataLayout.downcasedLayoutOf(unknown));
    }

    /**
     * RFC 2874, section 3.1.1: a prefix length octet, the low {@code 128 - prefixLength} bits of the address
     * rounded up to whole octets, and a prefix name only when the prefix length is not zero.
     */
    @Test
    public void testTheA6RuleFollowsRfc2874() {
        assertEquals(128, DnssecRdataLayout.A6_MAX_PREFIX_LENGTH);
        assertEquals(1 + 16, DnssecRdataLayout.a6NamesStart(0));
        assertEquals(1 + 8, DnssecRdataLayout.a6NamesStart(64));
        assertEquals(1 + 1, DnssecRdataLayout.a6NamesStart(120));
        assertEquals(1, DnssecRdataLayout.a6NamesStart(128));
        // A prefix length that is not a whole number of octets rounds the suffix up.
        assertEquals(1 + 1, DnssecRdataLayout.a6NamesStart(121));
        assertEquals(1 + 2, DnssecRdataLayout.a6NamesStart(119));

        assertEquals(0, DnssecRdataLayout.a6NameCount(0));
        for (int prefixLength = 1; prefixLength <= 128; prefixLength++) {
            assertEquals(1, DnssecRdataLayout.a6NameCount(prefixLength), "prefix length " + prefixLength);
        }
    }

    @Test
    public void testNoTypeStandardisedAfterRfc3597IsInEitherSet() {
        DnsRecordType[] types = {
                DnsRecordType.SVCB, DnsRecordType.HTTPS, DnsRecordType.TLSA, DnsRecordType.SMIMEA,
                DnsRecordType.CAA, DnsRecordType.NSEC3, DnsRecordType.NSEC3PARAM, DnsRecordType.DNSKEY,
                DnsRecordType.DS
        };
        for (DnsRecordType type : types) {
            assertInNeitherSet(type);
        }
    }

    @Test
    public void testTheTwoSetsAreNotTheSameSet() {
        // A guard against a future "cleanup" that collapses them: the sets have different sizes, and every
        // compressible type is downcased but not the other way round.
        assertFalse(Arrays.equals(COMPRESSIBLE, DOWNCASED));
        for (int type : COMPRESSIBLE) {
            assertTrue(DnssecRdataLayout.downcasesNames(DnsRecordType.valueOf(type)));
        }
        assertEquals(4, DOWNCASED.length - COMPRESSIBLE.length);
    }

    private static void assertDowncasedButNotCompressible(DnsRecordType type) {
        assertTrue(DnssecRdataLayout.downcasesNames(type), type.toString());
        assertFalse(DnssecRdataLayout.isCompressible(type), type.toString());
        assertNull(DnssecRdataLayout.compressibleLayoutOf(type), type.toString());
        assertNotNull(DnssecRdataLayout.downcasedLayoutOf(type), type.toString());
    }

    private static void assertInNeitherSet(DnsRecordType type) {
        assertFalse(DnssecRdataLayout.isCompressible(type), type.toString());
        assertFalse(DnssecRdataLayout.downcasesNames(type), type.toString());
        assertFalse(DnssecCanonicalizer.downcasesRdataNames(type), type.toString());
    }
}
