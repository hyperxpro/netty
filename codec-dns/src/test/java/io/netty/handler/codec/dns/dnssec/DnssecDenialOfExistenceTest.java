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
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@code NSEC} half of {@link DnssecDenialOfExistence}, worked against the eight example responses of
 * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#appendix-B">RFC 4035, appendix B</a> and the zone of its
 * appendix A, followed by the shapes those examples do not contain.
 */
public class DnssecDenialOfExistenceTest {

    private static final int A = 1;
    private static final int NS = 2;
    private static final int CNAME = 5;
    private static final int SOA = 6;
    private static final int HINFO = 13;
    private static final int MX = 15;
    private static final int AAAA = 28;
    private static final int DNAME = 39;
    private static final int DS = 43;
    private static final int RRSIG = 46;
    private static final int NSEC = 47;
    private static final int DNSKEY = 48;

    private static final DnsName EXAMPLE = DnsName.fromString("example.");

    private final List<DnsRecord> allocated = new ArrayList<DnsRecord>();

    /**
     * Every record built by a test holds a {@link ByteBuf}. Releasing them here rather than in each test's own
     * {@code finally} keeps the release unconditional even for a test that fails while still building its fixture.
     */
    @AfterEach
    public void releaseRecords() {
        for (DnsRecord record : allocated) {
            ReferenceCountUtil.release(record);
        }
        allocated.clear();
    }

    private static DnsName name(String name) {
        return DnsName.fromString(name);
    }

    private static DnssecDenialOfExistence evaluator() {
        return evaluator(DnssecLimits.defaults());
    }

    private static DnssecDenialOfExistence evaluator(DnssecLimits limits) {
        return new DnssecDenialOfExistence(EXAMPLE, new DnssecBudget(limits, DnssecClock.SYSTEM));
    }

    /**
     * Encodes the Type Bit Maps field of RFC 4034, section 4.1.2: one window block per high octet, each holding
     * the bits of the types in it, most significant bit first.
     */
    static void writeTypeBitmap(ByteBuf out, int... types) {
        int[] sorted = types.clone();
        Arrays.sort(sorted);
        int i = 0;
        while (i < sorted.length) {
            int window = sorted[i] >> 8;
            int end = i;
            while (end < sorted.length && sorted[end] >> 8 == window) {
                end++;
            }
            byte[] bitmap = new byte[((sorted[end - 1] & 0xff) >> 3) + 1];
            for (int k = i; k < end; k++) {
                int low = sorted[k] & 0xff;
                bitmap[low >> 3] |= (byte) (0x80 >>> (low & 7));
            }
            out.writeByte(window).writeByte(bitmap.length).writeBytes(bitmap);
            i = end;
        }
    }

    private DnsNsecRecord nsec(String owner, String next, int... types) {
        ByteBuf rdata = Unpooled.buffer();
        name(next).writeTo(rdata);
        writeTypeBitmap(rdata, types);
        DnsNsecRecord record = new DnsNsecRecord(owner, DnsRecordType.NSEC, DnsRecord.CLASS_IN, 3600,
                name(owner), rdata);
        allocated.add(record);
        return record;
    }

    private static List<DnsRecord> records(DnsRecord... records) {
        return Arrays.<DnsRecord>asList(records);
    }

    // ---------------------------------------------------------------------------------------------------------
    // RFC 4035, appendix B
    // ---------------------------------------------------------------------------------------------------------

    /**
     * B.1 is a positive answer whose authority section carries only the zone's NS RRset, so there is no denial in
     * it to evaluate. A validator asked for one anyway must say so rather than invent a verdict.
     */
    @Test
    public void testB1AnswerCarriesNoProof() {
        DnssecDenialOfExistence.Result result =
                evaluator().proveNameError(name("x.w.example."), Collections.<DnsRecord>emptyList());
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.NSEC_MISSING, result.reason());
        assertFalse(result.isProven());
    }

    /**
     * B.2, an authoritative name error: one NSEC covers {@code ml.example} and the apex NSEC covers the wildcard
     * {@code *.example} at the closest encloser.
     */
    @Test
    public void testB2NameError() {
        List<DnsRecord> authority = records(
                nsec("b.example.", "ns1.example.", NS, RRSIG, NSEC),
                nsec("example.", "a.example.", NS, SOA, MX, RRSIG, NSEC, DNSKEY));
        DnssecDenialOfExistence.Result result = evaluator().proveNameError(name("ml.example."), authority);
        assertEquals(DnssecStatus.SECURE, result.status());
        assertEquals(DnssecFailureReason.NONE, result.reason());
        assertEquals(EXAMPLE, result.closestEncloser());
        assertFalse(result.isOptOut());
        assertTrue(result.isProven());
    }

    /**
     * B.3, a no data error: the NSEC matches {@code ns1.example} and its bitmap holds A but not MX.
     */
    @Test
    public void testB3NoData() {
        List<DnsRecord> authority = records(nsec("ns1.example.", "ns2.example.", A, RRSIG, NSEC));
        DnssecDenialOfExistence.Result result =
                evaluator().proveNoData(name("ns1.example."), DnsRecordType.MX, authority);
        assertEquals(DnssecStatus.SECURE, result.status());
        assertEquals(DnssecFailureReason.NONE, result.reason());
        // A NODATA proof made by a record that matches the query name establishes no closest encloser.
        assertNull(result.closestEncloser());
    }

    /**
     * B.4, a referral to a signed zone: the parent published a DS, so there is nothing to prove insecure and the
     * response carries no NSEC at all.
     */
    @Test
    public void testB4ReferralToSignedZoneIsNotAnInsecureDelegation() {
        DnssecDenialOfExistence.Result result =
                evaluator().proveUnsignedDelegation(name("a.example."), Collections.<DnsRecord>emptyList());
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.NSEC_MISSING, result.reason());
    }

    /**
     * B.5, a referral to an unsigned zone. The NSEC matching the delegation has NS set and DS and SOA clear, which
     * is the full RFC 6840, section 4.4 test.
     */
    @Test
    public void testB5ReferralToUnsignedZone() {
        List<DnsRecord> authority = records(nsec("b.example.", "ns1.example.", NS, RRSIG, NSEC));
        DnssecDenialOfExistence.Result result = evaluator().proveUnsignedDelegation(name("b.example."), authority);
        assertEquals(DnssecStatus.INSECURE, result.status());
        assertEquals(DnssecFailureReason.UNSIGNED_DELEGATION, result.reason());
        assertEquals(name("b.example."), result.closestEncloser());
        assertFalse(result.isOptOut());
    }

    /**
     * B.6, an answer produced by expanding {@code *.w.example}. The NSEC proves {@code a.z.w.example} itself does
     * not exist, and the closest encloser it yields is the parent of the wildcard that was expanded.
     */
    @Test
    public void testB6WildcardExpansion() {
        List<DnsRecord> authority = records(nsec("x.y.w.example.", "xx.example.", MX, RRSIG, NSEC));
        DnssecDenialOfExistence.Result result = evaluator().proveWildcardAnswer(
                name("a.z.w.example."), name("*.w.example."), authority);
        assertEquals(DnssecStatus.SECURE, result.status());
        assertEquals(name("w.example."), result.closestEncloser());
    }

    /**
     * B.7, a no data error for a name covered by a wildcard: {@code a.z.w.example} does not exist, the wildcard
     * {@code *.w.example} matches it, and that wildcard has MX but not AAAA.
     */
    @Test
    public void testB7WildcardNoData() {
        List<DnsRecord> authority = records(
                nsec("x.y.w.example.", "xx.example.", MX, RRSIG, NSEC),
                nsec("*.w.example.", "x.w.example.", MX, RRSIG, NSEC));
        DnssecDenialOfExistence.Result result =
                evaluator().proveNoData(name("a.z.w.example."), DnsRecordType.AAAA, authority);
        assertEquals(DnssecStatus.SECURE, result.status());
        assertEquals(name("w.example."), result.closestEncloser());
    }

    /**
     * B.8, a DS query that reached the child. The NSEC matches, and its DS bit really is clear, but the SOA bit
     * says the record comes from the child's own apex and the DS lives in the parent. Accepting it would let a
     * child declare itself unsigned. The remedy is to ask the parent, which is why this is a rejected proof rather
     * than an accusation.
     */
    @Test
    public void testB8DsQueryAnsweredByTheChildIsRejected() {
        List<DnsRecord> authority = records(nsec("example.", "a.example.", NS, SOA, MX, RRSIG, NSEC, DNSKEY));
        DnssecDenialOfExistence.Result result =
                evaluator().proveNoData(EXAMPLE, DnsRecordType.DS, authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.BAILIWICK_VIOLATION, result.reason());
    }

    // ---------------------------------------------------------------------------------------------------------
    // The shapes appendix B does not contain
    // ---------------------------------------------------------------------------------------------------------

    /**
     * The last NSEC of a zone names the apex as its next domain name (RFC 4034, section 4.1.1), and the apex sorts
     * before every name below it, so that one interval wraps. A validator that tests {@code owner < name < next}
     * finds no cover for anything after the last name in the zone, which is a spurious BOGUS for the whole tail of
     * every signed zone.
     */
    @Test
    public void testTheLastNsecOfTheZoneWrapsAround() {
        List<DnsRecord> authority = records(
                nsec("xx.example.", "example.", A, HINFO, AAAA, RRSIG, NSEC),
                nsec("example.", "a.example.", NS, SOA, MX, RRSIG, NSEC, DNSKEY));
        DnssecDenialOfExistence.Result result = evaluator().proveNameError(name("zz.example."), authority);
        assertEquals(DnssecStatus.SECURE, result.status());
        assertEquals(EXAMPLE, result.closestEncloser());
    }

    /**
     * RFC 6840, section 4.3. Stripping the CNAME RRset out of a positive CNAME answer leaves a response whose
     * NSEC has the queried type clear; only the CNAME bit says the answer should have been positive.
     */
    @Test
    public void testNoDataIsRejectedWhenTheCnameBitIsSet() {
        List<DnsRecord> authority = records(nsec("ns1.example.", "ns2.example.", A, CNAME, RRSIG, NSEC));
        DnssecDenialOfExistence.Result result =
                evaluator().proveNoData(name("ns1.example."), DnsRecordType.MX, authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
    }

    @Test
    public void testNoDataIsRejectedWhenTheQueriedTypeIsPresent() {
        List<DnsRecord> authority = records(nsec("ns1.example.", "ns2.example.", A, RRSIG, NSEC));
        DnssecDenialOfExistence.Result result =
                evaluator().proveNoData(name("ns1.example."), DnsRecordType.A, authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
    }

    /**
     * RFC 4035, section 5.4: "a validator MUST ignore the settings of the NSEC and RRSIG bits in an NSEC RR",
     * because the record's own existence proves both types are there. Reading them out of the bitmap would let a
     * zone that omitted them prove they do not exist.
     */
    @Test
    public void testNoDataForNsecAndRrsigIsNeverProven() {
        List<DnsRecord> authority = records(nsec("ns1.example.", "ns2.example.", A));
        DnssecDenialOfExistence evaluator = evaluator();
        assertEquals(DnssecStatus.BOGUS,
                evaluator.proveNoData(name("ns1.example."), DnsRecordType.NSEC, authority).status());
        assertEquals(DnssecStatus.BOGUS,
                evaluator.proveNoData(name("ns1.example."), DnsRecordType.RRSIG, authority).status());
    }

    /**
     * RFC 6840, section 4.4: the NS bit must be <em>set</em>. Without that check an NSEC matching any ordinary
     * name is a claim that a delegation exists there, which moves the name and everything under it out of DNSSEC.
     */
    @Test
    public void testUnsignedDelegationNeedsTheNsBit() {
        List<DnsRecord> authority = records(nsec("b.example.", "ns1.example.", A, RRSIG, NSEC));
        DnssecDenialOfExistence.Result result = evaluator().proveUnsignedDelegation(name("b.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
    }

    @Test
    public void testUnsignedDelegationIsRejectedWhenADsExists() {
        List<DnsRecord> authority = records(nsec("a.example.", "ai.example.", NS, DS, RRSIG, NSEC));
        DnssecDenialOfExistence.Result result = evaluator().proveUnsignedDelegation(name("a.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
    }

    @Test
    public void testUnsignedDelegationIsRejectedWhenTheRecordIsFromTheChild() {
        List<DnsRecord> authority = records(nsec("b.example.", "ns1.example.", NS, SOA, RRSIG, NSEC));
        DnssecDenialOfExistence.Result result = evaluator().proveUnsignedDelegation(name("b.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.BAILIWICK_VIOLATION, result.reason());
    }

    /**
     * RFC 6840, section 4.1. An ancestor delegation NSEC sits at a zone cut in the parent: NS set, SOA clear, and
     * an owner name longer than the zone that signed it. It answers for the DS at its own owner name and for
     * nothing else, because everything else there belongs to the child.
     */
    @Test
    public void testAncestorDelegationNsecDeniesOnlyDs() {
        List<DnsRecord> authority = records(nsec("b.example.", "ns1.example.", NS, RRSIG, NSEC));
        DnssecDenialOfExistence evaluator = evaluator();
        assertEquals(DnssecStatus.SECURE,
                evaluator.proveNoData(name("b.example."), DnsRecordType.DS, authority).status());
        DnssecDenialOfExistence.Result other =
                evaluator.proveNoData(name("b.example."), DnsRecordType.A, authority);
        assertEquals(DnssecStatus.BOGUS, other.status());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, other.reason());
    }

    /**
     * The same record must not be used to deny anything <em>below</em> the cut either, whatever the type. The
     * interval it spans really does contain {@code x.b.example}, which is what makes this a rule rather than an
     * accident of the ordering.
     */
    @Test
    public void testAncestorDelegationNsecCannotDenyNamesBelowTheCut() {
        List<DnsRecord> authority = records(
                nsec("b.example.", "ns1.example.", NS, RRSIG, NSEC),
                nsec("example.", "a.example.", NS, SOA, MX, RRSIG, NSEC, DNSKEY));
        DnssecDenialOfExistence evaluator = evaluator();
        assertEquals(DnssecStatus.BOGUS,
                evaluator.proveNameError(name("x.b.example."), authority).status());
        assertEquals(DnssecStatus.BOGUS,
                evaluator.proveNoData(name("x.b.example."), DnsRecordType.A, authority).status());
    }

    /**
     * RFC 6840, section 4.1, second half: a name below a DNAME is rewritten rather than absent, so an NSEC at the
     * DNAME's owner name says nothing about it.
     */
    @Test
    public void testDnameNsecCannotDenyASubdomain() {
        List<DnsRecord> authority = records(
                nsec("b.example.", "ns1.example.", DNAME, RRSIG, NSEC),
                nsec("example.", "a.example.", NS, SOA, MX, RRSIG, NSEC, DNSKEY));
        DnssecDenialOfExistence.Result result = evaluator().proveNameError(name("x.b.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
    }

    /**
     * A name error is a lie when the zone publishes a wildcard that would have matched. The proof offered here is
     * complete apart from that: the covering NSEC is genuine and its closest encloser is right.
     */
    @Test
    public void testNameErrorIsRejectedWhenTheWildcardExists() {
        List<DnsRecord> authority = records(nsec("*.w.example.", "x.w.example.", MX, RRSIG, NSEC));
        DnssecDenialOfExistence.Result result = evaluator().proveNameError(name("a.w.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
    }

    @Test
    public void testNameErrorIsRejectedWhenAnNsecMatchesTheQueryName() {
        List<DnsRecord> authority = records(nsec("ns1.example.", "ns2.example.", A, RRSIG, NSEC));
        DnssecDenialOfExistence.Result result = evaluator().proveNameError(name("ns1.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
    }

    /**
     * The Next Domain Name of a covering NSEC shares exactly the closest encloser with the query name. One that
     * shares more lies <em>below</em> the query name, which means the query name exists as an empty non-terminal
     * and the name error is a lie. {@code w.example} owns no RRset of its own in the appendix A zone but has
     * children, so it is there, and the NSEC that spans it gives itself away.
     */
    @Test
    public void testNameErrorIsRejectedWhenTheQueryNameIsAnEmptyNonTerminal() {
        List<DnsRecord> authority = records(
                nsec("ns2.example.", "*.w.example.", A, RRSIG, NSEC),
                nsec("example.", "a.example.", NS, SOA, MX, RRSIG, NSEC, DNSKEY));
        DnssecDenialOfExistence.Result result = evaluator().proveNameError(name("w.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
    }

    @Test
    public void testNameErrorNeedsAWildcardProof() {
        List<DnsRecord> authority = records(nsec("b.example.", "ns1.example.", NS, RRSIG, NSEC));
        DnssecDenialOfExistence.Result result = evaluator().proveNameError(name("ml.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.WILDCARD_PROOF_MISSING, result.reason());
    }

    /**
     * A wildcard answer may only be believed for the wildcard at the closest encloser the chain actually proves.
     * Here the proof establishes {@code w.example}, so an answer claiming to have expanded {@code *.example} is
     * hiding whatever lives between the two.
     */
    @Test
    public void testWildcardAnswerIsRejectedWhenTheClosestEncloserDisagrees() {
        List<DnsRecord> authority = records(nsec("x.y.w.example.", "xx.example.", MX, RRSIG, NSEC));
        DnssecDenialOfExistence.Result result = evaluator().proveWildcardAnswer(
                name("a.z.w.example."), name("*.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.WILDCARD_PROOF_MISSING, result.reason());
    }

    @Test
    public void testWildcardAnswerIsRejectedWhenTheQueryNameExists() {
        List<DnsRecord> authority = records(nsec("x.w.example.", "x.y.w.example.", MX, RRSIG, NSEC));
        DnssecDenialOfExistence.Result result = evaluator().proveWildcardAnswer(
                name("x.w.example."), name("*.w.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
    }

    @Test
    public void testWildcardOwnerMustBeAWildcardInTheZone() {
        List<DnsRecord> authority = records(nsec("x.y.w.example.", "xx.example.", MX, RRSIG, NSEC));
        DnssecDenialOfExistence evaluator = evaluator();
        assertEquals(DnssecStatus.BOGUS, evaluator.proveWildcardAnswer(
                name("a.z.w.example."), name("w.example."), authority).status());
        assertEquals(DnssecStatus.BOGUS, evaluator.proveWildcardAnswer(
                name("a.z.w.example."), name("*.w.other."), authority).status());
    }

    /**
     * An NSEC whose owner lies outside the zone that signed the response takes no part, however conveniently it
     * spans the query name.
     *
     * <p>The record used here is the shape that matters. Canonical order compares the rightmost label first, so an
     * NSEC owned by {@code z.aaa} whose next domain name is {@code a.zzz} spans everything in between, which is
     * most of the namespace: {@code *.example} included. Supplied alongside a genuine NSEC from the zone it turns
     * a name error that is missing its wildcard proof into one that appears complete.</p>
     */
    @Test
    public void testOutOfZoneNsecIsIgnored() {
        List<DnsRecord> asWildcardProof = records(
                nsec("b.example.", "ns1.example.", NS, RRSIG, NSEC),
                nsec("z.aaa.", "a.zzz.", A, RRSIG, NSEC));
        DnssecDenialOfExistence.Result result = evaluator().proveNameError(name("ml.example."), asWildcardProof);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.WILDCARD_PROOF_MISSING, result.reason());

        List<DnsRecord> onItsOwn = records(nsec("z.aaa.", "a.zzz.", A, RRSIG, NSEC));
        DnssecDenialOfExistence.Result alone = evaluator().proveNameError(name("ml.example."), onItsOwn);
        assertEquals(DnssecStatus.BOGUS, alone.status());
        assertEquals(DnssecFailureReason.NSEC_MISSING, alone.reason());
    }

    // ---------------------------------------------------------------------------------------------------------
    // Bounds
    // ---------------------------------------------------------------------------------------------------------

    /**
     * The shape of hickory-dns GHSA-3v94-mw7p-v465: a response whose zone apex is not an ancestor of the query
     * name. A closest-encloser search that walks up until it recognises the apex never recognises it and runs off
     * the top of the tree. Here the mismatch is caught before any search starts, and nothing is spent.
     */
    @Test
    public void testQueryNameOutsideTheZoneIsRejectedBeforeAnyWork() {
        DnssecBudget budget = new DnssecBudget(DnssecLimits.defaults(), DnssecClock.SYSTEM);
        DnssecDenialOfExistence evaluator = new DnssecDenialOfExistence(name("other.test."), budget);
        List<DnsRecord> authority = records(nsec("b.example.", "ns1.example.", NS, RRSIG, NSEC));
        for (DnssecDenialOfExistence.Result result : Arrays.asList(
                evaluator.proveNameError(name("a.b.c.d.e.f.example."), authority),
                evaluator.proveNoData(name("a.b.c.d.e.f.example."), DnsRecordType.A, authority),
                evaluator.proveNoData(name("a.b.c.d.e.f.example."), DnsRecordType.DS, authority),
                evaluator.proveWildcardAnswer(name("a.b.c.d.e.f.example."), name("*.e.f.example."), authority),
                evaluator.proveUnsignedDelegation(name("a.b.c.d.e.f.example."), authority))) {
            assertEquals(DnssecStatus.BOGUS, result.status());
            assertEquals(DnssecFailureReason.BAILIWICK_VIOLATION, result.reason());
        }
        assertEquals(0, budget.nsec3HashComputations());
    }

    /**
     * BIND's CVE-2026-1519 and Unbound's CVE-2026-42923 were the same missing bound reached down two different
     * paths, an unsigned-delegation referral and a negative DS lookup. One budget, threaded through every entry
     * point, is what keeps a bound from being present on four paths and absent on the fifth.
     */
    @Test
    public void testTheRecordBoundBindsOnEveryEntryPoint() {
        DnssecLimits limits = DnssecLimits.newBuilder().maxNsecRecordsPerProof(1).build();
        List<DnsRecord> authority = records(
                nsec("b.example.", "ns1.example.", NS, RRSIG, NSEC),
                nsec("example.", "a.example.", NS, SOA, MX, RRSIG, NSEC, DNSKEY));
        DnsName qname = name("ml.example.");
        for (DnssecDenialOfExistence.Result result : Arrays.asList(
                evaluator(limits).proveNameError(qname, authority),
                evaluator(limits).proveNoData(qname, DnsRecordType.A, authority),
                evaluator(limits).proveNoData(name("b.example."), DnsRecordType.DS, authority),
                evaluator(limits).proveWildcardAnswer(qname, name("*.example."), authority),
                evaluator(limits).proveUnsignedDelegation(name("b.example."), authority))) {
            // Never INSECURE: an attacker who can make a validation expensive would otherwise hold a way to
            // switch validation off for any zone.
            assertEquals(DnssecStatus.BOGUS, result.status());
            assertEquals(DnssecFailureReason.LIMIT_EXCEEDED, result.reason());
        }
    }

    /**
     * The same five proofs succeed once the bound is wide enough, so the test above is measuring the bound and not
     * some other defect in the fixture.
     */
    @Test
    public void testTheSameProofsSucceedWithinTheBound() {
        DnssecLimits limits = DnssecLimits.newBuilder().maxNsecRecordsPerProof(2).build();
        List<DnsRecord> authority = records(
                nsec("b.example.", "ns1.example.", NS, RRSIG, NSEC),
                nsec("example.", "a.example.", NS, SOA, MX, RRSIG, NSEC, DNSKEY));
        assertEquals(DnssecStatus.SECURE,
                evaluator(limits).proveNameError(name("ml.example."), authority).status());
        assertEquals(DnssecStatus.SECURE,
                evaluator(limits).proveNoData(name("b.example."), DnsRecordType.DS, authority).status());
        assertEquals(DnssecStatus.INSECURE,
                evaluator(limits).proveUnsignedDelegation(name("b.example."), authority).status());
    }

    /**
     * {@link DnssecDenialOfExistence.Result#status()} is decided by the proof rather than read off
     * {@link DnssecFailureReason#impliedStatus()}, so the two could drift apart without anything failing to
     * compile. Every verdict this class can reach is checked here against the reason it carries, so that an edit
     * to the shared reason table cannot quietly turn a bogus proof into an insecure one, or the reverse.
     */
    @Test
    public void testEveryVerdictAgreesWithTheReasonItCarries() {
        List<DnsRecord> nameError = records(
                nsec("b.example.", "ns1.example.", NS, RRSIG, NSEC),
                nsec("example.", "a.example.", NS, SOA, MX, RRSIG, NSEC, DNSKEY));
        List<DnsRecord> wildcard = records(
                nsec("x.y.w.example.", "xx.example.", MX, RRSIG, NSEC),
                nsec("*.w.example.", "x.w.example.", MX, RRSIG, NSEC));
        DnssecLimits tight = DnssecLimits.newBuilder().maxNsecRecordsPerProof(1).build();
        for (DnssecDenialOfExistence.Result result : Arrays.asList(
                evaluator().proveNameError(name("ml.example."), nameError),
                evaluator().proveNameError(name("ns1.example."), nameError),
                evaluator().proveNameError(name("ml.example."), Collections.<DnsRecord>emptyList()),
                evaluator().proveNoData(name("b.example."), DnsRecordType.DS, nameError),
                evaluator().proveNoData(name("b.example."), DnsRecordType.A, nameError),
                evaluator().proveNoData(name("a.z.w.example."), DnsRecordType.AAAA, wildcard),
                evaluator().proveWildcardAnswer(name("a.z.w.example."), name("*.w.example."), wildcard),
                evaluator().proveWildcardAnswer(name("a.z.w.example."), name("*.example."), wildcard),
                evaluator().proveUnsignedDelegation(name("b.example."), nameError),
                evaluator().proveUnsignedDelegation(name("ns1.example."), nameError),
                evaluator(tight).proveNameError(name("ml.example."), nameError))) {
            assertEquals(result.reason().impliedStatus(), result.status(), result.toString());
            assertEquals(result.status() == DnssecStatus.SECURE, result.isProven(), result.toString());
        }
    }

    @Test
    public void testAccessorsAndArgumentChecks() {
        DnssecBudget budget = new DnssecBudget(DnssecLimits.defaults(), DnssecClock.SYSTEM);
        DnssecDenialOfExistence evaluator = new DnssecDenialOfExistence(EXAMPLE, budget);
        assertEquals(EXAMPLE, evaluator.zone());
        assertSame(budget, evaluator.budget());
        assertTrue(evaluator.toString().contains("example"));
        assertThrows(NullPointerException.class, () -> new DnssecDenialOfExistence(null, budget));
        assertThrows(NullPointerException.class, () -> new DnssecDenialOfExistence(EXAMPLE, null));
        assertThrows(NullPointerException.class,
                () -> evaluator.proveNameError(null, Collections.<DnsRecord>emptyList()));
        assertThrows(NullPointerException.class, () -> evaluator.proveNameError(EXAMPLE, null));
        assertThrows(NullPointerException.class,
                () -> evaluator.proveNoData(EXAMPLE, null, Collections.<DnsRecord>emptyList()));
        assertThrows(NullPointerException.class,
                () -> evaluator.proveWildcardAnswer(EXAMPLE, null, Collections.<DnsRecord>emptyList()));
    }
}
