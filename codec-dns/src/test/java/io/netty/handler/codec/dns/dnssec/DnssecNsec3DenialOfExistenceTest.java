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
import io.netty.util.CharsetUtil;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@code NSEC3} half of {@link DnssecDenialOfExistence}, worked against the seven example responses of
 * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#appendix-B">RFC 5155, appendix B</a> over the signed zone
 * of its appendix A, followed by the shapes those examples do not contain.
 *
 * <p>Every owner name here is a label RFC 5155 publishes, and every hash a proof has to compute for itself is one
 * the appendix names in a comment. {@link DnsNsec3HasherTest} checks that this implementation reproduces them, so
 * a failure here is a failure of the proof logic and not of the hash.</p>
 *
 * <p>The example zone sets the Opt-Out flag on every {@code NSEC3} record. That is why most of these responses are
 * {@link DnssecStatus#INSECURE} rather than {@link DnssecStatus#SECURE}: RFC 5155, section 9.2 forbids the
 * {@code AD} bit on a response whose closest encloser proof has an opt-out record covering the "next closer" name,
 * because a name in that span may still exist as an insecure delegation. The answer is still returned, it is
 * simply not authenticated. Where a test needs the authenticated outcome it repeats the same records with the flag
 * clear.</p>
 */
public class DnssecNsec3DenialOfExistenceTest {

    private static final int A = 1;
    private static final int NS = 2;
    private static final int CNAME = 5;
    private static final int SOA = 6;
    private static final int MX = 15;
    private static final int DNAME = 39;
    private static final int DS = 43;
    private static final int RRSIG = 46;
    private static final int DNSKEY = 48;
    private static final int NSEC3PARAM = 51;

    private static final DnsName EXAMPLE = DnsName.fromString("example.");

    /**
     * The parameters of the appendix A zone: SHA-1, opt-out, 12 iterations, salt {@code aabbccdd}.
     */
    private static final byte[] SALT = { (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd };
    private static final int ITERATIONS = 12;
    private static final int OPT_OUT = 1;
    private static final int NO_FLAGS = 0;

    // The NSEC3 owner names of appendix A, which are the base32hex hashes of the zone's names.
    private static final String H_EXAMPLE = "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom";
    private static final String H_NS1 = "2t7b4g4vsa5smi47k61mv5bv1a22bojr";
    private static final String H_X_Y_W = "2vptu5timamqttgl4luu9kg21e0aor3s";
    private static final String H_A = "35mthgpgcu1qg68fab165klnsnk3dpvl";
    private static final String H_X_W = "b4um86eghhds6nea196smvmlo4ors995";
    private static final String H_AI = "gjeqe526plbf1g8mklp59enfd789njgi";
    private static final String H_Y_W = "ji6neoaepv8b5o6k4ev33abha8ht9fgc";
    private static final String H_W = "k8udemvp1j2f7eg6jebps17vp3n8i58h";
    private static final String H_NS1_NSEC3 = "kohar7mbb8dc2ce8a9qvl8hon4k53uhi";
    private static final String H_NS2 = "q04jkcevqvmu85r014c7dkba38o0ji5r";
    private static final String H_WILDCARD_W = "r53bq7cc2uvmubfu5ocmm6pers9tk9en";
    private static final String H_XX = "t644ebqk9bibcna874givr6joj62mlhv";

    private final List<DnsRecord> allocated = new ArrayList<DnsRecord>();

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

    private static byte[] hash(String base32hex) {
        return Base32Hex.decode(base32hex.getBytes(CharsetUtil.US_ASCII));
    }

    private DnsNsec3Record nsec3(String owner, int flags, String next, int... types) {
        return nsec3(owner + ".example.", DnsNsec3Hasher.HASH_ALGORITHM_SHA1, flags, ITERATIONS, SALT,
                hash(next), types);
    }

    private DnsNsec3Record nsec3(String owner, int algorithm, int flags, int iterations, byte[] salt, byte[] next,
                                 int... types) {
        ByteBuf rdata = Unpooled.buffer();
        rdata.writeByte(algorithm).writeByte(flags).writeShort(iterations).writeByte(salt.length).writeBytes(salt);
        rdata.writeByte(next.length).writeBytes(next);
        DnssecDenialOfExistenceTest.writeTypeBitmap(rdata, types);
        DnsNsec3Record record = new DnsNsec3Record(owner, DnsRecordType.NSEC3, DnsRecord.CLASS_IN, 3600,
                name(owner), rdata);
        allocated.add(record);
        return record;
    }

    private static List<DnsRecord> records(DnsRecord... records) {
        return Arrays.<DnsRecord>asList(records);
    }

    /**
     * The three records of appendix B.1: the apex, which covers the "next closer" name {@code c.x.w.example}; the
     * record matching the closest encloser {@code x.w.example}; and the record for {@code a.example}, which covers
     * the wildcard {@code *.x.w.example}.
     */
    private List<DnsRecord> nameErrorProof(int flags) {
        return records(
                nsec3(H_EXAMPLE, flags, H_NS1, MX, DNSKEY, NS, SOA, NSEC3PARAM, RRSIG),
                nsec3(H_X_W, flags, H_AI, MX, RRSIG),
                nsec3(H_A, flags, H_X_W, NS, DS, RRSIG));
    }

    /**
     * The two records of appendix B.3, a referral to the unsigned zone {@code c.example}: nothing matches the
     * delegation name, and its "next closer" name is covered by an opt-out record.
     */
    private List<DnsRecord> optOutReferralProof(int flags) {
        return records(
                nsec3(H_A, flags, H_X_W, NS, DS, RRSIG),
                nsec3(H_EXAMPLE, flags, H_NS1, MX, DNSKEY, NS, SOA, NSEC3PARAM, RRSIG));
    }

    // ---------------------------------------------------------------------------------------------------------
    // RFC 5155, appendix B
    // ---------------------------------------------------------------------------------------------------------

    /**
     * B.1, an authoritative name error for {@code a.c.x.w.example}. The closest encloser is {@code x.w.example},
     * the "next closer" name {@code c.x.w.example} is covered by the apex record, and the wildcard
     * {@code *.x.w.example} is covered by the record for {@code a.example}.
     */
    @Test
    public void testB1NameError() {
        DnssecDenialOfExistence.Result result =
                evaluator().proveNameError(name("a.c.x.w.example."), nameErrorProof(OPT_OUT));
        assertEquals(DnssecStatus.INSECURE, result.status());
        assertEquals(DnssecFailureReason.NSEC3_OPT_OUT, result.reason());
        assertEquals(name("x.w.example."), result.closestEncloser());
        assertTrue(result.isOptOut());
        assertFalse(result.isProven());
    }

    /**
     * The same three records with the Opt-Out flag clear. Nothing else changes, which is what makes the flag, and
     * not some other property of the proof, the reason B.1 is not authenticated.
     */
    @Test
    public void testNameErrorIsSecureWithoutOptOut() {
        DnssecDenialOfExistence.Result result =
                evaluator().proveNameError(name("a.c.x.w.example."), nameErrorProof(NO_FLAGS));
        assertEquals(DnssecStatus.SECURE, result.status());
        assertEquals(DnssecFailureReason.NONE, result.reason());
        assertEquals(name("x.w.example."), result.closestEncloser());
        assertFalse(result.isOptOut());
    }

    /**
     * B.2, a no data error: the record matches {@code ns1.example} and has neither MX nor CNAME. No closest
     * encloser proof is involved, so opt-out has nothing to weaken and the answer is authenticated.
     */
    @Test
    public void testB2NoData() {
        List<DnsRecord> authority = records(nsec3(H_NS1, OPT_OUT, H_X_Y_W, A, RRSIG));
        DnssecDenialOfExistence.Result result =
                evaluator().proveNoData(name("ns1.example."), DnsRecordType.MX, authority);
        assertEquals(DnssecStatus.SECURE, result.status());
        assertEquals(DnssecFailureReason.NONE, result.reason());
        assertNull(result.closestEncloser());
        assertFalse(result.isOptOut());
    }

    /**
     * B.2.1, a no data error at an empty non-terminal. The record matching {@code y.w.example} has an empty Type
     * Bit Maps field, which RFC 6840, section 6.4 corrects RFC 5155's grammar to allow, and which asserts that no
     * type at all exists there.
     */
    @Test
    public void testB21EmptyNonTerminalNoData() {
        List<DnsRecord> authority = records(nsec3(H_Y_W, OPT_OUT, H_W));
        DnssecDenialOfExistence.Result result =
                evaluator().proveNoData(name("y.w.example."), DnsRecordType.A, authority);
        assertEquals(DnssecStatus.SECURE, result.status());
        assertNull(result.closestEncloser());
    }

    /**
     * B.3, a referral to an opt-out unsigned zone. Nothing matches {@code c.example} at all; what the proof shows
     * is that its closest provable encloser is the apex and that the span containing it is opted out. This is
     * opt-out's sanctioned use, and RFC 5155, section 8.9 requires the flag to be set here rather than merely
     * tolerating it.
     */
    @Test
    public void testB3ReferralToOptOutUnsignedZone() {
        DnssecDenialOfExistence.Result result =
                evaluator().proveUnsignedDelegation(name("c.example."), optOutReferralProof(OPT_OUT));
        assertEquals(DnssecStatus.INSECURE, result.status());
        assertEquals(DnssecFailureReason.NSEC3_OPT_OUT, result.reason());
        assertEquals(EXAMPLE, result.closestEncloser());
        assertTrue(result.isOptOut());
    }

    /**
     * Without the flag the same records prove nothing about {@code c.example}: an NSEC3 chain with opt-out clear
     * has a record at every name, so a delegation with none simply is not there.
     */
    @Test
    public void testReferralWithNoMatchAndNoOptOutIsRejected() {
        DnssecDenialOfExistence.Result result =
                evaluator().proveUnsignedDelegation(name("c.example."), optOutReferralProof(NO_FLAGS));
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.NSEC_MISSING, result.reason());
    }

    /**
     * B.4, an answer expanded from {@code *.w.example}. Section 8.8 asks only that the "next closer" name
     * {@code z.w.example} be covered; the answer itself is what proves {@code w.example} exists.
     */
    @Test
    public void testB4WildcardExpansion() {
        List<DnsRecord> authority = records(nsec3(H_NS2, OPT_OUT, H_WILDCARD_W, A, RRSIG));
        DnssecDenialOfExistence.Result result = evaluator().proveWildcardAnswer(
                name("a.z.w.example."), name("*.w.example."), authority);
        assertEquals(DnssecStatus.INSECURE, result.status());
        assertEquals(DnssecFailureReason.NSEC3_OPT_OUT, result.reason());
        assertEquals(name("w.example."), result.closestEncloser());
    }

    @Test
    public void testWildcardExpansionIsSecureWithoutOptOut() {
        List<DnsRecord> authority = records(nsec3(H_NS2, NO_FLAGS, H_WILDCARD_W, A, RRSIG));
        DnssecDenialOfExistence.Result result = evaluator().proveWildcardAnswer(
                name("a.z.w.example."), name("*.w.example."), authority);
        assertEquals(DnssecStatus.SECURE, result.status());
        assertEquals(name("w.example."), result.closestEncloser());
    }

    /**
     * B.5, a no data error for a name covered by a wildcard. Section 8.7: a closest encloser proof for
     * {@code a.z.w.example} plus a record matching {@code *.w.example} whose bitmap has MX but not AAAA.
     */
    @Test
    public void testB5WildcardNoData() {
        List<DnsRecord> authority = records(
                nsec3(H_W, OPT_OUT, H_NS1_NSEC3),
                nsec3(H_NS2, OPT_OUT, H_WILDCARD_W, A, RRSIG),
                nsec3(H_WILDCARD_W, OPT_OUT, H_XX, MX, RRSIG));
        DnssecDenialOfExistence.Result result =
                evaluator().proveNoData(name("a.z.w.example."), DnsRecordType.AAAA, authority);
        assertEquals(DnssecStatus.INSECURE, result.status());
        assertEquals(DnssecFailureReason.NSEC3_OPT_OUT, result.reason());
        assertEquals(name("w.example."), result.closestEncloser());
    }

    @Test
    public void testWildcardNoDataIsSecureWithoutOptOut() {
        List<DnsRecord> authority = records(
                nsec3(H_W, NO_FLAGS, H_NS1_NSEC3),
                nsec3(H_NS2, NO_FLAGS, H_WILDCARD_W, A, RRSIG),
                nsec3(H_WILDCARD_W, NO_FLAGS, H_XX, MX, RRSIG));
        DnssecDenialOfExistence.Result result =
                evaluator().proveNoData(name("a.z.w.example."), DnsRecordType.AAAA, authority);
        assertEquals(DnssecStatus.SECURE, result.status());
        assertEquals(name("w.example."), result.closestEncloser());
    }

    /**
     * B.6, a DS query that reached the child. RFC 5155's own commentary on this response says it: "The NSEC3 RR
     * indicates the presence of an SOA RR, showing that this NSEC3 RR is from the apex of the child, not from the
     * zone cut of the parent."
     */
    @Test
    public void testB6DsQueryAnsweredByTheChildIsRejected() {
        List<DnsRecord> authority =
                records(nsec3(H_EXAMPLE, OPT_OUT, H_NS1, MX, DNSKEY, NS, SOA, NSEC3PARAM, RRSIG));
        DnssecDenialOfExistence.Result result = evaluator().proveNoData(EXAMPLE, DnsRecordType.DS, authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.BAILIWICK_VIOLATION, result.reason());
    }

    // ---------------------------------------------------------------------------------------------------------
    // Parameters: RFC 5155 sections 8.1 and 8.2, RFC 9276 section 3.2
    // ---------------------------------------------------------------------------------------------------------

    /**
     * RFC 5155, section 8.2 leaves it a MAY to reject records that disagree on the parameters. It is a MUST here:
     * records that disagree need one hash chain each, and the query name has to be hashed against every chain at
     * every step of every closest-encloser walk. That product is the whole of the NSEC3 amplification, and no
     * legitimate zone needs it, since appendix C.1 requires one complete set of records per salt.
     */
    @Test
    public void testRecordsThatDisagreeOnTheParametersAreRejected() {
        byte[] otherSalt = { 0x11, 0x22, 0x33, 0x44 };
        List<DnsRecord> differentSalt = records(
                nsec3(H_EXAMPLE + ".example.", DnsNsec3Hasher.HASH_ALGORITHM_SHA1, OPT_OUT, ITERATIONS, SALT,
                        hash(H_NS1), MX, RRSIG),
                nsec3(H_X_W + ".example.", DnsNsec3Hasher.HASH_ALGORITHM_SHA1, OPT_OUT, ITERATIONS, otherSalt,
                        hash(H_AI), MX, RRSIG));
        DnssecDenialOfExistence.Result result =
                evaluator().proveNameError(name("a.c.x.w.example."), differentSalt);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, result.reason());

        List<DnsRecord> differentIterations = records(
                nsec3(H_EXAMPLE + ".example.", DnsNsec3Hasher.HASH_ALGORITHM_SHA1, OPT_OUT, ITERATIONS, SALT,
                        hash(H_NS1), MX, RRSIG),
                nsec3(H_X_W + ".example.", DnsNsec3Hasher.HASH_ALGORITHM_SHA1, OPT_OUT, ITERATIONS + 1, SALT,
                        hash(H_AI), MX, RRSIG));
        assertEquals(DnssecStatus.BOGUS,
                evaluator().proveNameError(name("a.c.x.w.example."), differentIterations).status());
    }

    /**
     * RFC 9276, section 3.2 asks for two thresholds. Between them the answer is returned unauthenticated; above
     * the higher one it is rejected outright, so that the unauthenticated band stays too narrow to be a general
     * way of switching validation off for a zone.
     *
     * <p>Neither verdict needs a single hash to be computed, which is the point: the iteration count is checked
     * before the work it asks for is done.</p>
     */
    @Test
    public void testIterationCountPolicy() {
        DnssecBudget budget = new DnssecBudget(DnssecLimits.defaults(), DnssecClock.SYSTEM);
        DnssecDenialOfExistence evaluator = new DnssecDenialOfExistence(EXAMPLE, budget);
        List<DnsRecord> tooMany = records(nsec3(H_EXAMPLE + ".example.",
                DnsNsec3Hasher.HASH_ALGORITHM_SHA1, OPT_OUT, 101, SALT, hash(H_NS1), MX, RRSIG));
        DnssecDenialOfExistence.Result insecure = evaluator.proveNameError(name("a.c.x.w.example."), tooMany);
        assertEquals(DnssecStatus.INSECURE, insecure.status());
        assertEquals(DnssecFailureReason.NSEC3_ITERATIONS_TOO_HIGH, insecure.reason());

        List<DnsRecord> farTooMany = records(nsec3(H_EXAMPLE + ".example.",
                DnsNsec3Hasher.HASH_ALGORITHM_SHA1, OPT_OUT, 501, SALT, hash(H_NS1), MX, RRSIG));
        DnssecDenialOfExistence.Result bogus = evaluator.proveNameError(name("a.c.x.w.example."), farTooMany);
        assertEquals(DnssecStatus.BOGUS, bogus.status());
        assertEquals(DnssecFailureReason.LIMIT_EXCEEDED, bogus.reason());
        assertEquals(0, budget.nsec3HashComputations());
    }

    /**
     * RFC 5155, section 8.1: an unknown hash type is ignored, and "the practical result of this is that responses
     * containing only such NSEC3 RRs will generally be considered bogus". Ignoring rather than failing is what
     * lets a zone rolling to a new hash algorithm publish both chains at once.
     */
    @Test
    public void testUnknownHashAlgorithmRecordsAreIgnored() {
        List<DnsRecord> authority = records(
                nsec3(H_EXAMPLE + ".example.", 2, OPT_OUT, ITERATIONS, SALT, hash(H_NS1), MX, RRSIG),
                nsec3(H_X_W + ".example.", 2, OPT_OUT, ITERATIONS, SALT, hash(H_AI), MX, RRSIG));
        DnssecDenialOfExistence.Result result = evaluator().proveNameError(name("a.c.x.w.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.NSEC_MISSING, result.reason());
    }

    /**
     * RFC 5155, section 8.2: "A validator MUST ignore NSEC3 RRs with a Flag fields value other than zero or one."
     * The reserved bits have no meaning yet, so a record that sets one is asserting something this validator
     * cannot read.
     */
    @Test
    public void testRecordsWithReservedFlagsAreIgnored() {
        List<DnsRecord> authority = records(
                nsec3(H_EXAMPLE, 0x02, H_NS1, MX, DNSKEY, NS, SOA, NSEC3PARAM, RRSIG),
                nsec3(H_X_W, 0x80, H_AI, MX, RRSIG));
        DnssecDenialOfExistence.Result result = evaluator().proveNameError(name("a.c.x.w.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.NSEC_MISSING, result.reason());
    }

    @Test
    public void testSaltLongerThanTheLimitIsRejected() {
        DnssecLimits limits = DnssecLimits.newBuilder().maxNsec3SaltLength(2).build();
        List<DnsRecord> authority = records(nsec3(H_EXAMPLE, OPT_OUT, H_NS1, MX, RRSIG));
        DnssecDenialOfExistence.Result result =
                evaluator(limits).proveNameError(name("a.c.x.w.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.LIMIT_EXCEEDED, result.reason());
    }

    /**
     * A record whose owner name is not one label below the zone apex, whose leftmost label is not base32hex, or
     * whose two hashes are not the length the algorithm produces cannot take part. Equal lengths in particular are
     * what make the interval test a comparison of hashes rather than of strings that happen to start alike.
     */
    @Test
    public void testUnusableOwnerNamesAreIgnored() {
        // The whole of the B.1 proof, republished one label lower. Every hash in it is still the hash of a name in
        // "example", so a validator that does not check where a record sits accepts the proof entire and lets a
        // delegated child deny names in its parent.
        List<DnsRecord> deepOwners = records(
                nsec3(H_EXAMPLE + ".sub.example.", DnsNsec3Hasher.HASH_ALGORITHM_SHA1, OPT_OUT, ITERATIONS, SALT,
                        hash(H_NS1), MX, DNSKEY, NS, SOA, NSEC3PARAM, RRSIG),
                nsec3(H_X_W + ".sub.example.", DnsNsec3Hasher.HASH_ALGORITHM_SHA1, OPT_OUT, ITERATIONS, SALT,
                        hash(H_AI), MX, RRSIG),
                nsec3(H_A + ".sub.example.", DnsNsec3Hasher.HASH_ALGORITHM_SHA1, OPT_OUT, ITERATIONS, SALT,
                        hash(H_X_W), NS, DS, RRSIG));
        assertEquals(DnssecFailureReason.NSEC_MISSING,
                evaluator().proveNameError(name("a.c.x.w.example."), deepOwners).reason());

        List<DnsRecord> notBase32 = records(nsec3("abc.example.",
                DnsNsec3Hasher.HASH_ALGORITHM_SHA1, OPT_OUT, ITERATIONS, SALT, hash(H_NS1), MX, RRSIG));
        assertEquals(DnssecFailureReason.NSEC_MISSING,
                evaluator().proveNameError(name("a.c.x.w.example."), notBase32).reason());

        List<DnsRecord> shortNextHash = records(nsec3(H_EXAMPLE + ".example.",
                DnsNsec3Hasher.HASH_ALGORITHM_SHA1, OPT_OUT, ITERATIONS, SALT, new byte[10], MX, RRSIG));
        assertEquals(DnssecFailureReason.NSEC_MISSING,
                evaluator().proveNameError(name("a.c.x.w.example."), shortNextHash).reason());
    }

    // ---------------------------------------------------------------------------------------------------------
    // The shapes appendix B does not contain
    // ---------------------------------------------------------------------------------------------------------

    /**
     * The closing rule of RFC 5155, section 8.3: the record matching the closest encloser must have the DNAME bit
     * clear and may only have NS set if SOA is set. Otherwise it comes from the parent side of a zone cut, or from
     * above a DNAME, and denying names under it is exactly what it may not do.
     */
    @Test
    public void testClosestEncloserRecordMustBeFromTheAuthoritativeZone() {
        List<DnsRecord> delegationAtEncloser = records(
                nsec3(H_EXAMPLE, OPT_OUT, H_NS1, MX, DNSKEY, NS, SOA, NSEC3PARAM, RRSIG),
                nsec3(H_X_W, OPT_OUT, H_AI, NS, RRSIG),
                nsec3(H_A, OPT_OUT, H_X_W, NS, DS, RRSIG));
        assertEquals(DnssecStatus.BOGUS,
                evaluator().proveNameError(name("a.c.x.w.example."), delegationAtEncloser).status());

        List<DnsRecord> dnameAtEncloser = records(
                nsec3(H_EXAMPLE, OPT_OUT, H_NS1, MX, DNSKEY, NS, SOA, NSEC3PARAM, RRSIG),
                nsec3(H_X_W, OPT_OUT, H_AI, DNAME, RRSIG),
                nsec3(H_A, OPT_OUT, H_X_W, NS, DS, RRSIG));
        assertEquals(DnssecStatus.BOGUS,
                evaluator().proveNameError(name("a.c.x.w.example."), dnameAtEncloser).status());
    }

    /**
     * RFC 5155, section 8.3 again: reaching a record that matches the query name itself with the flag still clear
     * is bogus, because nothing was shown not to exist.
     */
    @Test
    public void testNameErrorIsRejectedWhenTheQueryNameExists() {
        List<DnsRecord> authority = records(nsec3(H_NS1, OPT_OUT, H_X_Y_W, A, RRSIG));
        DnssecDenialOfExistence.Result result = evaluator().proveNameError(name("ns1.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
    }

    /**
     * RFC 6840, section 4.3, on the NSEC3 side.
     */
    @Test
    public void testNoDataIsRejectedWhenTheCnameBitIsSet() {
        List<DnsRecord> authority = records(nsec3(H_NS1, OPT_OUT, H_X_Y_W, A, CNAME, RRSIG));
        DnssecDenialOfExistence.Result result =
                evaluator().proveNoData(name("ns1.example."), DnsRecordType.MX, authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
    }

    /**
     * RFC 6840, section 4.1: a record at a zone cut in the parent, NS set and SOA clear, answers for the DS there
     * and for nothing else. {@code a.example} is a delegation in the appendix A zone, so its record is exactly
     * that shape.
     */
    @Test
    public void testAncestorDelegationRecordDeniesOnlyDs() {
        List<DnsRecord> authority = records(nsec3(H_A, OPT_OUT, H_X_W, NS, RRSIG));
        DnssecDenialOfExistence evaluator = evaluator();
        assertEquals(DnssecStatus.SECURE,
                evaluator.proveNoData(name("a.example."), DnsRecordType.DS, authority).status());
        DnssecDenialOfExistence.Result other =
                evaluator.proveNoData(name("a.example."), DnsRecordType.A, authority);
        assertEquals(DnssecStatus.BOGUS, other.status());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, other.reason());
    }

    /**
     * RFC 6840, section 4.4 on the NSEC3 side: {@code a.example} has a DS, so the delegation to it is signed and a
     * referral there is not insecure. The published record for it carries NS, DS and RRSIG.
     */
    @Test
    public void testUnsignedDelegationIsRejectedWhenADsExists() {
        List<DnsRecord> authority = records(nsec3(H_A, OPT_OUT, H_X_W, NS, DS, RRSIG));
        DnssecDenialOfExistence.Result result = evaluator().proveUnsignedDelegation(name("a.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
    }

    @Test
    public void testUnsignedDelegationNeedsTheNsBit() {
        List<DnsRecord> authority = records(nsec3(H_A, OPT_OUT, H_X_W, A, RRSIG));
        DnssecDenialOfExistence.Result result = evaluator().proveUnsignedDelegation(name("a.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
    }

    @Test
    public void testUnsignedDelegationWithAMatchingRecordAndNoDs() {
        List<DnsRecord> authority = records(nsec3(H_A, OPT_OUT, H_X_W, NS, RRSIG));
        DnssecDenialOfExistence.Result result = evaluator().proveUnsignedDelegation(name("a.example."), authority);
        assertEquals(DnssecStatus.INSECURE, result.status());
        assertEquals(DnssecFailureReason.UNSIGNED_DELEGATION, result.reason());
        assertEquals(name("a.example."), result.closestEncloser());
        // An NSEC3 that matches the delegation asserts it exists, so the answer does not rest on opt-out even
        // though the record happens to carry the flag: RFC 5155, section 6 says as much.
        assertFalse(result.isOptOut());
    }

    /**
     * <a href="https://www.rfc-editor.org/errata/eid3441">RFC 5155 erratum 3441</a> against section 8.5. As
     * published, section 8.5 has only the branch where a record matches the query name, so a NODATA for an empty
     * non-terminal underneath an opted-out insecure delegation has no rule at all. The erratum adds one, and the
     * verdict is insecure rather than proven: an opt-out span asserts nothing about the names in it, so this is
     * never a way to prove NODATA for a type at a name that exists.
     */
    @Test
    public void testNoDataForANonDsTypeUnderAnOptOutSpan() {
        DnssecDenialOfExistence.Result result =
                evaluator().proveNoData(name("c.example."), DnsRecordType.A, optOutReferralProof(OPT_OUT));
        assertEquals(DnssecStatus.INSECURE, result.status());
        assertEquals(DnssecFailureReason.NSEC3_OPT_OUT, result.reason());
        assertEquals(EXAMPLE, result.closestEncloser());
        assertTrue(result.isOptOut());
    }

    @Test
    public void testNoDataForANonDsTypeNeedsOptOutWhenNothingMatches() {
        DnssecDenialOfExistence.Result result =
                evaluator().proveNoData(name("c.example."), DnsRecordType.A, optOutReferralProof(NO_FLAGS));
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.NSEC_MISSING, result.reason());
    }

    /**
     * RFC 5155, section 8.6, second half: a DS query for a name with no record of its own is answered by a closest
     * provable encloser proof with the Opt-Out bit set on the record covering the "next closer" name. That is the
     * same shape as the referral of B.3, reached through the negative DS lookup instead, which is the path
     * Unbound's CVE-2026-42923 left unbounded while the referral path was bounded.
     */
    @Test
    public void testDsNoDataUnderAnOptOutSpan() {
        DnssecDenialOfExistence.Result result =
                evaluator().proveNoData(name("c.example."), DnsRecordType.DS, optOutReferralProof(OPT_OUT));
        assertEquals(DnssecStatus.INSECURE, result.status());
        assertEquals(DnssecFailureReason.NSEC3_OPT_OUT, result.reason());
    }

    @Test
    public void testDsNoDataNeedsOptOutWhenNothingMatches() {
        DnssecDenialOfExistence.Result result =
                evaluator().proveNoData(name("c.example."), DnsRecordType.DS, optOutReferralProof(NO_FLAGS));
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.NSEC_MISSING, result.reason());
    }

    @Test
    public void testWildcardAnswerNeedsTheNextCloserCovered() {
        List<DnsRecord> authority = records(nsec3(H_NS1, OPT_OUT, H_X_Y_W, A, RRSIG));
        DnssecDenialOfExistence.Result result = evaluator().proveWildcardAnswer(
                name("a.z.w.example."), name("*.w.example."), authority);
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.WILDCARD_PROOF_MISSING, result.reason());
    }

    // ---------------------------------------------------------------------------------------------------------
    // Bounds
    // ---------------------------------------------------------------------------------------------------------

    /**
     * BIND's CVE-2026-1519 and Unbound's CVE-2026-42923 were the same missing bound reached down two different
     * paths, an unsigned-delegation referral and a negative DS lookup. One budget, threaded through every entry
     * point, is what keeps a bound from being present on four paths and absent on the fifth.
     */
    @Test
    public void testTheRecordBoundBindsOnEveryEntryPoint() {
        DnssecLimits limits = DnssecLimits.newBuilder().maxNsec3RecordsPerProof(1).build();
        DnsName qname = name("a.c.x.w.example.");
        List<DnsRecord> wildcardProof = records(
                nsec3(H_NS2, OPT_OUT, H_WILDCARD_W, A, RRSIG),
                nsec3(H_W, OPT_OUT, H_NS1_NSEC3));
        for (DnssecDenialOfExistence.Result result : Arrays.asList(
                evaluator(limits).proveNameError(qname, nameErrorProof(OPT_OUT)),
                evaluator(limits).proveNoData(qname, DnsRecordType.A, nameErrorProof(OPT_OUT)),
                evaluator(limits).proveNoData(name("c.example."), DnsRecordType.DS, optOutReferralProof(OPT_OUT)),
                evaluator(limits).proveWildcardAnswer(name("a.z.w.example."), name("*.w.example."), wildcardProof),
                evaluator(limits).proveUnsignedDelegation(name("c.example."), optOutReferralProof(OPT_OUT)))) {
            // Never INSECURE: an attacker who can make a validation expensive would otherwise hold a way to
            // switch validation off for any zone.
            assertEquals(DnssecStatus.BOGUS, result.status());
            assertEquals(DnssecFailureReason.LIMIT_EXCEEDED, result.reason());
        }
    }

    /**
     * The hash quota binds on every proof that walks. A wildcard answer is the one that does not walk: RFC 5155,
     * section 8.8 needs a single hash, of the "next closer" name, so only the record bound above can constrain it.
     */
    @Test
    public void testTheHashBoundBindsOnEveryProofThatWalks() {
        DnssecLimits limits = DnssecLimits.newBuilder().maxNsec3HashComputations(1).build();
        DnsName qname = name("a.c.x.w.example.");
        for (DnssecDenialOfExistence.Result result : Arrays.asList(
                evaluator(limits).proveNameError(qname, nameErrorProof(OPT_OUT)),
                evaluator(limits).proveNoData(qname, DnsRecordType.A, nameErrorProof(OPT_OUT)),
                evaluator(limits).proveNoData(name("c.example."), DnsRecordType.DS, optOutReferralProof(OPT_OUT)),
                evaluator(limits).proveUnsignedDelegation(name("c.example."), optOutReferralProof(OPT_OUT)))) {
            assertEquals(DnssecStatus.BOGUS, result.status());
            assertEquals(DnssecFailureReason.LIMIT_EXCEEDED, result.reason());
        }
    }

    /**
     * The closest-encloser search hashes each ancestor once and no more, which is what keeps the cost of a proof
     * linear in the depth of the query name rather than quadratic in it. Asserting the counter states that about
     * the validator; a wall-clock assertion would only state it about this machine.
     */
    @Test
    public void testTheSearchHashesEachAncestorOnce() {
        DnssecBudget budget = new DnssecBudget(DnssecLimits.defaults(), DnssecClock.SYSTEM);
        DnssecDenialOfExistence evaluator = new DnssecDenialOfExistence(EXAMPLE, budget);
        DnssecDenialOfExistence.Result result =
                evaluator.proveNameError(name("a.c.x.w.example."), nameErrorProof(OPT_OUT));
        assertEquals(DnssecStatus.INSECURE, result.status());
        // a.c.x.w.example, c.x.w.example, x.w.example and the wildcard *.x.w.example: four names, four hashes,
        // even though the walk looks at each of them more than once.
        assertEquals(4, budget.nsec3HashComputations());
    }

    /**
     * The same invariant {@code DnssecDenialOfExistenceTest} asserts for NSEC, over the NSEC3 verdicts: the two
     * that resolve to {@link DnssecStatus#INSECURE} are the ones an edit to the shared reason table could most
     * easily turn into a false {@link DnssecStatus#SECURE}.
     */
    @Test
    public void testEveryVerdictAgreesWithTheReasonItCarries() {
        DnssecLimits tight = DnssecLimits.newBuilder().maxNsec3RecordsPerProof(1).build();
        List<DnsRecord> tooManyIterations = records(nsec3(H_EXAMPLE + ".example.",
                DnsNsec3Hasher.HASH_ALGORITHM_SHA1, OPT_OUT, 101, SALT, hash(H_NS1), MX, RRSIG));
        for (DnssecDenialOfExistence.Result result : Arrays.asList(
                evaluator().proveNameError(name("a.c.x.w.example."), nameErrorProof(OPT_OUT)),
                evaluator().proveNameError(name("a.c.x.w.example."), nameErrorProof(NO_FLAGS)),
                evaluator().proveNameError(name("a.c.x.w.example."), tooManyIterations),
                evaluator().proveNoData(name("ns1.example."), DnsRecordType.MX,
                        records(nsec3(H_NS1, OPT_OUT, H_X_Y_W, A, RRSIG))),
                evaluator().proveNoData(name("c.example."), DnsRecordType.DS, optOutReferralProof(OPT_OUT)),
                evaluator().proveNoData(name("c.example."), DnsRecordType.DS, optOutReferralProof(NO_FLAGS)),
                evaluator().proveWildcardAnswer(name("a.z.w.example."), name("*.w.example."),
                        records(nsec3(H_NS2, OPT_OUT, H_WILDCARD_W, A, RRSIG))),
                evaluator().proveUnsignedDelegation(name("c.example."), optOutReferralProof(OPT_OUT)),
                evaluator().proveUnsignedDelegation(name("a.example."),
                        records(nsec3(H_A, OPT_OUT, H_X_W, NS, RRSIG))),
                evaluator(tight).proveNameError(name("a.c.x.w.example."), nameErrorProof(OPT_OUT)))) {
            assertEquals(result.reason().impliedStatus(), result.status(), result.toString());
            assertEquals(result.status() == DnssecStatus.SECURE, result.isProven(), result.toString());
        }
    }

    /**
     * The hickory-dns GHSA-3v94-mw7p-v465 shape, on the NSEC3 side: an apex that is not an ancestor of the query
     * name. The search that walks up towards it would never arrive.
     */
    @Test
    public void testQueryNameOutsideTheZoneIsRejectedBeforeAnyWork() {
        DnssecBudget budget = new DnssecBudget(DnssecLimits.defaults(), DnssecClock.SYSTEM);
        DnssecDenialOfExistence evaluator = new DnssecDenialOfExistence(name("other.test."), budget);
        DnssecDenialOfExistence.Result result =
                evaluator.proveNameError(name("a.c.x.w.example."), nameErrorProof(OPT_OUT));
        assertEquals(DnssecStatus.BOGUS, result.status());
        assertEquals(DnssecFailureReason.BAILIWICK_VIOLATION, result.reason());
        assertEquals(0, budget.nsec3HashComputations());
    }
}
