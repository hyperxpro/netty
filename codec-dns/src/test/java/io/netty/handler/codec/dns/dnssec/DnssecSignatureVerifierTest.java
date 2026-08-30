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
import io.netty.handler.codec.dns.DefaultDnsResponse;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.handler.codec.dns.DnsResponse;
import io.netty.handler.codec.dns.DnsSection;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.EXAMPLE;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.A_Z_W_EXAMPLE;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.RFC4035_EXPIRATION;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.RFC4035_INCEPTION;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.RFC4035_VALID_AT;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.RFC4035_ZSK_KEY_TAG;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.clockAt;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.hex;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.releaseAll;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.wireName;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnssecSignatureVerifierTest {

    private static DnssecSignatureVerifier verifierAt(long seconds) {
        return new DnssecSignatureVerifier(clockAt(seconds), DnssecLimits.defaults());
    }

    private static DnsRRset nsecRRset(String nextDomainName, DnsRrsigRecord rrsig) {
        return new DnsRRset(EXAMPLE, DnsRecordType.NSEC, DnsRecord.CLASS_IN,
                Collections.singletonList(DnssecRRsetFixtures.apexNsec(nextDomainName)),
                Collections.singletonList(rrsig));
    }

    private static void release(DnsRRset rrset) {
        releaseAll(rrset.records().toArray());
        releaseAll(rrset.signatures().toArray());
    }

    // The RFC 4035, appendix A end-to-end fixture.

    @Test
    public void testRfc4035ApexNsecVerifies() {
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        DnsRRset rrset = nsecRRset("a.example.", DnssecRRsetFixtures.apexNsecRrsig());
        try {
            // RFC 4034, section 2.1.1 and RFC 6840, section 6.2: the Secure Entry Point bit must not change the
            // outcome, and this key does not have it set. If SEP were ever a criterion this fixture would fail.
            assertFalse(zsk.isSecureEntryPoint());
            assertTrue(zsk.isZoneKey());
            assertEquals(RFC4035_ZSK_KEY_TAG, zsk.keyTag());

            DnssecBudget budget = new DnssecBudget(DnssecLimits.defaults(), clockAt(RFC4035_VALID_AT));
            DnssecVerificationResult result =
                    verifierAt(RFC4035_VALID_AT).verify(rrset, Collections.singletonList(zsk), budget);

            assertSame(DnssecStatus.SECURE, result.status(), result.message());
            assertSame(DnssecFailureReason.NONE, result.reason());
            assertTrue(result.isSecure());
            assertSame(zsk, result.key());
            assertNotNull(result.signature());
            assertEquals(EXAMPLE, result.signedOwner());
            assertFalse(result.isWildcardExpanded());
            assertEquals(1, budget.signatureVerifications());
        } finally {
            release(rrset);
            zsk.release();
        }
    }

    /**
     * The RFC 6840, section 5.1 fixture. The {@code NSEC} Next Domain Name is re-cased on the wire; an
     * implementation that downcases it, as the superseded list in RFC 4034, section 6.2 says to, rebuilds the
     * preimage the zone signed and accepts the tampered record. A correct one does not.
     *
     * <p>The impact is signature malleability rather than a denial-of-existence bypass: name comparison is
     * case-insensitive, so the re-cased record still covers exactly the same range of names. What is lost is the
     * signature's commitment to the octets that were actually published.</p>
     */
    @Test
    public void testRecasedNsecNextDomainNameIsRejected() {
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        DnsRRset published = nsecRRset("a.example.", DnssecRRsetFixtures.apexNsecRrsig());
        DnsRRset tampered = nsecRRset("A.EXAMPLE.", DnssecRRsetFixtures.apexNsecRrsig());
        try {
            List<DnsDnskeyRecord> keys = Collections.singletonList(zsk);
            DnssecSignatureVerifier verifier = verifierAt(RFC4035_VALID_AT);

            assertSame(DnssecStatus.SECURE, verifier.verify(published, keys).status());

            DnssecVerificationResult result = verifier.verify(tampered, keys);
            assertSame(DnssecStatus.BOGUS, result.status());
            assertSame(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
            assertNull(result.key());
        } finally {
            release(published);
            release(tampered);
            zsk.release();
        }
    }

    // RFC 4035, appendix B.6: the wildcard.

    @Test
    public void testWildcardExpandedAnswerVerifiesAgainstTheWildcardOwner() {
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        DnsRRset rrset = new DnsRRset(A_Z_W_EXAMPLE, DnsRecordType.MX, DnsRecord.CLASS_IN,
                Collections.singletonList(DnssecRRsetFixtures.wildcardMx()),
                Collections.singletonList(DnssecRRsetFixtures.wildcardMxRrsig(2)));
        try {
            DnssecVerificationResult result =
                    verifierAt(RFC4035_VALID_AT).verify(rrset, Collections.singletonList(zsk));
            assertSame(DnssecStatus.SECURE, result.status(), result.message());
            assertTrue(result.isWildcardExpanded());
            assertEquals(DnsName.fromString("*.w.example."), result.signedOwner());
            assertNotSame(A_Z_W_EXAMPLE, result.signedOwner());
        } finally {
            release(rrset);
            zsk.release();
        }
    }

    @Test
    public void testTheSameAnswerDoesNotVerifyAgainstItsLiteralOwner() {
        // Same records, but the RRSIG claims four labels, so the preimage is built over a.z.w.example. rather than
        // over *.w.example. and the signature no longer matches.
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        DnsRRset rrset = new DnsRRset(A_Z_W_EXAMPLE, DnsRecordType.MX, DnsRecord.CLASS_IN,
                Collections.singletonList(DnssecRRsetFixtures.wildcardMx()),
                Collections.singletonList(DnssecRRsetFixtures.wildcardMxRrsig(4)));
        try {
            DnssecVerificationResult result =
                    verifierAt(RFC4035_VALID_AT).verify(rrset, Collections.singletonList(zsk));
            assertSame(DnssecStatus.BOGUS, result.status());
            assertSame(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
        } finally {
            release(rrset);
            zsk.release();
        }
    }

    // RFC 4034, section 3.1.5 and RFC 1982: the validity period.

    @Test
    public void testExpiredSignature() {
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        DnsRRset rrset = nsecRRset("a.example.", DnssecRRsetFixtures.apexNsecRrsig());
        try {
            DnssecVerificationResult result =
                    verifierAt(RFC4035_EXPIRATION + 1).verify(rrset, Collections.singletonList(zsk));
            assertSame(DnssecFailureReason.SIGNATURE_EXPIRED, result.reason());
            assertSame(DnssecStatus.BOGUS, result.status());
        } finally {
            release(rrset);
            zsk.release();
        }
    }

    @Test
    public void testNotYetValidSignature() {
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        DnsRRset rrset = nsecRRset("a.example.", DnssecRRsetFixtures.apexNsecRrsig());
        try {
            DnssecVerificationResult result =
                    verifierAt(RFC4035_INCEPTION - 1).verify(rrset, Collections.singletonList(zsk));
            assertSame(DnssecFailureReason.SIGNATURE_NOT_YET_VALID, result.reason());
        } finally {
            release(rrset);
            zsk.release();
        }
    }

    @Test
    public void testValidityPeriodAtTheExactBoundaries() {
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        DnsRRset rrset = nsecRRset("a.example.", DnssecRRsetFixtures.apexNsecRrsig());
        try {
            List<DnsDnskeyRecord> keys = Collections.singletonList(zsk);
            // RFC 4035, section 5.3.1 makes both comparisons inclusive.
            assertSame(DnssecStatus.SECURE, verifierAt(RFC4035_INCEPTION).verify(rrset, keys).status());
            assertSame(DnssecStatus.SECURE, verifierAt(RFC4035_EXPIRATION).verify(rrset, keys).status());
        } finally {
            release(rrset);
            zsk.release();
        }
    }

    /**
     * The RFC 1982 wrap. Both timestamps are chosen so that a 32-bit serial comparison and a comparison of two
     * widened {@code long}s disagree: the signature is inside its window under RFC 1982 and outside it under a
     * plain {@code <}. An implementation that widens reports SIGNATURE_NOT_YET_VALID here.
     */
    @Test
    public void testValidityPeriodUsesRfc1982SerialArithmetic() {
        long inception = 4294967040L;   // 0xFFFFFF00, in 2106
        long expiration = 256L;         // wrapped past 2^32, so shortly after inception
        long now = 4294967312L;         // 0x100000010, whose low 32 bits are 16: between the two
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.rrsig(EXAMPLE, DnsRecordType.NSEC, DnssecAlgorithm.RSASHA1, 1,
                3600, expiration, inception, RFC4035_ZSK_KEY_TAG, wireName("example."), hex("00"));
        DnsRRset rrset = nsecRRset("a.example.", rrsig);
        try {
            DnssecVerificationResult result = verifierAt(now).verify(rrset, Collections.singletonList(zsk));
            // The signature itself is nonsense, so the answer is Bogus either way; what is asserted is that the
            // validity check was passed rather than tripped.
            assertSame(DnssecFailureReason.DNSSEC_BOGUS, result.reason(), result.message());
        } finally {
            release(rrset);
            zsk.release();
        }
    }

    @Test
    public void testClockSkewIsAppliedToNowAndNotToTheRecord() {
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        DnsRRset rrset = nsecRRset("a.example.", DnssecRRsetFixtures.apexNsecRrsig());
        try {
            List<DnsDnskeyRecord> keys = Collections.singletonList(zsk);
            DnssecLimits skewed = DnssecLimits.newBuilder().clockSkewSeconds(60).build();
            assertSame(DnssecFailureReason.SIGNATURE_EXPIRED,
                    new DnssecSignatureVerifier(clockAt(RFC4035_EXPIRATION + 61), skewed)
                            .verify(rrset, keys).reason());
            assertSame(DnssecStatus.SECURE,
                    new DnssecSignatureVerifier(clockAt(RFC4035_EXPIRATION + 60), skewed)
                            .verify(rrset, keys).status());
            assertSame(DnssecStatus.SECURE,
                    new DnssecSignatureVerifier(clockAt(RFC4035_INCEPTION - 60), skewed)
                            .verify(rrset, keys).status());
        } finally {
            release(rrset);
            zsk.release();
        }
    }

    // RFC 4035, section 5.3.1 and CVE-2026-44690: the Labels field.

    @Test
    public void testLabelsAboveTheOwnerLabelCountIsRejected() {
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.rrsig(EXAMPLE, DnsRecordType.NSEC, DnssecAlgorithm.RSASHA1, 2,
                3600, RFC4035_EXPIRATION, RFC4035_INCEPTION, RFC4035_ZSK_KEY_TAG, wireName("example."), hex("00"));
        DnsRRset rrset = nsecRRset("a.example.", rrsig);
        try {
            DnssecVerificationResult result =
                    verifierAt(RFC4035_VALID_AT).verify(rrset, Collections.singletonList(zsk));
            assertSame(DnssecFailureReason.RRSIG_LABELS_INVALID, result.reason());
        } finally {
            release(rrset);
            zsk.release();
        }
    }

    @Test
    public void testLabelsBelowTheSignerLabelCountIsRejected() {
        // CVE-2026-44690: evil.example. signs x.evil.example. with labels = 1, which would mint the signed owner
        // *.example. — a wildcard in a zone it has no authority over.
        DnsName owner = DnsName.fromString("x.evil.example.");
        DnsName signer = DnsName.fromString("evil.example.");
        DnsDnskeyRecord key = DnssecRRsetFixtures.dnskey(signer, 256, 3, DnssecAlgorithm.RSASHA1,
                "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBVrZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61e"
                        + "k8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFovBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZI"
                        + "ySFNsgEYvh0z2542lzMKR4Dh8uZffQ==");
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.rrsig(owner, DnsRecordType.A, DnssecAlgorithm.RSASHA1, 1, 3600,
                RFC4035_EXPIRATION, RFC4035_INCEPTION, key.keyTag(), wireName("evil.example."), hex("00"));
        DnssecRecord a = DnssecRRsetFixtures.rawRecord(owner, DnsRecordType.A, 3600, hex("C0000201"));
        DnsRRset rrset = new DnsRRset(owner, DnsRecordType.A, DnsRecord.CLASS_IN,
                Collections.singletonList(a), Collections.singletonList(rrsig));
        try {
            DnssecVerificationResult result =
                    verifierAt(RFC4035_VALID_AT).verify(rrset, Collections.singletonList(key));
            assertSame(DnssecFailureReason.RRSIG_LABELS_INVALID, result.reason());
            assertSame(DnssecStatus.BOGUS, result.status());
        } finally {
            release(rrset);
            key.release();
        }
    }

    @Test
    public void testSignerOutsideTheOwnersAncestryIsRejected() {
        DnsName signer = DnsName.fromString("other.");
        DnsDnskeyRecord key = DnssecRRsetFixtures.dnskey(signer, 256, 3, DnssecAlgorithm.RSASHA1,
                "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBVrZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61e"
                        + "k8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFovBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZI"
                        + "ySFNsgEYvh0z2542lzMKR4Dh8uZffQ==");
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.rrsig(EXAMPLE, DnsRecordType.NSEC, DnssecAlgorithm.RSASHA1, 1,
                3600, RFC4035_EXPIRATION, RFC4035_INCEPTION, key.keyTag(), wireName("other."), hex("00"));
        DnsRRset rrset = nsecRRset("a.example.", rrsig);
        try {
            DnssecVerificationResult result =
                    verifierAt(RFC4035_VALID_AT).verify(rrset, Collections.singletonList(key));
            assertSame(DnssecFailureReason.SIGNER_NOT_ZONE, result.reason());
        } finally {
            release(rrset);
            key.release();
        }
    }

    // Key selection.

    @Test
    public void testNoRrsigAtAll() {
        DnsNsecRecord nsec = DnssecRRsetFixtures.apexNsec("a.example.");
        DnsRRset rrset = new DnsRRset(EXAMPLE, DnsRecordType.NSEC, DnsRecord.CLASS_IN,
                Collections.singletonList(nsec), Collections.<DnsRrsigRecord>emptyList());
        try {
            DnssecVerificationResult result = verifierAt(RFC4035_VALID_AT)
                    .verify(rrset, Collections.<DnsDnskeyRecord>emptyList());
            assertSame(DnssecFailureReason.RRSIGS_MISSING, result.reason());
        } finally {
            nsec.release();
        }
    }

    @Test
    public void testRrsigWithNoDnskeyOfThatAlgorithmIsDisregarded() {
        // RFC 6840, section 5.12, and the cheapest of the KeyTrap defences: no key material is even looked at.
        DnsRRset rrset = nsecRRset("a.example.", DnssecRRsetFixtures.apexNsecRrsig());
        try {
            DnssecBudget budget = new DnssecBudget(DnssecLimits.defaults(), clockAt(RFC4035_VALID_AT));
            DnssecVerificationResult result = verifierAt(RFC4035_VALID_AT)
                    .verify(rrset, Collections.<DnsDnskeyRecord>emptyList(), budget);
            assertSame(DnssecFailureReason.DNSKEY_MISSING, result.reason());
            assertEquals(0, budget.signatureVerifications());
        } finally {
            release(rrset);
        }
    }

    @Test
    public void testKeyTagMismatch() {
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.rrsig(EXAMPLE, DnsRecordType.NSEC, DnssecAlgorithm.RSASHA1, 1,
                3600, RFC4035_EXPIRATION, RFC4035_INCEPTION, RFC4035_ZSK_KEY_TAG + 1, wireName("example."),
                hex("00"));
        DnsRRset rrset = nsecRRset("a.example.", rrsig);
        try {
            DnssecVerificationResult result =
                    verifierAt(RFC4035_VALID_AT).verify(rrset, Collections.singletonList(zsk));
            assertSame(DnssecFailureReason.KEY_TAG_NO_MATCH, result.reason());
        } finally {
            release(rrset);
            zsk.release();
        }
    }

    @Test
    public void testRevokedKeyIsRejected() {
        assertKeyRejected(256 | DnsDnskeyRecord.FLAG_REVOKE, 3, DnssecFailureReason.DNSKEY_REVOKED);
    }

    @Test
    public void testKeyWithoutTheZoneKeyFlagIsRejected() {
        assertKeyRejected(0, 3, DnssecFailureReason.NO_ZONE_KEY_BIT_SET);
    }

    @Test
    public void testKeyWithTheWrongProtocolIsRejected() {
        assertKeyRejected(256, 4, DnssecFailureReason.DNSSEC_BOGUS);
    }

    private static void assertKeyRejected(int flags, int protocol, DnssecFailureReason expected) {
        DnsDnskeyRecord key = DnssecRRsetFixtures.dnskey(EXAMPLE, flags, protocol, DnssecAlgorithm.RSASHA1,
                "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBVrZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61e"
                        + "k8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFovBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZI"
                        + "ySFNsgEYvh0z2542lzMKR4Dh8uZffQ==");
        // The flags and the protocol are inside the key tag, so the RRSIG has to name the tag of the key it is
        // being offered against or it would be rejected for the wrong reason.
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.rrsig(EXAMPLE, DnsRecordType.NSEC, DnssecAlgorithm.RSASHA1, 1,
                3600, RFC4035_EXPIRATION, RFC4035_INCEPTION, key.keyTag(), wireName("example."), hex("00"));
        DnsRRset rrset = nsecRRset("a.example.", rrsig);
        try {
            DnssecBudget budget = new DnssecBudget(DnssecLimits.defaults(), clockAt(RFC4035_VALID_AT));
            DnssecVerificationResult result =
                    verifierAt(RFC4035_VALID_AT).verify(rrset, Collections.singletonList(key), budget);
            assertSame(expected, result.reason(), result.message());
            assertSame(DnssecStatus.BOGUS, result.status());
            // Rejected before any cryptography, which is the point of doing these checks first.
            assertEquals(0, budget.signatureVerifications());
        } finally {
            release(rrset);
            key.release();
        }
    }

    @Test
    public void testUnsupportedAlgorithmIsInsecureAndNotBogus() {
        // RFC 4035, section 5.2: material the validator cannot evaluate makes the zone unsigned, not broken.
        DnsDnskeyRecord key = DnssecRRsetFixtures.dnskey(EXAMPLE, 256, 3, DnssecAlgorithm.DSA, "AQID");
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.rrsig(EXAMPLE, DnsRecordType.NSEC, DnssecAlgorithm.DSA, 1, 3600,
                RFC4035_EXPIRATION, RFC4035_INCEPTION, key.keyTag(), wireName("example."), hex("00"));
        DnsRRset rrset = nsecRRset("a.example.", rrsig);
        try {
            assertFalse(DnssecAlgorithm.DSA.isSupported());
            DnssecVerificationResult result =
                    verifierAt(RFC4035_VALID_AT).verify(rrset, Collections.singletonList(key));
            assertSame(DnssecFailureReason.UNSUPPORTED_DNSKEY_ALGORITHM, result.reason());
            assertSame(DnssecStatus.INSECURE, result.status());
        } finally {
            release(rrset);
            key.release();
        }
    }

    @Test
    public void testAlgorithmRefusedByPolicyIsInsecure() {
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        DnsRRset rrset = nsecRRset("a.example.", DnssecRRsetFixtures.apexNsecRrsig());
        try {
            DnssecLimits noSha1 = DnssecLimits.newBuilder().allowSha1Signatures(false).build();
            DnssecVerificationResult result = new DnssecSignatureVerifier(clockAt(RFC4035_VALID_AT), noSha1)
                    .verify(rrset, Collections.singletonList(zsk));
            assertSame(DnssecFailureReason.UNSUPPORTED_DNSKEY_ALGORITHM, result.reason());
            assertSame(DnssecStatus.INSECURE, result.status());
        } finally {
            release(rrset);
            zsk.release();
        }
    }

    // RFC 4034, section 3.1.8.1, and the shape of the RRSIG itself.

    @Test
    public void testRrsetWithAForeignRecordIsRejected() {
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        DnsNsecRecord ours = DnssecRRsetFixtures.apexNsec("a.example.");
        DnssecRecord foreign = DnssecRRsetFixtures.rawRecord(DnsName.fromString("other.example."),
                DnsRecordType.NSEC, 3600, hex("00"));
        DnsRRset rrset = new DnsRRset(EXAMPLE, DnsRecordType.NSEC, DnsRecord.CLASS_IN,
                Arrays.asList(ours, foreign), Collections.singletonList(DnssecRRsetFixtures.apexNsecRrsig()));
        try {
            DnssecVerificationResult result =
                    verifierAt(RFC4035_VALID_AT).verify(rrset, Collections.singletonList(zsk));
            assertSame(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
            assertTrue(result.message().contains("other.example."), result.message());
        } finally {
            release(rrset);
            zsk.release();
        }
    }

    @Test
    public void testRrsigCoveringAnotherTypeIsRejected() {
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.rrsig(EXAMPLE, DnsRecordType.SOA, DnssecAlgorithm.RSASHA1, 1,
                3600, RFC4035_EXPIRATION, RFC4035_INCEPTION, RFC4035_ZSK_KEY_TAG, wireName("example."), hex("00"));
        DnsRRset rrset = nsecRRset("a.example.", rrsig);
        try {
            DnssecVerificationResult result =
                    verifierAt(RFC4035_VALID_AT).verify(rrset, Collections.singletonList(zsk));
            assertSame(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
            assertTrue(result.message().contains("covers"), result.message());
        } finally {
            release(rrset);
            zsk.release();
        }
    }

    @Test
    public void testRrsigOfAnotherClassIsRejected() {
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        // The RRset is class CH and so are its records, so the homogeneity check passes and the class comparison
        // of RFC 4035, section 5.3.1 is what rejects the class IN RRSIG.
        DnssecRecord nsec = DnssecRRsetFixtures.rawRecord(EXAMPLE, DnsRecordType.NSEC, 3, 3600,
                DnssecRRsetFixtures.concat(wireName("a.example."), hex("000722010000000380")));
        DnsRrsigRecord rrsig = DnssecRRsetFixtures.apexNsecRrsig();
        DnsRRset rrset = new DnsRRset(EXAMPLE, DnsRecordType.NSEC, 3,
                Collections.singletonList(nsec), Collections.singletonList(rrsig));
        try {
            DnssecVerificationResult result =
                    verifierAt(RFC4035_VALID_AT).verify(rrset, Collections.singletonList(zsk));
            assertSame(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
            assertTrue(result.message().contains("class"), result.message());
        } finally {
            releaseAll(nsec, rrsig);
            zsk.release();
        }
    }

    /**
     * The whole path, from octets on the wire to a verdict: the RFC 4035, appendix B.6 answer written with a
     * compression pointer inside the {@code MX} {@code RDATA} and another in the {@code RRSIG} owner name, decoded
     * by {@link DnssecDnsRecordDecoder}, grouped by {@link DnsRRset#group}, and checked against the appendix A zone
     * signing key. Nothing here is hand-assembled, so it is also the proof that the decompressed {@code RDATA} the
     * decoder produces is what the signature covers.
     */
    @Test
    public void testEndToEndFromTheWireWithCompressedRdata() throws Exception {
        DnsRrsigRecord template = DnssecRRsetFixtures.wildcardMxRrsig(2);
        byte[] rrsigRdata;
        try {
            rrsigRdata = ByteBufUtil.getBytes(template.content());
        } finally {
            template.release();
        }

        ByteBuf message = Unpooled.buffer();
        DnsResponse response = new DefaultDnsResponse(1);
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        try {
            // a.z.w.example. written out in full, so that "example." sits at offset 6 and can be pointed at.
            message.writeBytes(wireName("a.z.w.example."));
            message.writeShort(DnsRecordType.MX.intValue());
            message.writeShort(DnsRecord.CLASS_IN);
            message.writeInt(3600);
            message.writeShort(7);
            message.writeShort(1);
            message.writeByte(2);
            message.writeByte('a');
            message.writeByte('i');
            message.writeShort(0xc006);
            // The RRSIG owner is a pointer back to offset 0.
            message.writeShort(0xc000);
            message.writeShort(DnsRecordType.RRSIG.intValue());
            message.writeShort(DnsRecord.CLASS_IN);
            message.writeInt(3600);
            message.writeShort(rrsigRdata.length);
            message.writeBytes(rrsigRdata);

            response.addRecord(DnsSection.ANSWER,
                    DnssecDnsRecordDecoder.INSTANCE.<DnsRecord>decodeRecord(message));
            response.addRecord(DnsSection.ANSWER,
                    DnssecDnsRecordDecoder.INSTANCE.<DnsRecord>decodeRecord(message));
            assertFalse(message.isReadable());

            List<DnsRRset> rrsets = DnsRRset.group(response, DnsSection.ANSWER, DnssecLimits.defaults());
            assertEquals(1, rrsets.size());
            assertEquals(A_Z_W_EXAMPLE, rrsets.get(0).owner());
            assertEquals(1, rrsets.get(0).signatures().size());

            DnssecVerificationResult result =
                    verifierAt(RFC4035_VALID_AT).verify(rrsets.get(0), Collections.singletonList(zsk));
            assertSame(DnssecStatus.SECURE, result.status(), result.message());
            assertTrue(result.isWildcardExpanded());
            assertEquals(DnsName.fromString("*.w.example."), result.signedOwner());
        } finally {
            response.release();
            message.release();
            zsk.release();
        }
    }

    // Bounded work.

    @Test
    public void testCollidingKeyTagsExhaustTheKeyTagLimit() {
        // Key tags are a 16-bit checksum, so an attacker can mint as many keys with one tag as they like. Every
        // one of them would otherwise be a signature verification the validator is obliged to perform: KeyTrap.
        List<DnsDnskeyRecord> keys = new ArrayList<DnsDnskeyRecord>();
        for (int i = 0; i < 3; i++) {
            keys.add(keyWithTag(RFC4035_ZSK_KEY_TAG, i));
        }
        DnsRRset rrset = nsecRRset("a.example.", DnssecRRsetFixtures.apexNsecRrsig());
        try {
            for (DnsDnskeyRecord key : keys) {
                assertEquals(RFC4035_ZSK_KEY_TAG, key.keyTag());
            }
            DnssecBudget budget = new DnssecBudget(DnssecLimits.defaults(), clockAt(RFC4035_VALID_AT));
            DnssecVerificationResult result = verifierAt(RFC4035_VALID_AT).verify(rrset, keys, budget);
            assertSame(DnssecFailureReason.LIMIT_EXCEEDED, result.reason());
            assertSame(DnssecStatus.BOGUS, result.status());
            assertTrue(result.message().contains("maxDnskeysPerKeyTag"), result.message());
            assertEquals(0, budget.signatureVerifications());
        } finally {
            release(rrset);
            releaseAll(keys.toArray());
        }
    }

    @Test
    public void testPerRrsetVerificationLimitIsEnforced() {
        // Two keys share the tag the RRSIG names, and the limit allows one verification, so the second key can
        // never be reached however many RRSIGs are offered.
        DnsDnskeyRecord first = keyWithTag(RFC4035_ZSK_KEY_TAG, 1);
        DnsDnskeyRecord second = keyWithTag(RFC4035_ZSK_KEY_TAG, 2);
        DnsRRset rrset = nsecRRset("a.example.", DnssecRRsetFixtures.apexNsecRrsig());
        try {
            DnssecLimits limits = DnssecLimits.newBuilder().maxSignatureVerificationsPerRrset(1).build();
            DnssecBudget budget = new DnssecBudget(limits, clockAt(RFC4035_VALID_AT));
            DnssecVerificationResult result = new DnssecSignatureVerifier(clockAt(RFC4035_VALID_AT), limits)
                    .verify(rrset, Arrays.asList(first, second), budget);
            assertSame(DnssecFailureReason.LIMIT_EXCEEDED, result.reason());
            assertTrue(result.message().contains("maxSignatureVerificationsPerRrset"), result.message());
            assertEquals(1, budget.signatureVerifications());
        } finally {
            release(rrset);
            releaseAll(first, second);
        }
    }

    @Test
    public void testExhaustedValidationBudgetIsBogus() {
        DnsDnskeyRecord zsk = DnssecRRsetFixtures.zoneSigningKey();
        DnsRRset rrset = nsecRRset("a.example.", DnssecRRsetFixtures.apexNsecRrsig());
        try {
            DnssecLimits limits = DnssecLimits.newBuilder()
                    .maxSignatureVerificationsPerRrset(1)
                    .maxSignatureVerificationsPerValidation(1)
                    .build();
            DnssecBudget budget = new DnssecBudget(limits, clockAt(RFC4035_VALID_AT));
            budget.spendSignatureVerification();
            DnssecVerificationResult result = new DnssecSignatureVerifier(clockAt(RFC4035_VALID_AT), limits)
                    .verify(rrset, Collections.singletonList(zsk), budget);
            assertSame(DnssecFailureReason.LIMIT_EXCEEDED, result.reason());
            assertSame(DnssecStatus.BOGUS, result.status());
        } finally {
            release(rrset);
            zsk.release();
        }
    }

    private static DnsDnskeyRecord keyWithTag(int tag, int distinguisher) {
        return DnssecRRsetFixtures.keyWithTag(EXAMPLE, tag, distinguisher);
    }
}
