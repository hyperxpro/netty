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

import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnssecFailureReasonTest {

    /**
     * The codes of the IANA Extended DNS Error registry of RFC 8914, so a resolver can copy them straight into an
     * {@code EDE} option. A wrong number here is a wrong number on the wire.
     */
    @Test
    public void testExtendedDnsErrorCodesMatchTheRegistry() {
        assertEquals(1, DnssecFailureReason.UNSUPPORTED_DNSKEY_ALGORITHM.extendedDnsErrorCode());
        assertEquals(2, DnssecFailureReason.UNSUPPORTED_DS_DIGEST_TYPE.extendedDnsErrorCode());
        assertEquals(5, DnssecFailureReason.DNSSEC_INDETERMINATE.extendedDnsErrorCode());
        assertEquals(6, DnssecFailureReason.DNSSEC_BOGUS.extendedDnsErrorCode());
        assertEquals(7, DnssecFailureReason.SIGNATURE_EXPIRED.extendedDnsErrorCode());
        assertEquals(8, DnssecFailureReason.SIGNATURE_NOT_YET_VALID.extendedDnsErrorCode());
        assertEquals(9, DnssecFailureReason.DNSKEY_MISSING.extendedDnsErrorCode());
        assertEquals(10, DnssecFailureReason.RRSIGS_MISSING.extendedDnsErrorCode());
        assertEquals(11, DnssecFailureReason.NO_ZONE_KEY_BIT_SET.extendedDnsErrorCode());
        assertEquals(12, DnssecFailureReason.NSEC_MISSING.extendedDnsErrorCode());
        // Indistinguishable from an unsupported algorithm as far as the other side can tell.
        assertEquals(1, DnssecFailureReason.LOCAL_CRYPTO_UNAVAILABLE.extendedDnsErrorCode());
    }

    /**
     * Every reason either carries a registry code or the negative sentinel, and the two accessors never disagree.
     * A sentinel that could be mistaken for a code would be emitted as INFO-CODE 65535.
     */
    @Test
    public void testSentinelIsNegativeAndConsistent() {
        assertEquals(-1, DnssecFailureReason.NO_EXTENDED_DNS_ERROR);
        for (DnssecFailureReason reason : DnssecFailureReason.values()) {
            int code = reason.extendedDnsErrorCode();
            if (reason.hasExtendedDnsErrorCode()) {
                assertTrue(code >= 0 && code <= 65535, reason + " code: " + code);
            } else {
                assertEquals(DnssecFailureReason.NO_EXTENDED_DNS_ERROR, code, reason.toString());
            }
        }
        assertFalse(DnssecFailureReason.NONE.hasExtendedDnsErrorCode());
        assertFalse(DnssecFailureReason.LIMIT_EXCEEDED.hasExtendedDnsErrorCode());
    }

    @Test
    public void testEveryReasonImpliesAStatus() {
        for (DnssecFailureReason reason : DnssecFailureReason.values()) {
            assertNotNull(reason.impliedStatus(), reason.toString());
        }
    }

    /**
     * Only success is Secure. A failure reason that implied {@link DnssecStatus#SECURE} would hand the answer to
     * the application after the validator had already decided something was wrong with it.
     */
    @Test
    public void testOnlyNoneIsSecure() {
        assertSame(DnssecStatus.SECURE, DnssecFailureReason.NONE.impliedStatus());
        for (DnssecFailureReason reason : DnssecFailureReason.values()) {
            if (reason != DnssecFailureReason.NONE) {
                assertFalse(reason.impliedStatus() == DnssecStatus.SECURE, reason.toString());
            }
        }
    }

    /**
     * RFC 6840, Section 5.2: a delegation whose DS records all use algorithms or digest types the validator cannot
     * evaluate is treated as unsigned. Failing these closed would break every zone that has rolled to an algorithm
     * this build does not implement.
     */
    @Test
    public void testUnsupportedAlgorithmAndDigestAreInsecureNotBogus() {
        assertSame(DnssecStatus.INSECURE, DnssecFailureReason.UNSUPPORTED_DNSKEY_ALGORITHM.impliedStatus());
        assertSame(DnssecStatus.INSECURE, DnssecFailureReason.UNSUPPORTED_DS_DIGEST_TYPE.impliedStatus());
        assertSame(DnssecStatus.INSECURE, DnssecFailureReason.LOCAL_CRYPTO_UNAVAILABLE.impliedStatus());
    }

    /**
     * Whoever supplies the records decides whether a limit is reached, so a limit breach that produced
     * {@link DnssecStatus#INSECURE} would be a downgrade oracle: flood the response and the zone stops being
     * validated.
     */
    @Test
    public void testLimitExceededIsBogusNotInsecure() {
        assertSame(DnssecStatus.BOGUS, DnssecFailureReason.LIMIT_EXCEEDED.impliedStatus());
        // Same reasoning, for a defect an input might be able to reproduce.
        assertSame(DnssecStatus.BOGUS, DnssecFailureReason.INTERNAL_ERROR.impliedStatus());
    }

    /**
     * A failure to obtain data is Indeterminate, never Insecure: failing to fetch a DS RRset is exactly what an
     * on-path attacker arranges, and reading that as "the delegation is unsigned" is the downgrade.
     */
    @Test
    public void testMissingDataIsIndeterminateNotInsecure() {
        assertSame(DnssecStatus.INDETERMINATE, DnssecFailureReason.NO_TRUST_ANCHOR.impliedStatus());
        assertSame(DnssecStatus.INDETERMINATE, DnssecFailureReason.FETCH_FAILED.impliedStatus());
        assertSame(DnssecStatus.INDETERMINATE, DnssecFailureReason.TIMEOUT.impliedStatus());
        assertSame(DnssecStatus.INDETERMINATE, DnssecFailureReason.DNSSEC_INDETERMINATE.impliedStatus());
    }

    /**
     * Pins the exact set of reasons that can downgrade an answer to Insecure. Every one of them rests either on a
     * signed proof of absence or on the RFC 6840, Section 5.2 "unknown algorithm means unsigned" rule; adding a
     * reason to this set is adding a way to strip DNSSEC from a zone, so it has to be a deliberate edit here too.
     */
    @Test
    public void testInsecureIsReachableOnlyFromProofsAndUnknownAlgorithms() {
        Set<DnssecFailureReason> expected = EnumSet.of(
                DnssecFailureReason.UNSUPPORTED_DNSKEY_ALGORITHM,
                DnssecFailureReason.UNSUPPORTED_DS_DIGEST_TYPE,
                DnssecFailureReason.UNSIGNED_DELEGATION,
                DnssecFailureReason.NSEC3_OPT_OUT,
                DnssecFailureReason.NSEC3_ITERATIONS_TOO_HIGH,
                DnssecFailureReason.NSEC3_UNKNOWN_HASH,
                DnssecFailureReason.LOCAL_CRYPTO_UNAVAILABLE);

        Set<DnssecFailureReason> actual = EnumSet.noneOf(DnssecFailureReason.class);
        for (DnssecFailureReason reason : DnssecFailureReason.values()) {
            if (reason.impliedStatus() == DnssecStatus.INSECURE) {
                actual.add(reason);
            }
        }
        assertEquals(expected, actual);
    }

    /**
     * The inconsistency proofs, which are the only route to Bogus.
     */
    @Test
    public void testProofsOfInconsistencyAreBogus() {
        DnssecFailureReason[] bogus = {
                DnssecFailureReason.DNSSEC_BOGUS,
                DnssecFailureReason.SIGNATURE_EXPIRED,
                DnssecFailureReason.SIGNATURE_NOT_YET_VALID,
                DnssecFailureReason.DNSKEY_MISSING,
                DnssecFailureReason.RRSIGS_MISSING,
                DnssecFailureReason.NO_ZONE_KEY_BIT_SET,
                DnssecFailureReason.NSEC_MISSING,
                DnssecFailureReason.SIGNER_NOT_ZONE,
                DnssecFailureReason.RRSIG_LABELS_INVALID,
                DnssecFailureReason.KEY_TAG_NO_MATCH,
                DnssecFailureReason.DNSKEY_REVOKED,
                DnssecFailureReason.DS_MISMATCH,
                DnssecFailureReason.WILDCARD_PROOF_MISSING,
                DnssecFailureReason.CNAME_CHAIN_INVALID,
                DnssecFailureReason.BAILIWICK_VIOLATION,
                DnssecFailureReason.COMPRESSED_RDATA,
                DnssecFailureReason.NAME_NOT_REPRESENTABLE
        };
        for (DnssecFailureReason reason : bogus) {
            assertSame(DnssecStatus.BOGUS, reason.impliedStatus(), reason.toString());
        }
    }
}
