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

import io.netty.handler.codec.dns.DnsName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.EXAMPLE;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.EXAMPLE_NET;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.clockAt;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.hex;
import static io.netty.handler.codec.dns.dnssec.DnssecRRsetFixtures.releaseAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnssecDsMatcherTest {

    /** {@code example.net. 3600 IN DS 55648 13 2 (...)} from RFC 6605, section 6.1. */
    private static final String RFC6605_P256_DIGEST =
            "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17";

    /** {@code example.net. 3600 IN DS 10771 14 4 (...)} from RFC 6605, section 6.2. */
    private static final String RFC6605_P384_DIGEST =
            "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0"
                    + "563a9b5f4d288405c3008a946df983d6";

    private static DnssecBudget budget() {
        return new DnssecBudget(DnssecLimits.defaults(), clockAt(1600000000L));
    }

    @Test
    public void testRfc6605P256DsMatches() {
        DnsDnskeyRecord key = DnssecRRsetFixtures.rfc6605P256Key();
        DnsDsRecord ds = DnssecRRsetFixtures.ds(EXAMPLE_NET, 55648, DnssecAlgorithm.ECDSAP256SHA256,
                DnssecDigestType.SHA256, RFC6605_P256_DIGEST);
        DnssecBudget budget = budget();
        try {
            assertEquals(55648, key.keyTag());
            assertArrayEquals(hex(RFC6605_P256_DIGEST),
                    DnssecDsMatcher.digest(DnssecDigestType.SHA256, EXAMPLE_NET, key));
            assertTrue(DnssecDsMatcher.matches(ds, key, budget));
            assertEquals(0, budget.dsMatchFailures());
        } finally {
            releaseAll(key, ds);
        }
    }

    @Test
    public void testRfc6605P384DsMatches() {
        DnsDnskeyRecord key = DnssecRRsetFixtures.rfc6605P384Key();
        DnsDsRecord ds = DnssecRRsetFixtures.ds(EXAMPLE_NET, 10771, DnssecAlgorithm.ECDSAP384SHA384,
                DnssecDigestType.SHA384, RFC6605_P384_DIGEST);
        DnssecBudget budget = budget();
        try {
            assertEquals(10771, key.keyTag());
            assertArrayEquals(hex(RFC6605_P384_DIGEST),
                    DnssecDsMatcher.digest(DnssecDigestType.SHA384, EXAMPLE_NET, key));
            assertTrue(DnssecDsMatcher.matches(ds, key, budget));
        } finally {
            releaseAll(key, ds);
        }
    }

    @Test
    public void testTheOwnerNameIsDowncasedBeforeItIsDigested() {
        // RFC 4034, section 5.1.4 digests the owner name in the canonical form of section 6.2, so the same zone
        // published with a mixed-case owner has to produce the same DS.
        DnsDnskeyRecord key = DnssecRRsetFixtures.rfc6605P256Key();
        try {
            assertArrayEquals(hex(RFC6605_P256_DIGEST), DnssecDsMatcher.digest(DnssecDigestType.SHA256,
                    DnsName.fromString("ExAmPlE.NeT."), key));
        } finally {
            key.release();
        }
    }

    @Test
    public void testADigestThatDoesNotMatchCostsBudget() {
        DnsDnskeyRecord key = DnssecRRsetFixtures.rfc6605P256Key();
        DnsDsRecord ds = DnssecRRsetFixtures.ds(EXAMPLE_NET, 55648, DnssecAlgorithm.ECDSAP256SHA256,
                DnssecDigestType.SHA256, RFC6605_P256_DIGEST.replace("b4c8", "b4c9"));
        DnssecBudget budget = budget();
        try {
            assertFalse(DnssecDsMatcher.matches(ds, key, budget));
            assertEquals(1, budget.dsMatchFailures());
        } finally {
            releaseAll(key, ds);
        }
    }

    @Test
    public void testAWrongKeyTagIsRejectedWithoutSpendingBudget() {
        DnsDnskeyRecord key = DnssecRRsetFixtures.rfc6605P256Key();
        DnsDsRecord ds = DnssecRRsetFixtures.ds(EXAMPLE_NET, 55649, DnssecAlgorithm.ECDSAP256SHA256,
                DnssecDigestType.SHA256, RFC6605_P256_DIGEST);
        DnssecBudget budget = budget();
        try {
            assertFalse(DnssecDsMatcher.matches(ds, key, budget));
            assertEquals(0, budget.dsMatchFailures());
        } finally {
            releaseAll(key, ds);
        }
    }

    @Test
    public void testADsAtAnotherOwnerNeverMatches() {
        DnsDnskeyRecord key = DnssecRRsetFixtures.rfc6605P256Key();
        DnsDsRecord ds = DnssecRRsetFixtures.ds(DnsName.fromString("other.net."), 55648,
                DnssecAlgorithm.ECDSAP256SHA256, DnssecDigestType.SHA256, RFC6605_P256_DIGEST);
        DnssecBudget budget = budget();
        try {
            assertFalse(DnssecDsMatcher.matches(ds, key, budget));
        } finally {
            releaseAll(key, ds);
        }
    }

    @Test
    public void testMaxDsMatchFailuresIsEnforced() {
        DnsDnskeyRecord key = DnssecRRsetFixtures.rfc6605P256Key();
        DnsDsRecord ds = DnssecRRsetFixtures.ds(EXAMPLE_NET, 55648, DnssecAlgorithm.ECDSAP256SHA256,
                DnssecDigestType.SHA256, RFC6605_P256_DIGEST.replace("b4c8", "b4c9"));
        DnssecLimits limits = DnssecLimits.newBuilder().maxDsMatchFailures(1).build();
        DnssecBudget budget = new DnssecBudget(limits, clockAt(1600000000L));
        try {
            assertFalse(DnssecDsMatcher.matches(ds, key, budget));
            DnssecLimitExceededException e = assertThrows(DnssecLimitExceededException.class,
                    () -> DnssecDsMatcher.matches(ds, key, budget));
            assertEquals("maxDsMatchFailures", e.limitName());
            assertEquals(1, e.limit());
            // Running out of budget is Bogus, never a quiet downgrade to Insecure.
            assertSame(DnssecStatus.BOGUS, DnssecFailureReason.LIMIT_EXCEEDED.impliedStatus());
        } finally {
            releaseAll(key, ds);
        }
    }

    // RFC 6840, section 5.2: an unknown algorithm or digest type is disregarded, and a delegation left with none
    // is Insecure rather than Bogus.

    @Test
    public void testUnsupportedDigestTypeIsDisregarded() {
        DnsDsRecord gost = DnssecRRsetFixtures.ds(EXAMPLE_NET, 55648, DnssecAlgorithm.ECDSAP256SHA256,
                DnssecDigestType.GOST_R_34_11_94, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        DnsDsRecord sha256 = DnssecRRsetFixtures.ds(EXAMPLE_NET, 55648, DnssecAlgorithm.ECDSAP256SHA256,
                DnssecDigestType.SHA256, RFC6605_P256_DIGEST);
        try {
            assertFalse(DnssecDigestType.GOST_R_34_11_94.isSupported());
            List<DnsDsRecord> usable = DnssecDsMatcher.usable(Arrays.asList(gost, sha256), DnssecLimits.defaults());
            assertEquals(1, usable.size());
            assertSame(sha256, usable.get(0));
            assertTrue(DnssecDsMatcher.usable(Collections.singletonList(gost), DnssecLimits.defaults()).isEmpty());
        } finally {
            releaseAll(gost, sha256);
        }
    }

    @Test
    public void testUnsupportedDnskeyAlgorithmIsDisregarded() {
        DnsDsRecord ds = DnssecRRsetFixtures.ds(EXAMPLE_NET, 1, DnssecAlgorithm.ECC_GOST, DnssecDigestType.SHA256,
                RFC6605_P256_DIGEST);
        try {
            assertFalse(DnssecAlgorithm.ECC_GOST.isSupported());
            assertTrue(DnssecDsMatcher.usable(Collections.singletonList(ds), DnssecLimits.defaults()).isEmpty());
        } finally {
            ds.release();
        }
    }

    @Test
    public void testSha1DsDigestCanBeRefusedByPolicy() {
        DnsDsRecord ds = DnssecRRsetFixtures.ds(EXAMPLE, 57855, DnssecAlgorithm.RSASHA1, DnssecDigestType.SHA1,
                "b6dcd485719adca18e5f3d48a2331627fdd3636b");
        try {
            assertEquals(1, DnssecDsMatcher.usable(Collections.singletonList(ds), DnssecLimits.defaults()).size());
            DnssecLimits noSha1 = DnssecLimits.newBuilder().allowSha1DsDigest(false).build();
            assertTrue(DnssecDsMatcher.usable(Collections.singletonList(ds), noSha1).isEmpty());
        } finally {
            ds.release();
        }
    }

    // matchingKeys

    @Test
    public void testMatchingKeysReturnsOnlyTheVouchedForKeys() {
        DnsDnskeyRecord matching = DnssecRRsetFixtures.rfc6605P256Key();
        DnsDnskeyRecord other = DnssecRRsetFixtures.rfc6605P384Key();
        DnsDsRecord ds = DnssecRRsetFixtures.ds(EXAMPLE_NET, 55648, DnssecAlgorithm.ECDSAP256SHA256,
                DnssecDigestType.SHA256, RFC6605_P256_DIGEST);
        try {
            List<DnsDnskeyRecord> keys = new ArrayList<DnsDnskeyRecord>(Arrays.asList(other, matching));
            List<DnsDnskeyRecord> matched =
                    DnssecDsMatcher.matchingKeys(Collections.singletonList(ds), keys, budget());
            assertEquals(1, matched.size());
            assertSame(matching, matched.get(0));
        } finally {
            releaseAll(matching, other, ds);
        }
    }

    @Test
    public void testARevokedOrNonZoneKeyIsNeverVouchedFor() {
        // Both flags change the key tag, so these keys could never be named by the DS anyway; the point is that
        // matchingKeys refuses them before it gets that far, and says so.
        DnsDnskeyRecord revoked = DnssecRRsetFixtures.dnskey(EXAMPLE_NET,
                257 | DnsDnskeyRecord.FLAG_REVOKE, 3, DnssecAlgorithm.ECDSAP256SHA256,
                "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==");
        DnsDnskeyRecord notAZoneKey = DnssecRRsetFixtures.dnskey(EXAMPLE_NET, 1, 3,
                DnssecAlgorithm.ECDSAP256SHA256,
                "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==");
        DnssecBudget budget = budget();
        try {
            DnsDsRecord revokedDs = DnssecRRsetFixtures.ds(EXAMPLE_NET, revoked.keyTag(),
                    DnssecAlgorithm.ECDSAP256SHA256, DnssecDigestType.SHA256,
                    toHex(DnssecDsMatcher.digest(DnssecDigestType.SHA256, EXAMPLE_NET, revoked)));
            try {
                assertTrue(DnssecDsMatcher.matches(revokedDs, revoked, budget));
                assertTrue(DnssecDsMatcher.matchingKeys(Collections.singletonList(revokedDs),
                        Arrays.asList(revoked, notAZoneKey), budget).isEmpty());
            } finally {
                revokedDs.release();
            }
        } finally {
            releaseAll(revoked, notAZoneKey);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b & 0xff) >>> 4, 16)).append(Character.forDigit(b & 0x0f, 16));
        }
        return out.toString();
    }
}
