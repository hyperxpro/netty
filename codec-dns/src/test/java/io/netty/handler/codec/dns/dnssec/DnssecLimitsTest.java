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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnssecLimitsTest {

    /**
     * The defaults, restated so that changing one is a visible edit rather than a silent loosening. Each is the
     * figure the corresponding accessor cites.
     */
    @Test
    public void testDefaults() {
        DnssecLimits limits = DnssecLimits.defaults();
        assertEquals(8, limits.maxSignatureVerificationsPerRrset());
        assertEquals(32, limits.maxSignatureVerificationsPerValidation());
        assertEquals(4, limits.maxDsMatchFailures());
        assertEquals(2, limits.maxDnskeysPerKeyTag());
        assertEquals(16, limits.maxDnskeysPerRrset());
        assertEquals(16, limits.maxDsRecordsPerRrset());
        assertEquals(100, limits.maxNsec3Iterations());
        assertEquals(500, limits.maxNsec3IterationsHardFail());
        assertEquals(64, limits.maxNsec3HashComputations());
        assertEquals(32, limits.maxNsec3SaltLength());
        assertEquals(16, limits.maxNsecRecordsPerProof());
        assertEquals(16, limits.maxNsec3RecordsPerProof());
        assertEquals(32, limits.maxDelegationDepth());
        assertEquals(24, limits.maxFetches());
        assertEquals(16, limits.maxCnameChainLength());
        assertEquals(256, limits.maxRecordsPerSection());
        assertEquals(1024, limits.minimumRsaKeySizeBits());
        assertEquals(5000L, limits.validationTimeoutMillis());
        assertEquals(0L, limits.clockSkewSeconds());
    }

    /**
     * Zero clock skew is a decision, not an oversight: any grace period is a window in which an expired signature is
     * still accepted, and a silent default would hide a broken clock.
     */
    @Test
    public void testClockSkewDefaultsToZero() {
        assertEquals(0L, DnssecLimits.defaults().clockSkewSeconds());
    }

    /**
     * RFC 9904 keeps algorithms 5 and 7 and DS digest type 1 as MUST implement for validation. Refusing them turns
     * working zones Insecure rather than making anything safer, so they are on by default.
     */
    @Test
    public void testSha1IsAllowedByDefault() {
        assertTrue(DnssecLimits.defaults().allowSha1Signatures());
        assertTrue(DnssecLimits.defaults().allowSha1DsDigest());
    }

    @Test
    public void testDefaultsIsShared() {
        assertSame(DnssecLimits.defaults(), DnssecLimits.defaults());
        assertEquals(DnssecLimits.defaults().maxFetches(), DnssecLimits.newBuilder().build().maxFetches());
    }

    @Test
    public void testBuilderSetsEveryKnob() {
        DnssecLimits limits = DnssecLimits.newBuilder()
                .maxSignatureVerificationsPerRrset(3)
                .maxSignatureVerificationsPerValidation(7)
                .maxDsMatchFailures(5)
                .maxDnskeysPerKeyTag(1)
                .maxDnskeysPerRrset(9)
                .maxDsRecordsPerRrset(11)
                .maxNsec3Iterations(13)
                .maxNsec3IterationsHardFail(17)
                .maxNsec3HashComputations(19)
                .maxNsec3SaltLength(23)
                .maxNsecRecordsPerProof(29)
                .maxNsec3RecordsPerProof(31)
                .maxDelegationDepth(37)
                .maxFetches(41)
                .maxCnameChainLength(43)
                .maxRecordsPerSection(47)
                .minimumRsaKeySizeBits(2048)
                .validationTimeoutMillis(53L)
                .clockSkewSeconds(59L)
                .allowSha1Signatures(false)
                .allowSha1DsDigest(false)
                .build();

        assertEquals(3, limits.maxSignatureVerificationsPerRrset());
        assertEquals(7, limits.maxSignatureVerificationsPerValidation());
        assertEquals(5, limits.maxDsMatchFailures());
        assertEquals(1, limits.maxDnskeysPerKeyTag());
        assertEquals(9, limits.maxDnskeysPerRrset());
        assertEquals(11, limits.maxDsRecordsPerRrset());
        assertEquals(13, limits.maxNsec3Iterations());
        assertEquals(17, limits.maxNsec3IterationsHardFail());
        assertEquals(19, limits.maxNsec3HashComputations());
        assertEquals(23, limits.maxNsec3SaltLength());
        assertEquals(29, limits.maxNsecRecordsPerProof());
        assertEquals(31, limits.maxNsec3RecordsPerProof());
        assertEquals(37, limits.maxDelegationDepth());
        assertEquals(41, limits.maxFetches());
        assertEquals(43, limits.maxCnameChainLength());
        assertEquals(47, limits.maxRecordsPerSection());
        assertEquals(2048, limits.minimumRsaKeySizeBits());
        assertEquals(53L, limits.validationTimeoutMillis());
        assertEquals(59L, limits.clockSkewSeconds());
        assertFalse(limits.allowSha1Signatures());
        assertFalse(limits.allowSha1DsDigest());
    }

    @Test
    public void testBuilderCopiesEveryKnob() {
        DnssecLimits original = DnssecLimits.newBuilder()
                .maxSignatureVerificationsPerRrset(3)
                .maxDnskeysPerKeyTag(7)
                .allowSha1Signatures(false)
                .build();
        DnssecLimits copy = DnssecLimits.newBuilder(original).maxFetches(5).build();

        assertEquals(3, copy.maxSignatureVerificationsPerRrset());
        assertEquals(7, copy.maxDnskeysPerKeyTag());
        assertFalse(copy.allowSha1Signatures());
        assertEquals(5, copy.maxFetches());
        // The original is untouched.
        assertEquals(24, original.maxFetches());
        assertThrows(NullPointerException.class, () -> DnssecLimits.newBuilder(null));
    }

    @Test
    public void testNonPositiveCountsAreRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> DnssecLimits.newBuilder().maxSignatureVerificationsPerRrset(0));
        assertThrows(IllegalArgumentException.class,
                () -> DnssecLimits.newBuilder().maxSignatureVerificationsPerValidation(0));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxDsMatchFailures(0));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxDnskeysPerKeyTag(0));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxDnskeysPerRrset(0));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxDsRecordsPerRrset(0));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxNsec3HashComputations(0));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxNsecRecordsPerProof(0));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxNsec3RecordsPerProof(0));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxDelegationDepth(0));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxFetches(0));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxCnameChainLength(0));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxRecordsPerSection(0));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().validationTimeoutMillis(0L));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().clockSkewSeconds(-1L));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxNsec3Iterations(-1));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxNsec3SaltLength(-1));
    }

    /**
     * The upper bounds are the wire widths where there is one, so a limit can never be set to a value the protocol
     * could not produce in the first place.
     */
    @Test
    public void testUpperBoundsFollowTheWireFormat() {
        assertEquals(255, DnssecLimits.newBuilder().maxNsec3SaltLength(255).build().maxNsec3SaltLength());
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxNsec3SaltLength(256));

        assertEquals(65535,
                DnssecLimits.newBuilder().maxNsec3IterationsHardFail(65535).build().maxNsec3IterationsHardFail());
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxNsec3IterationsHardFail(65536));

        assertEquals(2500, DnssecLimits.newBuilder()
                .maxNsec3IterationsHardFail(65535).maxNsec3Iterations(2500).build().maxNsec3Iterations());
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxNsec3Iterations(2501));

        assertEquals(65535, DnssecLimits.newBuilder().maxRecordsPerSection(65535).build().maxRecordsPerSection());
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxRecordsPerSection(65536));

        // A name has at most 127 labels, so a chain cannot be deeper than that plus the anchor.
        assertEquals(128, DnssecLimits.newBuilder().maxDelegationDepth(128).build().maxDelegationDepth());
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().maxDelegationDepth(129));
    }

    @Test
    public void testRsaKeySizeBoundsFollowRfc5702() {
        assertEquals(1024, DnssecLimits.newBuilder().minimumRsaKeySizeBits(1024).build().minimumRsaKeySizeBits());
        assertEquals(512, DnssecLimits.newBuilder().minimumRsaKeySizeBits(512).build().minimumRsaKeySizeBits());
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().minimumRsaKeySizeBits(511));
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().minimumRsaKeySizeBits(16385));
    }

    @Test
    public void testValidationTimeoutIsBounded() {
        assertEquals(1L, DnssecLimits.newBuilder().validationTimeoutMillis(1L).build().validationTimeoutMillis());
        assertEquals(3600000L,
                DnssecLimits.newBuilder().validationTimeoutMillis(3600000L).build().validationTimeoutMillis());
        assertThrows(IllegalArgumentException.class,
                () -> DnssecLimits.newBuilder().validationTimeoutMillis(3600001L));
        assertEquals(86400L, DnssecLimits.newBuilder().clockSkewSeconds(86400L).build().clockSkewSeconds());
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder().clockSkewSeconds(86401L));
    }

    /**
     * A per-message cap below the per-RRset cap would make one of the two unreachable, which is a configuration
     * mistake rather than a policy, so it is refused instead of silently ignored.
     */
    @Test
    public void testPerValidationCapMustNotBeBelowPerRrsetCap() {
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder()
                .maxSignatureVerificationsPerRrset(8)
                .maxSignatureVerificationsPerValidation(7)
                .build());
        assertNotNull(DnssecLimits.newBuilder()
                .maxSignatureVerificationsPerRrset(8)
                .maxSignatureVerificationsPerValidation(8)
                .build());
    }

    /**
     * RFC 9276, Appendix A puts the "insecure" threshold below the "bogus" one; inverting them would make the
     * softer verdict unreachable.
     */
    @Test
    public void testNsec3HardFailMustNotBeBelowTheSoftLimit() {
        assertThrows(IllegalArgumentException.class, () -> DnssecLimits.newBuilder()
                .maxNsec3Iterations(200)
                .maxNsec3IterationsHardFail(100)
                .build());
        assertNotNull(DnssecLimits.newBuilder()
                .maxNsec3Iterations(100)
                .maxNsec3IterationsHardFail(100)
                .build());
        assertTrue(DnssecLimits.defaults().maxNsec3IterationsHardFail()
                > DnssecLimits.defaults().maxNsec3Iterations());
    }

    @Test
    public void testToStringNamesEveryKnob() {
        String text = DnssecLimits.defaults().toString();
        assertTrue(text.startsWith("DnssecLimits("), text);
        assertTrue(text.contains("maxSignatureVerificationsPerRrset: 8"), text);
        assertTrue(text.contains("maxDnskeysPerKeyTag: 2"), text);
        assertTrue(text.contains("allowSha1DsDigest: true"), text);
    }
}
