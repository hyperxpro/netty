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
import io.netty.util.internal.StringUtil;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnssecTrustAnchorTest {

    private static byte[] digest(int length, int fill) {
        byte[] digest = new byte[length];
        Arrays.fill(digest, (byte) fill);
        return digest;
    }

    private static DnssecTrustAnchor rootAnchor() {
        return new DnssecTrustAnchor(DnsName.ROOT, 20326, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256,
                digest(32, 0xab));
    }

    @Test
    public void testAccessors() {
        DnssecTrustAnchor anchor = rootAnchor();
        assertEquals(DnsName.ROOT, anchor.owner());
        assertEquals(20326, anchor.keyTag());
        assertEquals(DnssecAlgorithm.RSASHA256, anchor.algorithm());
        assertEquals(DnssecDigestType.SHA256, anchor.digestType());
        assertArrayEquals(digest(32, 0xab), anchor.digest());
        assertEquals(Long.MIN_VALUE, anchor.validFrom());
        assertEquals(Long.MAX_VALUE, anchor.validUntil());
    }

    @Test
    public void testRejectsNullArguments() {
        assertThrows(NullPointerException.class, () -> new DnssecTrustAnchor(
                null, 1, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, digest(32, 1)));
        assertThrows(NullPointerException.class, () -> new DnssecTrustAnchor(
                DnsName.ROOT, 1, null, DnssecDigestType.SHA256, digest(32, 1)));
        assertThrows(NullPointerException.class, () -> new DnssecTrustAnchor(
                DnsName.ROOT, 1, DnssecAlgorithm.RSASHA256, null, digest(32, 1)));
        assertThrows(NullPointerException.class, () -> new DnssecTrustAnchor(
                DnsName.ROOT, 1, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, null));
    }

    @Test
    public void testKeyTagMustFitInSixteenBits() {
        assertEquals(0, new DnssecTrustAnchor(DnsName.ROOT, 0, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256,
                digest(32, 1)).keyTag());
        assertEquals(65535, new DnssecTrustAnchor(DnsName.ROOT, 65535, DnssecAlgorithm.RSASHA256,
                DnssecDigestType.SHA256, digest(32, 1)).keyTag());
        assertThrows(IllegalArgumentException.class, () -> new DnssecTrustAnchor(
                DnsName.ROOT, -1, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, digest(32, 1)));
        assertThrows(IllegalArgumentException.class, () -> new DnssecTrustAnchor(
                DnsName.ROOT, 65536, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, digest(32, 1)));
    }

    /**
     * The digest length is fixed by the digest algorithm, so a wrong one is a transcription error, and a
     * transcription error in a trust anchor is a validator that trusts nothing or trusts the wrong thing.
     */
    @Test
    public void testDigestLengthMustMatchTheDigestType() {
        assertEquals(20, new DnssecTrustAnchor(DnsName.ROOT, 1, DnssecAlgorithm.RSASHA1, DnssecDigestType.SHA1,
                digest(20, 1)).digest().length);
        assertEquals(48, new DnssecTrustAnchor(DnsName.ROOT, 1, DnssecAlgorithm.ECDSAP384SHA384,
                DnssecDigestType.SHA384, digest(48, 1)).digest().length);

        for (int length : new int[] {0, 31, 33, 64}) {
            assertThrows(IllegalArgumentException.class, () -> new DnssecTrustAnchor(
                    DnsName.ROOT, 1, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, digest(length, 1)),
                    "length " + length);
        }
    }

    /**
     * A digest one octet short of the real root anchor, which is what a copy-and-paste error looks like.
     */
    @Test
    public void testTruncatedRootDigestIsRejected() {
        byte[] truncated = StringUtil.decodeHexDump(
                "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC");
        assertEquals(31, truncated.length);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> new DnssecTrustAnchor(
                DnsName.ROOT, 20326, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, truncated));
        assertTrue(e.getMessage().contains("31"), e.getMessage());
    }

    /**
     * An anchor for a digest type this build cannot compute is still storable: it makes the zone Insecure per
     * RFC 6840, Section 5.2, rather than being a configuration error.
     */
    @Test
    public void testUnsupportedDigestTypeAcceptsAnyPlausibleLength() {
        DnssecDigestType unknown = DnssecDigestType.valueOf(200);
        assertFalse(unknown.isSupported());
        assertEquals(0, unknown.digestLength());

        assertEquals(1, new DnssecTrustAnchor(DnsName.ROOT, 1, DnssecAlgorithm.RSASHA256, unknown,
                digest(1, 1)).digest().length);
        assertEquals(255, new DnssecTrustAnchor(DnsName.ROOT, 1, DnssecAlgorithm.RSASHA256, unknown,
                digest(255, 1)).digest().length);
        assertThrows(IllegalArgumentException.class, () -> new DnssecTrustAnchor(
                DnsName.ROOT, 1, DnssecAlgorithm.RSASHA256, unknown, digest(0, 1)));
        assertThrows(IllegalArgumentException.class, () -> new DnssecTrustAnchor(
                DnsName.ROOT, 1, DnssecAlgorithm.RSASHA256, unknown, digest(256, 1)));
    }

    @Test
    public void testDigestIsCopiedInAndOut() {
        byte[] source = digest(32, 0xab);
        DnssecTrustAnchor anchor = new DnssecTrustAnchor(DnsName.ROOT, 20326, DnssecAlgorithm.RSASHA256,
                DnssecDigestType.SHA256, source);

        source[0] = 0;
        assertEquals((byte) 0xab, anchor.digest()[0], "the anchor kept a reference to the caller's array");

        byte[] returned = anchor.digest();
        returned[0] = 0;
        assertEquals((byte) 0xab, anchor.digest()[0], "the anchor handed out its own array");
        assertNotSame(anchor.digest(), anchor.digest());
    }

    @Test
    public void testValidityWindow() {
        DnssecTrustAnchor anchor = new DnssecTrustAnchor(DnsName.ROOT, 20326, DnssecAlgorithm.RSASHA256,
                DnssecDigestType.SHA256, digest(32, 1), 100L, 200L);
        assertEquals(100L, anchor.validFrom());
        assertEquals(200L, anchor.validUntil());

        assertFalse(anchor.isValidAt(99L));
        assertTrue(anchor.isValidAt(100L));
        assertTrue(anchor.isValidAt(150L));
        assertTrue(anchor.isValidAt(200L));
        assertFalse(anchor.isValidAt(201L));
    }

    @Test
    public void testUnboundedWindowIsAlwaysValid() {
        DnssecTrustAnchor anchor = rootAnchor();
        assertTrue(anchor.isValidAt(Long.MIN_VALUE));
        assertTrue(anchor.isValidAt(0L));
        assertTrue(anchor.isValidAt(System.currentTimeMillis()));
        assertTrue(anchor.isValidAt(Long.MAX_VALUE));
    }

    @Test
    public void testInvertedWindowIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> new DnssecTrustAnchor(
                DnsName.ROOT, 1, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, digest(32, 1), 200L, 100L));
        // A window of a single instant is degenerate but not wrong.
        DnssecTrustAnchor instant = new DnssecTrustAnchor(DnsName.ROOT, 1, DnssecAlgorithm.RSASHA256,
                DnssecDigestType.SHA256, digest(32, 1), 100L, 100L);
        assertTrue(instant.isValidAt(100L));
        assertFalse(instant.isValidAt(101L));
    }

    @Test
    public void testEqualsAndHashCode() {
        DnssecTrustAnchor anchor = rootAnchor();
        assertEquals(anchor, anchor);
        assertEquals(anchor, rootAnchor());
        assertEquals(anchor.hashCode(), rootAnchor().hashCode());
        assertNotEquals(anchor, new Object());
        assertNotEquals(anchor, null);

        assertNotEquals(anchor, new DnssecTrustAnchor(DnsName.ROOT, 20327, DnssecAlgorithm.RSASHA256,
                DnssecDigestType.SHA256, digest(32, 0xab)));
        assertNotEquals(anchor, new DnssecTrustAnchor(DnsName.ROOT, 20326, DnssecAlgorithm.RSASHA512,
                DnssecDigestType.SHA256, digest(32, 0xab)));
        assertNotEquals(anchor, new DnssecTrustAnchor(DnsName.ROOT, 20326, DnssecAlgorithm.RSASHA256,
                DnssecDigestType.SHA256, digest(32, 0xac)));
        assertNotEquals(anchor, new DnssecTrustAnchor(DnsName.fromString("example.com"), 20326,
                DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, digest(32, 0xab)));
        assertNotEquals(anchor, new DnssecTrustAnchor(DnsName.ROOT, 20326, DnssecAlgorithm.RSASHA256,
                DnssecDigestType.SHA256, digest(32, 0xab), 0L, Long.MAX_VALUE));
    }

    /**
     * Owner names compare the way DNS does, so an anchor is found however the operator wrote its name.
     */
    @Test
    public void testOwnerComparisonIsCaseInsensitive() {
        DnssecTrustAnchor lower = new DnssecTrustAnchor(DnsName.fromString("example.com"), 1,
                DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, digest(32, 1));
        DnssecTrustAnchor upper = new DnssecTrustAnchor(DnsName.fromString("EXAMPLE.COM"), 1,
                DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, digest(32, 1));
        assertEquals(lower, upper);
        assertEquals(lower.hashCode(), upper.hashCode());
    }

    /**
     * A trust anchor is logged wherever a validator explains itself, and a full digest in a log line invites
     * comparing anchors by eye.
     */
    @Test
    public void testToStringDoesNotDumpTheDigest() {
        DnssecTrustAnchor anchor = rootAnchor();
        String text = anchor.toString();
        assertTrue(text.contains("keyTag: 20326"), text);
        assertTrue(text.contains("RSASHA256"), text);
        assertTrue(text.contains("SHA-256"), text);
        assertTrue(text.contains("digestLength: 32"), text);
        assertFalse(text.contains(StringUtil.toHexStringPadded(digest(32, 0xab))), text);
        assertFalse(text.toLowerCase().contains("ababab"), text);
    }
}
