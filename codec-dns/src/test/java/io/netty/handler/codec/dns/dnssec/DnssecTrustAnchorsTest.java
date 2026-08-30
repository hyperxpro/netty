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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnssecTrustAnchorsTest {

    private static final String KSK_2017_DIGEST =
            "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";
    private static final String KSK_2024_DIGEST =
            "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16";

    private static byte[] digest(int fill) {
        byte[] digest = new byte[32];
        Arrays.fill(digest, (byte) fill);
        return digest;
    }

    private static DnssecTrustAnchor anchor(String owner, int keyTag, int fill) {
        return new DnssecTrustAnchor(DnsName.fromString(owner), keyTag, DnssecAlgorithm.RSASHA256,
                DnssecDigestType.SHA256, digest(fill));
    }

    private static DnssecTrustAnchor findByKeyTag(DnssecTrustAnchors anchors, int keyTag) {
        for (DnssecTrustAnchor anchor : anchors.anchorsFor(DnsName.ROOT)) {
            if (anchor.keyTag() == keyTag) {
                return anchor;
            }
        }
        return null;
    }

    /**
     * This is the test that fails loudly if the bundled list ever goes stale: both live IANA root anchors have to be
     * present, and each has to be inside its validity window right now. An anchor that has been withdrawn, or a list
     * that has lost one of the two, shows up here rather than as a resolution outage in production.
     */
    @Test
    public void testIanaAnchorsArePresentAndValidNow() {
        DnssecTrustAnchors anchors = DnssecTrustAnchors.iana();
        assertFalse(anchors.isEmpty());
        assertEquals(2, anchors.size());
        assertEquals(1, anchors.names().size());
        assertTrue(anchors.names().contains(DnsName.ROOT));

        long now = System.currentTimeMillis();
        DnssecTrustAnchor ksk2017 = findByKeyTag(anchors, 20326);
        DnssecTrustAnchor ksk2024 = findByKeyTag(anchors, 38696);
        assertNotNull(ksk2017, "KSK-2017 (key tag 20326) is missing: " + anchors);
        assertNotNull(ksk2024, "KSK-2024 (key tag 38696) is missing: " + anchors);
        assertTrue(ksk2017.isValidAt(now), "KSK-2017 is not valid at " + now + ": " + ksk2017);
        assertTrue(ksk2024.isValidAt(now), "KSK-2024 is not valid at " + now + ": " + ksk2024);
    }

    /**
     * The values as published at data.iana.org/root-anchors/root-anchors.xml. Netty is not a trust anchor
     * distribution channel, so these are a convenience to cross-check against, not an authority.
     */
    @Test
    public void testIanaAnchorContents() {
        DnssecTrustAnchor ksk2017 = findByKeyTag(DnssecTrustAnchors.iana(), 20326);
        assertEquals(DnsName.ROOT, ksk2017.owner());
        assertEquals(DnssecAlgorithm.RSASHA256, ksk2017.algorithm());
        assertEquals(8, ksk2017.algorithm().intValue());
        assertEquals(DnssecDigestType.SHA256, ksk2017.digestType());
        assertEquals(2, ksk2017.digestType().intValue());
        assertArrayEquals(StringUtil.decodeHexDump(KSK_2017_DIGEST), ksk2017.digest());
        // 2017-02-02T00:00:00Z, with no withdrawal date.
        assertEquals(1485993600000L, ksk2017.validFrom());
        assertEquals(Long.MAX_VALUE, ksk2017.validUntil());

        DnssecTrustAnchor ksk2024 = findByKeyTag(DnssecTrustAnchors.iana(), 38696);
        assertEquals(DnsName.ROOT, ksk2024.owner());
        assertEquals(DnssecAlgorithm.RSASHA256, ksk2024.algorithm());
        assertEquals(DnssecDigestType.SHA256, ksk2024.digestType());
        assertArrayEquals(StringUtil.decodeHexDump(KSK_2024_DIGEST), ksk2024.digest());
        // 2024-07-18T00:00:00Z, with no withdrawal date.
        assertEquals(1721260800000L, ksk2024.validFrom());
        assertEquals(Long.MAX_VALUE, ksk2024.validUntil());
    }

    /**
     * From 2026-10-11 the root zone is signed exclusively by KSK-2024, so a list without it fails every validation
     * from that date. The assertion is stated against that instant rather than "now" so it keeps meaning something
     * before the date arrives.
     */
    @Test
    public void testIanaCarriesTheKeyTheRootRollsTo() {
        // 2026-10-11T00:00:00Z.
        final long exclusiveKsk2024Millis = 1791676800000L;
        DnssecTrustAnchor ksk2024 = findByKeyTag(DnssecTrustAnchors.iana(), 38696);
        assertNotNull(ksk2024);
        assertTrue(ksk2024.isValidAt(exclusiveKsk2024Millis), ksk2024.toString());
        assertTrue(ksk2024.isValidAt(exclusiveKsk2024Millis + 10L * 365L * 24L * 3600L * 1000L), ksk2024.toString());
    }

    /**
     * KSK-2010 was withdrawn on 2019-01-11. An anchor that can no longer validate anything only survives by being
     * copied out of lists like this one.
     */
    @Test
    public void testIanaOmitsTheRetiredKsk2010() {
        assertNull(findByKeyTag(DnssecTrustAnchors.iana(), 19036));
    }

    @Test
    public void testIanaIsShared() {
        assertSame(DnssecTrustAnchors.iana(), DnssecTrustAnchors.iana());
    }

    @Test
    public void testEmpty() {
        DnssecTrustAnchors anchors = DnssecTrustAnchors.newBuilder().build();
        assertTrue(anchors.isEmpty());
        assertEquals(0, anchors.size());
        assertTrue(anchors.names().isEmpty());
        assertNull(anchors.deepestAnchorName(DnsName.fromString("example.com")));
        assertTrue(anchors.anchorsFor(DnsName.fromString("example.com")).isEmpty());
    }

    /**
     * An anchor installed for a zone overrides the one at the root for that subtree, which is how an island of
     * security or a private zone is configured. The shallower anchors are not merged in: the operator said the
     * chain of trust for that subtree starts here.
     */
    @Test
    public void testDeepestAnchorWins() {
        DnssecTrustAnchors anchors = DnssecTrustAnchors.newBuilder()
                .addAnchor(anchor(".", 1, 0x11))
                .addAnchor(anchor("example.com", 2, 0x22))
                .addAnchor(anchor("internal.example.com", 3, 0x33))
                .build();
        assertEquals(3, anchors.size());

        assertEquals(DnsName.fromString("internal.example.com"),
                anchors.deepestAnchorName(DnsName.fromString("a.b.internal.example.com")));
        assertEquals(1, anchors.anchorsFor(DnsName.fromString("a.b.internal.example.com")).size());
        assertEquals(3, anchors.anchorsFor(DnsName.fromString("a.b.internal.example.com")).get(0).keyTag());

        assertEquals(DnsName.fromString("example.com"),
                anchors.deepestAnchorName(DnsName.fromString("www.example.com")));
        assertEquals(2, anchors.anchorsFor(DnsName.fromString("www.example.com")).get(0).keyTag());

        assertEquals(DnsName.fromString("example.com"),
                anchors.deepestAnchorName(DnsName.fromString("example.com")));

        assertEquals(DnsName.ROOT, anchors.deepestAnchorName(DnsName.fromString("example.org")));
        assertEquals(1, anchors.anchorsFor(DnsName.fromString("example.org")).get(0).keyTag());
        assertEquals(DnsName.ROOT, anchors.deepestAnchorName(DnsName.ROOT));
    }

    /**
     * Walking up from a deep name must stop at the root rather than spin, since the parent of the root is the root.
     */
    @Test
    public void testLookupTerminatesAtTheRootWithoutAnAnchor() {
        DnssecTrustAnchors anchors = DnssecTrustAnchors.newBuilder()
                .addAnchor(anchor("example.com", 1, 0x11))
                .build();
        assertNull(anchors.deepestAnchorName(DnsName.ROOT));
        assertNull(anchors.deepestAnchorName(DnsName.fromString("a.b.c.d.e.f.example.org")));
        assertTrue(anchors.anchorsFor(DnsName.fromString("example.org")).isEmpty());
    }

    @Test
    public void testLookupIsCaseInsensitive() {
        DnssecTrustAnchors anchors = DnssecTrustAnchors.newBuilder()
                .addAnchor(anchor("Example.COM", 1, 0x11))
                .build();
        assertEquals(1, anchors.anchorsFor(DnsName.fromString("WWW.example.com")).size());
        assertNotNull(anchors.deepestAnchorName(DnsName.fromString("example.COM")));
    }

    @Test
    public void testAnchorsAreKeptInInsertionOrder() {
        DnssecTrustAnchors anchors = DnssecTrustAnchors.newBuilder()
                .addAnchor(anchor(".", 3, 0x33))
                .addAnchor(anchor(".", 1, 0x11))
                .addAnchor(anchor(".", 2, 0x22))
                .build();
        List<DnssecTrustAnchor> rootAnchors = anchors.anchorsFor(DnsName.ROOT);
        assertEquals(3, rootAnchors.size());
        assertEquals(3, rootAnchors.get(0).keyTag());
        assertEquals(1, rootAnchors.get(1).keyTag());
        assertEquals(2, rootAnchors.get(2).keyTag());
    }

    @Test
    public void testDuplicateAnchorsAreIgnored() {
        DnssecTrustAnchors anchors = DnssecTrustAnchors.newBuilder()
                .addAnchor(anchor(".", 1, 0x11))
                .addAnchor(anchor(".", 1, 0x11))
                .addAnchor(anchor(".", 1, 0x11))
                .build();
        assertEquals(1, anchors.size());
        assertEquals(1, anchors.anchorsFor(DnsName.ROOT).size());
    }

    @Test
    public void testAddAnchors() {
        List<DnssecTrustAnchor> list = new ArrayList<DnssecTrustAnchor>();
        list.add(anchor(".", 1, 0x11));
        list.add(anchor("example.com", 2, 0x22));
        DnssecTrustAnchors anchors = DnssecTrustAnchors.newBuilder().addAnchors(list).build();
        assertEquals(2, anchors.size());
        assertEquals(2, anchors.names().size());
    }

    @Test
    public void testHexDigestOverload() {
        DnssecTrustAnchors anchors = DnssecTrustAnchors.newBuilder()
                .addAnchor(DnsName.ROOT, 20326, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, KSK_2017_DIGEST)
                .addAnchor(DnsName.fromString("example.com"), 1, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256,
                        KSK_2024_DIGEST.toLowerCase(Locale.US), 1L, 2L)
                .build();
        assertArrayEquals(StringUtil.decodeHexDump(KSK_2017_DIGEST), anchors.anchorsFor(DnsName.ROOT).get(0).digest());

        DnssecTrustAnchor lowerCase = anchors.anchorsFor(DnsName.fromString("example.com")).get(0);
        assertArrayEquals(StringUtil.decodeHexDump(KSK_2024_DIGEST), lowerCase.digest());
        assertEquals(1L, lowerCase.validFrom());
        assertEquals(2L, lowerCase.validUntil());
    }

    @Test
    public void testMalformedHexDigestIsRejected() {
        final DnssecTrustAnchors.Builder builder = DnssecTrustAnchors.newBuilder();
        assertThrows(IllegalArgumentException.class, () -> builder.addAnchor(
                DnsName.ROOT, 1, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, KSK_2017_DIGEST + "0"));
        assertThrows(IllegalArgumentException.class, () -> builder.addAnchor(
                DnsName.ROOT, 1, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256,
                "ZZ" + KSK_2017_DIGEST.substring(2)));
        assertThrows(NullPointerException.class, () -> builder.addAnchor(
                DnsName.ROOT, 1, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, (String) null));
        assertTrue(builder.build().isEmpty());
    }

    @Test
    public void testRejectsNullArguments() {
        assertThrows(NullPointerException.class,
                () -> DnssecTrustAnchors.newBuilder().addAnchor((DnssecTrustAnchor) null));
        assertThrows(NullPointerException.class, () -> DnssecTrustAnchors.newBuilder().addAnchors(null));
        assertThrows(NullPointerException.class, () -> DnssecTrustAnchors.iana().anchorsFor(null));
        assertThrows(NullPointerException.class, () -> DnssecTrustAnchors.iana().deepestAnchorName(null));
    }

    @Test
    public void testResultsAreUnmodifiable() {
        DnssecTrustAnchors anchors = DnssecTrustAnchors.iana();
        assertThrows(UnsupportedOperationException.class,
                () -> anchors.anchorsFor(DnsName.ROOT).add(anchor(".", 1, 0x11)));
        assertThrows(UnsupportedOperationException.class, () -> anchors.names().add(DnsName.ROOT));
    }

    /**
     * A built instance must not change when the builder that made it is used again.
     */
    @Test
    public void testBuildTakesASnapshot() {
        DnssecTrustAnchors.Builder builder = DnssecTrustAnchors.newBuilder().addAnchor(anchor(".", 1, 0x11));
        DnssecTrustAnchors first = builder.build();
        builder.addAnchor(anchor(".", 2, 0x22));
        DnssecTrustAnchors second = builder.build();

        assertEquals(1, first.size());
        assertEquals(1, first.anchorsFor(DnsName.ROOT).size());
        assertEquals(2, second.size());
        assertEquals(2, second.anchorsFor(DnsName.ROOT).size());
    }

    @Test
    public void testToString() {
        String text = DnssecTrustAnchors.iana().toString();
        assertTrue(text.startsWith("DnssecTrustAnchors("), text);
        assertTrue(text.contains("size: 2"), text);
    }
}
