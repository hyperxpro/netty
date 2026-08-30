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
import io.netty.util.internal.ObjectUtil;
import io.netty.util.internal.StringUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The set of {@link DnssecTrustAnchor}s a validator starts from, indexed by the name each secures.
 *
 * <p>Lookup follows the DNS tree: {@link #anchorsFor(DnsName)} returns the anchors configured at the deepest
 * ancestor-or-equal name that has any, so an anchor installed for {@code example.com} takes precedence over one for
 * the root when validating {@code www.example.com}, which is how an island of security or a private zone is
 * configured alongside the public root.</p>
 *
 * <p>Immutable, and safe to share between validations and threads.</p>
 */
public final class DnssecTrustAnchors {

    /**
     * KSK-2017, "Klajeyz", published 2017-02-02.
     */
    private static final long KSK_2017_VALID_FROM = 1485993600000L;

    /**
     * KSK-2024, "Kmyv6jo", published 2024-07-18.
     */
    private static final long KSK_2024_VALID_FROM = 1721260800000L;

    private static final DnssecTrustAnchors IANA = newBuilder()
            .addAnchor(DnsName.ROOT, 20326, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256,
                    "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
                    KSK_2017_VALID_FROM, Long.MAX_VALUE)
            .addAnchor(DnsName.ROOT, 38696, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256,
                    "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
                    KSK_2024_VALID_FROM, Long.MAX_VALUE)
            .build();

    private final Map<DnsName, List<DnssecTrustAnchor>> byOwner;
    private final int size;

    private DnssecTrustAnchors(Map<DnsName, List<DnssecTrustAnchor>> byOwner, int size) {
        this.byOwner = byOwner;
        this.size = size;
    }

    /**
     * Returns the two live root zone anchors published by IANA at
     * <a href="https://data.iana.org/root-anchors/root-anchors.xml">data.iana.org/root-anchors/root-anchors.xml</a>:
     * KSK-2017 with key tag 20326 and KSK-2024 with key tag 38696, both SHA-256 digests of an RSASHA256 key for the
     * root.
     *
     * <p><strong>Verify these values against IANA before relying on them.</strong> Netty is a networking library,
     * not a trust anchor distribution channel: it has no revocation path, no signed update mechanism of the kind
     * <a href="https://www.rfc-editor.org/rfc/rfc7958.html">RFC 7958</a> defines for the IANA file, and its release
     * cadence has nothing to do with the root key's. The list here is a convenience for getting started and a
     * cross-check against a locally provisioned file, and treating it as authoritative puts the root of your chain
     * of trust on a library upgrade schedule.</p>
     *
     * <p><strong>The root key is being rolled, and this list has a date on it.</strong> The root zone has been
     * signed by both keys during the overlap, but <strong>from 2026-10-11 it is signed exclusively by KSK-2024, key
     * tag 38696</strong>. A deployment pinned to KSK-2017 alone fails <em>every</em> validation from that date, and
     * the failure is {@link DnssecStatus#BOGUS}, so it is a total resolution outage rather than a quiet degradation.
     * Both keys are present here for exactly that reason.</p>
     *
     * <p>An operator who cannot ship a Netty upgrade on the root's schedule should not be using this method. Supply
     * your own anchors from a file you control, refreshed from IANA or maintained by
     * <a href="https://www.rfc-editor.org/rfc/rfc5011.html">RFC 5011</a> automated updates, and use
     * {@link #newBuilder()}.</p>
     *
     * <p>The retired KSK-2010, key tag 19036, is deliberately absent: it was withdrawn on 2019-01-11 and an anchor
     * that can no longer validate anything is only a way to keep a dead key alive in configurations that copy this
     * list.</p>
     */
    public static DnssecTrustAnchors iana() {
        return IANA;
    }

    /**
     * Returns a new, empty {@link Builder}.
     */
    public static Builder newBuilder() {
        return new Builder();
    }

    /**
     * Returns {@code true} if there are no anchors at all, in which case every name is
     * {@link DnssecFailureReason#NO_TRUST_ANCHOR} and validation cannot start.
     */
    public boolean isEmpty() {
        return size == 0;
    }

    /**
     * Returns the total number of anchors, counting every name.
     */
    public int size() {
        return size;
    }

    /**
     * Returns the names that have at least one anchor, in the order they were first added. Unmodifiable.
     */
    public Set<DnsName> names() {
        return byOwner.keySet();
    }

    /**
     * Returns the deepest ancestor-or-equal name of {@code name} that has at least one anchor, or {@code null} if
     * none does.
     *
     * <p>{@code null} rather than an empty result on purpose: "which zone is this name's trust anchor at" and
     * "there is no trust anchor for this name" are different answers, and the second one is
     * {@link DnssecStatus#INDETERMINATE}.</p>
     *
     * @param name the name being validated.
     */
    public DnsName deepestAnchorName(DnsName name) {
        ObjectUtil.checkNotNull(name, "name");
        DnsName current = name;
        for (;;) {
            if (byOwner.containsKey(current)) {
                return current;
            }
            if (current.isRoot()) {
                return null;
            }
            current = current.parent();
        }
    }

    /**
     * Returns the anchors at {@link #deepestAnchorName(DnsName)}, or an empty list if no ancestor-or-equal name has
     * any. Unmodifiable, and in the order the anchors were added.
     *
     * <p>Only the deepest name's anchors are returned; anchors at a shallower name are not merged in. An anchor
     * configured for a name is a statement that the chain of trust for that subtree starts there, and quietly
     * falling back to the root would let a validator get a <em>Secure</em> answer through a chain the operator
     * deliberately overrode.</p>
     *
     * <p>The result is <em>not</em> filtered by {@link DnssecTrustAnchor#isValidAt(long)}. Anchors have publication
     * and withdrawal dates, so a caller must apply its own validation clock before using one; leaving that here
     * would mean either taking a clock the caller has not supplied or silently making the answer depend on the
     * system time.</p>
     *
     * @param name the name being validated.
     */
    public List<DnssecTrustAnchor> anchorsFor(DnsName name) {
        DnsName anchorName = deepestAnchorName(name);
        if (anchorName == null) {
            return Collections.emptyList();
        }
        return byOwner.get(anchorName);
    }

    @Override
    public String toString() {
        return "DnssecTrustAnchors(size: " + size + ", names: " + byOwner.keySet() + ')';
    }

    /**
     * Collects {@link DnssecTrustAnchor}s into a {@link DnssecTrustAnchors}. Adding an anchor that
     * {@link DnssecTrustAnchor#equals(Object) equals} one already added is a no-op rather than an error, so merging
     * two overlapping sources does not duplicate work at validation time.
     *
     * <p>Not thread-safe; build the instance on one thread and share the result, which is immutable.</p>
     */
    public static final class Builder {

        private final Map<DnsName, List<DnssecTrustAnchor>> byOwner =
                new LinkedHashMap<DnsName, List<DnssecTrustAnchor>>();
        private int size;

        Builder() {
        }

        /**
         * Adds an anchor.
         *
         * @param anchor the anchor to add.
         */
        public Builder addAnchor(DnssecTrustAnchor anchor) {
            ObjectUtil.checkNotNull(anchor, "anchor");
            List<DnssecTrustAnchor> anchors = byOwner.get(anchor.owner());
            if (anchors == null) {
                anchors = new ArrayList<DnssecTrustAnchor>(2);
                byOwner.put(anchor.owner(), anchors);
            }
            if (!anchors.contains(anchor)) {
                anchors.add(anchor);
                size++;
            }
            return this;
        }

        /**
         * Adds every anchor of {@code anchors}.
         *
         * @param anchors the anchors to add.
         */
        public Builder addAnchors(Iterable<DnssecTrustAnchor> anchors) {
            ObjectUtil.checkNotNull(anchors, "anchors");
            for (DnssecTrustAnchor anchor : anchors) {
                addAnchor(anchor);
            }
            return this;
        }

        /**
         * Adds an anchor with no validity window. See
         * {@link DnssecTrustAnchor#DnssecTrustAnchor(DnsName, int, DnssecAlgorithm, DnssecDigestType, byte[])}.
         */
        public Builder addAnchor(DnsName owner, int keyTag, DnssecAlgorithm algorithm, DnssecDigestType digestType,
                                 byte[] digest) {
            return addAnchor(new DnssecTrustAnchor(owner, keyTag, algorithm, digestType, digest));
        }

        /**
         * Adds an anchor with a validity window. See
         * {@link DnssecTrustAnchor#DnssecTrustAnchor(DnsName, int, DnssecAlgorithm, DnssecDigestType, byte[], long,
         * long)}.
         */
        public Builder addAnchor(DnsName owner, int keyTag, DnssecAlgorithm algorithm, DnssecDigestType digestType,
                                 byte[] digest, long validFrom, long validUntil) {
            return addAnchor(new DnssecTrustAnchor(owner, keyTag, algorithm, digestType, digest, validFrom,
                    validUntil));
        }

        /**
         * Adds an anchor with no validity window, taking the digest as hexadecimal, which is the form IANA and
         * every {@code DS} presentation format use.
         *
         * @param hexDigest an even number of hexadecimal digits, in either case, with no separators.
         * @throws IllegalArgumentException if {@code hexDigest} is not valid hexadecimal.
         */
        public Builder addAnchor(DnsName owner, int keyTag, DnssecAlgorithm algorithm, DnssecDigestType digestType,
                                 String hexDigest) {
            return addAnchor(owner, keyTag, algorithm, digestType, decodeHexDigest(hexDigest));
        }

        /**
         * Adds an anchor with a validity window, taking the digest as hexadecimal.
         *
         * @param hexDigest an even number of hexadecimal digits, in either case, with no separators.
         * @throws IllegalArgumentException if {@code hexDigest} is not valid hexadecimal.
         */
        public Builder addAnchor(DnsName owner, int keyTag, DnssecAlgorithm algorithm, DnssecDigestType digestType,
                                 String hexDigest, long validFrom, long validUntil) {
            return addAnchor(owner, keyTag, algorithm, digestType, decodeHexDigest(hexDigest), validFrom, validUntil);
        }

        private static byte[] decodeHexDigest(String hexDigest) {
            ObjectUtil.checkNotNull(hexDigest, "hexDigest");
            if ((hexDigest.length() & 1) != 0) {
                throw new IllegalArgumentException("hexDigest: " + hexDigest.length()
                        + " digits (expected: an even number)");
            }
            return StringUtil.decodeHexDump(hexDigest);
        }

        /**
         * Builds the {@link DnssecTrustAnchors}.
         */
        public DnssecTrustAnchors build() {
            Map<DnsName, List<DnssecTrustAnchor>> copy =
                    new LinkedHashMap<DnsName, List<DnssecTrustAnchor>>(byOwner.size());
            for (Map.Entry<DnsName, List<DnssecTrustAnchor>> entry : byOwner.entrySet()) {
                copy.put(entry.getKey(),
                        Collections.unmodifiableList(new ArrayList<DnssecTrustAnchor>(entry.getValue())));
            }
            return new DnssecTrustAnchors(Collections.unmodifiableMap(copy), size);
        }
    }
}
