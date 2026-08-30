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
import io.netty.util.internal.PlatformDependent;

import java.util.Arrays;

/**
 * A configured starting point for a chain of trust, in the {@code DS} form of
 * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-5.1">RFC 4034, Section 5.1</a>: a key tag, an
 * algorithm, a digest type and the digest of a {@code DNSKEY} that is expected to appear at
 * {@link #owner()}.
 *
 * <p>A trust anchor is "a configured DNSKEY RR or DS RR hash of a DNSKEY RR", per
 * <a href="https://www.rfc-editor.org/rfc/rfc4033.html#section-2">RFC 4033, Section 2</a>. The {@code DS} form is
 * used here because it is what IANA publishes for the root, what
 * <a href="https://www.rfc-editor.org/rfc/rfc7958.html">RFC 7958</a> distributes, and because it survives a key roll
 * that changes the key's encoding but not its digest.</p>
 *
 * <p>The optional {@link #validFrom()} and {@link #validUntil()} window carries the publication and withdrawal
 * instants that the IANA trust anchor file records for each key, so that a retired anchor stops being used at the
 * right moment instead of being deleted from a list somebody has to remember to edit.</p>
 *
 * <p>Immutable, and safe to share between validations and threads.</p>
 */
public final class DnssecTrustAnchor {

    /**
     * The greatest digest length accepted for a digest type whose length this package does not know. No registered
     * digest type produces anything close to this, but an anchor for an unrecognised digest type still has to be
     * storable, since it makes the zone {@link DnssecStatus#INSECURE} rather than being an error.
     */
    private static final int MAX_UNKNOWN_DIGEST_LENGTH = 255;

    private final DnsName owner;
    private final int keyTag;
    private final DnssecAlgorithm algorithm;
    private final DnssecDigestType digestType;
    private final byte[] digest;
    private final long validFrom;
    private final long validUntil;

    /**
     * Creates an anchor with no validity window, equivalent to passing {@link Long#MIN_VALUE} and
     * {@link Long#MAX_VALUE}.
     *
     * @param owner      the name the anchor secures, {@link DnsName#ROOT} for the root zone.
     * @param keyTag     the key tag of the {@code DNSKEY}, as computed by {@link DnssecKeyTag}, between {@code 0}
     *                   and {@code 65535}.
     * @param algorithm  the algorithm of the {@code DNSKEY}.
     * @param digestType the digest type used to produce {@code digest}.
     * @param digest     the digest of the {@code DNSKEY}, copied.
     */
    public DnssecTrustAnchor(DnsName owner, int keyTag, DnssecAlgorithm algorithm, DnssecDigestType digestType,
                             byte[] digest) {
        this(owner, keyTag, algorithm, digestType, digest, Long.MIN_VALUE, Long.MAX_VALUE);
    }

    /**
     * Creates an anchor that is only used inside a window.
     *
     * @param owner      the name the anchor secures, {@link DnsName#ROOT} for the root zone.
     * @param keyTag     the key tag of the {@code DNSKEY}, as computed by {@link DnssecKeyTag}, between {@code 0}
     *                   and {@code 65535}.
     * @param algorithm  the algorithm of the {@code DNSKEY}.
     * @param digestType the digest type used to produce {@code digest}.
     * @param digest     the digest of the {@code DNSKEY}, copied. Its length must be exactly
     *                   {@link DnssecDigestType#digestLength()} when that is known.
     * @param validFrom  the first instant at which the anchor is used, in epoch milliseconds, or
     *                   {@link Long#MIN_VALUE} for "always has been".
     * @param validUntil the last instant at which the anchor is used, in epoch milliseconds, or
     *                   {@link Long#MAX_VALUE} for "no end".
     * @throws IllegalArgumentException if {@code keyTag} does not fit in 16 bits, if the digest length does not
     *                                  match the digest type, or if {@code validFrom} is after {@code validUntil}.
     */
    public DnssecTrustAnchor(DnsName owner, int keyTag, DnssecAlgorithm algorithm, DnssecDigestType digestType,
                             byte[] digest, long validFrom, long validUntil) {
        this.owner = ObjectUtil.checkNotNull(owner, "owner");
        this.keyTag = ObjectUtil.checkInRange(keyTag, 0, 65535, "keyTag");
        this.algorithm = ObjectUtil.checkNotNull(algorithm, "algorithm");
        this.digestType = ObjectUtil.checkNotNull(digestType, "digestType");
        ObjectUtil.checkNotNull(digest, "digest");

        int expectedLength = digestType.digestLength();
        if (expectedLength > 0) {
            // The length is fixed by the digest algorithm, so a wrong one is a transcription error, and a
            // transcription error in a trust anchor is a validator that trusts nothing or trusts the wrong thing.
            if (digest.length != expectedLength) {
                throw new IllegalArgumentException("digest length: " + digest.length + " (expected: " + expectedLength
                        + " for " + digestType + ')');
            }
        } else if (digest.length < 1 || digest.length > MAX_UNKNOWN_DIGEST_LENGTH) {
            throw new IllegalArgumentException("digest length: " + digest.length + " (expected: 1-"
                    + MAX_UNKNOWN_DIGEST_LENGTH + " for the unsupported " + digestType + ')');
        }
        if (validFrom > validUntil) {
            throw new IllegalArgumentException("validFrom: " + validFrom + " (expected: <= validUntil ("
                    + validUntil + "))");
        }
        this.digest = digest.clone();
        this.validFrom = validFrom;
        this.validUntil = validUntil;
    }

    /**
     * Returns the name this anchor secures. Validation of any name at or below it starts here.
     */
    public DnsName owner() {
        return owner;
    }

    /**
     * Returns the key tag of the {@code DNSKEY} this anchor names, between {@code 0} and {@code 65535}.
     *
     * <p>A hint, not an identifier: the key tag of
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#appendix-B">RFC 4034, Appendix B</a> is a checksum and
     * several keys may share one. It narrows the set of keys to hash; only {@link #digest()} decides.</p>
     */
    public int keyTag() {
        return keyTag;
    }

    /**
     * Returns the algorithm of the {@code DNSKEY} this anchor names.
     */
    public DnssecAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the digest type that produced {@link #digest()}. An anchor whose digest type is not
     * {@link DnssecDigestType#isSupported() supported} cannot be matched, which makes the zone
     * {@link DnssecStatus#INSECURE} rather than {@link DnssecStatus#BOGUS}, per
     * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.2">RFC 6840, Section 5.2</a>.
     */
    public DnssecDigestType digestType() {
        return digestType;
    }

    /**
     * Returns a copy of the expected digest of the {@code DNSKEY} RDATA.
     *
     * <p>Compare it with {@link PlatformDependent#equalsConstantTime(byte[], int, byte[], int, int)} rather than
     * with {@link Arrays#equals(byte[], byte[])}.</p>
     */
    public byte[] digest() {
        return digest.clone();
    }

    /**
     * Returns the first instant at which this anchor is used, in epoch milliseconds, or {@link Long#MIN_VALUE} if it
     * has no lower bound.
     */
    public long validFrom() {
        return validFrom;
    }

    /**
     * Returns the last instant at which this anchor is used, in epoch milliseconds, or {@link Long#MAX_VALUE} if it
     * has no upper bound.
     */
    public long validUntil() {
        return validUntil;
    }

    /**
     * Returns {@code true} if this anchor is within its validity window at {@code epochMillis}. Both bounds are
     * inclusive.
     *
     * @param epochMillis the instant to test, on the scale of {@link DnssecClock#currentTimeMillis()}.
     */
    public boolean isValidAt(long epochMillis) {
        return epochMillis >= validFrom && epochMillis <= validUntil;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof DnssecTrustAnchor)) {
            return false;
        }
        DnssecTrustAnchor other = (DnssecTrustAnchor) o;
        return keyTag == other.keyTag
                && validFrom == other.validFrom
                && validUntil == other.validUntil
                && algorithm.equals(other.algorithm)
                && digestType.equals(other.digestType)
                && owner.equals(other.owner)
                && digestsEqual(digest, other.digest);
    }

    private static boolean digestsEqual(byte[] left, byte[] right) {
        return left.length == right.length
                && PlatformDependent.equalsConstantTime(left, 0, right, 0, left.length) != 0;
    }

    @Override
    public int hashCode() {
        int hash = owner.hashCode();
        hash = 31 * hash + keyTag;
        hash = 31 * hash + algorithm.hashCode();
        hash = 31 * hash + digestType.hashCode();
        hash = 31 * hash + Arrays.hashCode(digest);
        hash = 31 * hash + (int) (validFrom ^ validFrom >>> 32);
        hash = 31 * hash + (int) (validUntil ^ validUntil >>> 32);
        return hash;
    }

    /**
     * Returns a description naming the owner, key tag, algorithm and digest type.
     *
     * <p>The digest itself is deliberately not included, only its length: an anchor is logged wherever a validator
     * explains itself, and a full digest in a log line is noise that invites someone to compare anchors by eye
     * instead of by {@link #equals(Object)}.</p>
     */
    @Override
    public String toString() {
        return "DnssecTrustAnchor(owner: " + owner + ", keyTag: " + keyTag + ", algorithm: " + algorithm
                + ", digestType: " + digestType + ", digestLength: " + digest.length + ')';
    }
}
