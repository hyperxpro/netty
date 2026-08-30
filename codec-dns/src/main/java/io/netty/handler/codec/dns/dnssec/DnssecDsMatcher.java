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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * Decides whether a {@code DS} record in a parent zone vouches for a {@code DNSKEY} in the child, which is the link
 * every step of a chain of trust is made of.
 *
 * <p><a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-5.1.4">RFC 4034, Section 5.1.4</a> defines the
 * relationship as</p>
 *
 * <pre>
 * digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA )
 * DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key
 * </pre>
 *
 * <p>with the owner name in the canonical form of Section 6.2, so downcased, and the {@code RDATA} exactly as it
 * appears on the wire. Because the owner name is inside the digest, a {@code DS} is bound to one name as well as to
 * one key.</p>
 *
 * <h3>The verdict a caller has to reach</h3>
 *
 * <p>Whether a delegation is secure is not a single boolean, and the three outcomes are easy to conflate. The
 * procedure, from <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.2">RFC 4035, Section 5.2</a> as
 * extended by <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.2">RFC 6840, Section 5.2</a>, is:</p>
 *
 * <pre>
 * List&lt;DnsDsRecord&gt; usable = DnssecDsMatcher.usable(dsRrset, limits);
 * if (usable.isEmpty()) {
 *     // nothing here can be evaluated, so the child is treated as unsigned: INSECURE
 * } else if (DnssecDsMatcher.matchingKeys(usable, dnskeyRrset, budget).isEmpty()) {
 *     // the parent named keys we do understand and the child has none of them: BOGUS
 * } else {
 *     // descend, using the returned keys to verify the child's DNSKEY RRset
 * }
 * </pre>
 *
 * <p>The first branch is the one that has to be got right. RFC 6840, Section 5.2 says a validator "disregards any
 * authenticated DS records that specify unknown or unsupported DNSKEY algorithms" and, from that document onwards,
 * unknown or unsupported <em>digest</em> algorithms too; if none are left "the zone is treated as if it were
 * unsigned". Reporting Bogus there instead would make every zone that rolls to an algorithm this build does not
 * know unreachable rather than merely unvalidated.</p>
 *
 * <p>Digests are compared with {@link PlatformDependent#equalsConstantTime(byte[], int, byte[], int, int)} rather
 * than {@code Arrays.equals}. The comparison is against a value the other side chose, and an early-exit comparison
 * leaks, through timing, how many leading octets of a guess were right — which turns finding a matching digest
 * from a search over the whole output into a search one octet at a time.</p>
 *
 * <p>This class is stateless and thread-safe.</p>
 */
public final class DnssecDsMatcher {

    private DnssecDsMatcher() {
    }

    /**
     * Computes {@code digest_algorithm( DNSKEY owner name | DNSKEY RDATA )} of RFC 4034, Section 5.1.4.
     *
     * <p>The owner name is downcased first, so a zone published with a mixed-case owner produces the same digest as
     * the same zone published in lower case, which is what makes a {@code DS} comparable at all.</p>
     *
     * @param digestType the digest algorithm, from the {@code DS} Digest Type field.
     * @param owner      the {@code DNSKEY} owner name, in wire form.
     * @param key        the key to digest. Its {@code RDATA} is read exactly as it arrived.
     * @return the digest.
     * @throws DnssecUnsupportedAlgorithmException if {@code digestType} is one this build does not implement or the
     *                                             JDK does not offer.
     */
    public static byte[] digest(DnssecDigestType digestType, DnsName owner, DnsDnskeyRecord key) {
        ObjectUtil.checkNotNull(digestType, "digestType");
        ObjectUtil.checkNotNull(owner, "owner");
        ObjectUtil.checkNotNull(key, "key");
        if (!digestType.isSupported()) {
            throw new DnssecUnsupportedAlgorithmException("unsupported DS digest type: " + digestType);
        }
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(digestType.algorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new DnssecUnsupportedAlgorithmException(
                    "no provider offers " + digestType.algorithm() + " for DS digest type " + digestType, e);
        }
        digest.update(owner.toLowerCase().toWireBytes());
        digest.update(key.content().nioBuffer());
        return digest.digest();
    }

    /**
     * Returns {@code true} if {@code ds} vouches for {@code key}.
     *
     * <p>The key tag and algorithm are compared first because they are free, but neither is what makes the match:
     * a key tag is a 16-bit checksum that RFC 4034, Appendix B says explicitly does not identify a key. Only the
     * digest does.</p>
     *
     * <p>The owner names are required to be equal as well. That is not in Section 5.1.4, where the digest already
     * covers the name, but it stops a {@code DS} published at one name from being offered as the parent link of a
     * key at another, without the caller having to remember to check.</p>
     *
     * @param ds     the delegation signer record from the parent zone.
     * @param key    the candidate key from the child zone.
     * @param budget charged one {@link DnssecBudget#spendDsMatchFailure()} for each digest that is computed and
     *               does not match, which is what bounds the work an attacker who supplies many colliding key tags
     *               can force.
     * @return {@code true} if the digest matches.
     * @throws DnssecUnsupportedAlgorithmException if the digest type is not supported. Use
     *                                             {@link #usable(Collection, DnssecLimits)} to filter those out
     *                                             first.
     * @throws DnssecLimitExceededException        if {@link DnssecLimits#maxDsMatchFailures()} is reached.
     */
    public static boolean matches(DnsDsRecord ds, DnsDnskeyRecord key, DnssecBudget budget) {
        ObjectUtil.checkNotNull(ds, "ds");
        ObjectUtil.checkNotNull(key, "key");
        ObjectUtil.checkNotNull(budget, "budget");

        if (ds.algorithm().intValue() != key.algorithm().intValue() || !ds.owner().equals(key.owner())) {
            return false;
        }
        int keyTag;
        try {
            keyTag = key.keyTag();
        } catch (DnssecException ignored) {
            // Only RSAMD5 lands here, and its key tag is not computable, so no DS can name it.
            return false;
        }
        if (ds.keyTag() != keyTag) {
            return false;
        }
        byte[] expected = ds.digest();
        byte[] actual = digest(ds.digestType(), key.owner(), key);
        if (expected.length == actual.length
                && PlatformDependent.equalsConstantTime(expected, 0, actual, 0, actual.length) != 0) {
            return true;
        }
        // Charged only on failure: a match ends the search, a mismatch is what can be repeated.
        budget.spendDsMatchFailure();
        return false;
    }

    /**
     * Returns the {@code DS} records a validator is able to act on, which are those whose {@code DNSKEY} algorithm
     * and whose digest type this build and this JVM both implement.
     *
     * <p>An empty result does not mean the delegation is broken. It means the parent named only algorithms or
     * digests that cannot be evaluated here, and RFC 6840, Section 5.2 requires the child to be treated as
     * unsigned, that is {@link DnssecStatus#INSECURE}.</p>
     *
     * @param dsRecords the parent's {@code DS} RRset.
     * @param limits    consulted for {@link DnssecLimits#allowSha1DsDigest()}, which lets an operator refuse digest
     *                  type 1 as a matter of policy. Refusing it does not make anything safer; it turns working
     *                  delegations Insecure.
     * @return a new list, never {@code null}.
     */
    public static List<DnsDsRecord> usable(Collection<DnsDsRecord> dsRecords, DnssecLimits limits) {
        ObjectUtil.checkNotNull(dsRecords, "dsRecords");
        ObjectUtil.checkNotNull(limits, "limits");
        List<DnsDsRecord> usable = new ArrayList<DnsDsRecord>(dsRecords.size());
        for (Iterator<DnsDsRecord> i = dsRecords.iterator(); i.hasNext();) {
            DnsDsRecord ds = i.next();
            if (ds == null || !ds.algorithm().isSupported() || !ds.digestType().isSupported()) {
                continue;
            }
            if (!limits.allowSha1DsDigest() && ds.digestType().intValue() == DnssecDigestType.SHA1.intValue()) {
                continue;
            }
            usable.add(ds);
        }
        return usable;
    }

    /**
     * Returns the keys at least one of {@code dsRecords} vouches for.
     *
     * <p>Call it with the output of {@link #usable(Collection, DnssecLimits)}, so that a {@code DS} nobody can
     * evaluate is never mistaken for one that failed to match. An empty result from a non-empty input is
     * {@link DnssecStatus#BOGUS}: the parent named keys in a language we speak and the child produced none of
     * them.</p>
     *
     * @param dsRecords the parent's usable {@code DS} records.
     * @param keys      the child's apex {@code DNSKEY} RRset.
     * @param budget    charged one {@link DnssecBudget#spendDsMatchFailure()} per digest computed that did not
     *                  match.
     * @return the vouched-for keys, in the order they appear in {@code keys}, never {@code null}.
     * @throws DnssecLimitExceededException if {@link DnssecLimits#maxDsMatchFailures()} is reached.
     */
    public static List<DnsDnskeyRecord> matchingKeys(Collection<DnsDsRecord> dsRecords,
                                                     Collection<DnsDnskeyRecord> keys, DnssecBudget budget) {
        ObjectUtil.checkNotNull(dsRecords, "dsRecords");
        ObjectUtil.checkNotNull(keys, "keys");
        ObjectUtil.checkNotNull(budget, "budget");

        List<DnsDnskeyRecord> matched = new ArrayList<DnsDnskeyRecord>(2);
        for (Iterator<DnsDnskeyRecord> k = keys.iterator(); k.hasNext();) {
            DnsDnskeyRecord key = k.next();
            if (key == null || !key.isZoneKey() || key.isRevoked()) {
                // RFC 4034, Section 2.1.1 and RFC 5011, Section 2.1: a key that does not sign the zone, or that the
                // zone has withdrawn, is not a secure entry point whatever the parent says about it.
                continue;
            }
            for (Iterator<DnsDsRecord> d = dsRecords.iterator(); d.hasNext();) {
                DnsDsRecord ds = d.next();
                if (ds != null && matches(ds, key, budget)) {
                    matched.add(key);
                    break;
                }
            }
        }
        return matched;
    }
}
