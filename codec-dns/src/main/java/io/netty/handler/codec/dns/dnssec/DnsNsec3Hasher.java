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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * The iterated, salted hash of <a href="https://www.rfc-editor.org/rfc/rfc5155.html#section-5">RFC 5155,
 * section 5</a>, which is what turns an owner name into the label an {@code NSEC3} record is published under.
 *
 * <p>The function is
 * <pre>
 * IH(salt, x, 0) = H(x || salt)
 * IH(salt, x, k) = H(IH(salt, x, k-1) || salt), if k &gt; 0
 * </pre>
 * <p>evaluated over the canonical wire form of the name, so the hash of a name costs
 * {@code iterations + 1} digest operations: the Iterations field counts the <em>extra</em> hashes, not the total.
 * The canonical form is the one of <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-6.2">RFC 4034,
 * section 6.2</a>: fully qualified, uncompressed, and with {@code A} to {@code Z} replaced by {@code a} to
 * {@code z}. A wildcard name keeps its literal {@code *} label, which falls out of doing nothing special with
 * it.
 *
 * <p>A closest-encloser search walks from the query name up towards the zone apex, and every step of every proof
 * hashes another ancestor. The ancestors repeat, both between the searches a single response provokes and between
 * a search and the wildcard names derived from its result. Each instance therefore memoises what it has computed,
 * keyed on the name and the parameters, and spends a {@link DnssecBudget#spendNsec3HashComputation()} only when it
 * has to do the work. Without that, the same ancestor is rehashed once per candidate and the quadratic
 * closest-encloser search of <a href="https://www.cve.org/CVERecord?id=CVE-2023-50868">CVE-2023-50868</a> costs
 * the attacker proportionally less for the same load on the validator.
 *
 * <p>The budget is what bounds the cache: nothing is ever evicted, and nothing needs to be, because the number of
 * distinct entries can never exceed {@link DnssecLimits#maxNsec3HashComputations()}.
 *
 * <p>One instance belongs to one validation, on one thread, exactly like the {@link DnssecBudget} it is created
 * with. It is not thread-safe and must not be shared: the cache would under-count the budget and
 * {@link MessageDigest} is not safe to use from two threads at once.
 */
public final class DnsNsec3Hasher {

    /**
     * Hash Algorithm 1, SHA-1, the only algorithm RFC 5155 defines and the only one this class implements. See the
     * <a href="https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml">DNSSEC NSEC3
     * Parameters</a> registry, in which every other value is unassigned.
     */
    public static final int HASH_ALGORITHM_SHA1 = 1;

    private static final String SHA1 = "SHA-1";

    /**
     * The digest length of {@link #HASH_ALGORITHM_SHA1}, in octets.
     */
    private static final int SHA1_LENGTH = 20;

    private final DnssecBudget budget;
    private final Map<CacheKey, byte[]> cache = new HashMap<CacheKey, byte[]>();

    private MessageDigest digest;

    /**
     * Creates a hasher that charges its work to {@code budget}.
     */
    public DnsNsec3Hasher(DnssecBudget budget) {
        this.budget = ObjectUtil.checkNotNull(budget, "budget");
    }

    /**
     * Returns {@code true} if {@code hashAlgorithm} is an {@code NSEC3} Hash Algorithm this class can evaluate.
     *
     * <p>Callers must test this before reaching for {@link #hash(DnsName, int, int, byte[])}, because
     * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#section-8.1">RFC 5155, section 8.1</a> requires an
     * {@code NSEC3} record with an unknown hash type to be <em>ignored</em> rather than to fail the response: a
     * zone in the middle of a hash algorithm rollover legitimately publishes records this validator cannot read
     * alongside records it can. It is only when ignoring them leaves nothing behind that the response is bogus,
     * and that is a judgement for the proof, not for the hash function.
     */
    public static boolean isSupportedAlgorithm(int hashAlgorithm) {
        return hashAlgorithm == HASH_ALGORITHM_SHA1;
    }

    /**
     * Returns the length in octets of the digest {@code hashAlgorithm} produces.
     *
     * @throws IllegalArgumentException if {@link #isSupportedAlgorithm(int)} is {@code false} for
     *                                  {@code hashAlgorithm}
     */
    public static int hashLength(int hashAlgorithm) {
        checkAlgorithm(hashAlgorithm);
        return SHA1_LENGTH;
    }

    /**
     * Returns the base32hex form of {@code hash}, which is how it appears in the leftmost label of an {@code NSEC3}
     * owner name, in upper case.
     *
     * <p>Comparing owner names as text is not what this is for. A proof decodes the label and compares octets,
     * because <a href="https://www.rfc-editor.org/rfc/rfc5155.html#section-3.3">RFC 5155, section 3.3</a> makes the
     * label case-insensitive and a text comparison then has to get that right; the octets have no such
     * problem.
     */
    static String toLabel(byte[] hash) {
        return Base32Hex.encode(ObjectUtil.checkNotNull(hash, "hash"));
    }

    /**
     * Returns {@code IH(salt, name, iterations)} for the canonical wire form of {@code name}.
     *
     * <p>The result is cached, so calling this again with the same arguments costs nothing and spends nothing. The
     * returned array is owned by this hasher and must not be modified.
     *
     * @param name          the owner name to hash, used in its canonical, down-cased wire form
     * @param hashAlgorithm the Hash Algorithm field of the {@code NSEC3} record
     * @param iterations    the Iterations field, the number of <em>additional</em> hashes
     * @param salt          the Salt field, which may be empty; not copied and not modified
     * @throws IllegalArgumentException     if {@code hashAlgorithm} is not supported or {@code iterations} is not a
     *                                      16-bit value
     * @throws DnssecLimitExceededException if the budget has no hash computation left
     * @throws DnssecUnsupportedAlgorithmException if this JVM has no implementation of the digest
     */
    public byte[] hash(DnsName name, int hashAlgorithm, int iterations, byte[] salt) {
        ObjectUtil.checkNotNull(name, "name");
        ObjectUtil.checkNotNull(salt, "salt");
        checkAlgorithm(hashAlgorithm);
        // The Iterations field is 16 bits wide; anything else cannot have come off the wire.
        ObjectUtil.checkInRange(iterations, 0, 65535, "iterations");
        CacheKey key = new CacheKey(name, hashAlgorithm, iterations, salt);
        byte[] cached = cache.get(key);
        if (cached != null) {
            return cached;
        }
        // Spent before the work, not after, so that a computation that throws has still been paid for.
        budget.spendNsec3HashComputation();
        byte[] computed = compute(name.toLowerCase().toWireBytes(), iterations, salt);
        cache.put(key, computed);
        return computed;
    }

    /**
     * Returns how many distinct hashes this instance has computed, which is how many
     * {@link DnssecBudget#spendNsec3HashComputation()} it has spent.
     */
    int computedHashes() {
        return cache.size();
    }

    @Override
    public String toString() {
        return "DnsNsec3Hasher(computedHashes: " + cache.size() + ')';
    }

    private byte[] compute(byte[] canonicalName, int iterations, byte[] salt) {
        MessageDigest md = digest();
        md.update(canonicalName);
        md.update(salt);
        byte[] hash = md.digest();
        for (int i = 0; i < iterations; i++) {
            // digest() resets the MessageDigest and returns a fresh array, so the previous hash stays intact while
            // it is being fed back in.
            md.update(hash);
            md.update(salt);
            hash = md.digest();
        }
        return hash;
    }

    private MessageDigest digest() {
        MessageDigest md = digest;
        if (md == null) {
            try {
                md = MessageDigest.getInstance(SHA1);
            } catch (NoSuchAlgorithmException e) {
                // SHA-1 is required of every JDK, but a provider set that has removed it is not a data error: the
                // records may be perfectly good and this JVM simply cannot read them.
                throw new DnssecUnsupportedAlgorithmException("no " + SHA1 + " MessageDigest available for NSEC3", e);
            }
            digest = md;
        } else {
            // A digest left half-fed by a computation that threw must not leak into the next one.
            md.reset();
        }
        return md;
    }

    private static void checkAlgorithm(int hashAlgorithm) {
        if (!isSupportedAlgorithm(hashAlgorithm)) {
            throw new IllegalArgumentException("hashAlgorithm: " + hashAlgorithm + " (expected: "
                    + HASH_ALGORITHM_SHA1 + ')');
        }
    }

    /**
     * The parameters that decide a hash. The salt is part of the key even though a single proof is required to use
     * one set of parameters throughout, because this class does not get to assume that its caller enforced it.
     */
    private static final class CacheKey {

        private final DnsName name;
        private final int hashAlgorithm;
        private final int iterations;
        private final byte[] salt;
        private final int hash;

        CacheKey(DnsName name, int hashAlgorithm, int iterations, byte[] salt) {
            this.name = name;
            this.hashAlgorithm = hashAlgorithm;
            this.iterations = iterations;
            this.salt = salt;
            hash = ((name.hashCode() * 31 + hashAlgorithm) * 31 + iterations) * 31 + Arrays.hashCode(salt);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof CacheKey)) {
                return false;
            }
            CacheKey other = (CacheKey) obj;
            return hashAlgorithm == other.hashAlgorithm && iterations == other.iterations
                    && name.equals(other.name) && Arrays.equals(salt, other.salt);
        }

        @Override
        public int hashCode() {
            return hash;
        }
    }
}
