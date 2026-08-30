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
import io.netty.util.CharsetUtil;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnsNsec3HasherTest {

    /**
     * The salt of the signed example zone in
     * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#appendix-A">RFC 5155, appendix A</a>.
     */
    private static final byte[] SALT = { (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd };

    /**
     * The iteration count of that zone, which is 12 <em>extra</em> hashes, so 13 digest operations per name.
     */
    private static final int ITERATIONS = 12;

    private static final byte[] EMPTY_SALT = {};

    private static DnsNsec3Hasher newHasher() {
        return new DnsNsec3Hasher(newBudget(DnssecLimits.defaults()));
    }

    private static DnssecBudget newBudget(DnssecLimits limits) {
        return new DnssecBudget(limits, DnssecClock.SYSTEM);
    }

    private static String label(DnsNsec3Hasher hasher, String name) {
        byte[] hash = hasher.hash(DnsName.fromString(name), DnsNsec3Hasher.HASH_ALGORITHM_SHA1, ITERATIONS, SALT);
        return DnsNsec3Hasher.toLabel(hash).toLowerCase(Locale.US);
    }

    /**
     * RFC 5155, appendix A publishes the owner names of the {@code NSEC3} records of a fully signed zone, and says
     * of them that "they can also be used as test vectors for the hash algorithm". These are those labels, plus the
     * names appendix B works through, whose hashes the appendix spells out in its comments.
     */
    @Test
    public void testReproducesRfc5155AppendixAOwnerNames() {
        DnsNsec3Hasher hasher = newHasher();
        assertEquals("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", label(hasher, "example."));
        assertEquals("35mthgpgcu1qg68fab165klnsnk3dpvl", label(hasher, "a.example."));
        assertEquals("gjeqe526plbf1g8mklp59enfd789njgi", label(hasher, "ai.example."));
        assertEquals("2t7b4g4vsa5smi47k61mv5bv1a22bojr", label(hasher, "ns1.example."));
        assertEquals("q04jkcevqvmu85r014c7dkba38o0ji5r", label(hasher, "ns2.example."));
        assertEquals("r53bq7cc2uvmubfu5ocmm6pers9tk9en", label(hasher, "*.w.example."));
        assertEquals("k8udemvp1j2f7eg6jebps17vp3n8i58h", label(hasher, "w.example."));
        assertEquals("ji6neoaepv8b5o6k4ev33abha8ht9fgc", label(hasher, "y.w.example."));
        assertEquals("b4um86eghhds6nea196smvmlo4ors995", label(hasher, "x.w.example."));
        assertEquals("2vptu5timamqttgl4luu9kg21e0aor3s", label(hasher, "x.y.w.example."));
        assertEquals("t644ebqk9bibcna874givr6joj62mlhv", label(hasher, "xx.example."));
        // The hash of an NSEC3 owner name, which appendix B.5 needs because RFC 5155, section 7.2.8 puts NSEC3
        // owner names in the chain like any other name.
        assertEquals("kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
                label(hasher, "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example."));
    }

    /**
     * The hashes appendix B names in its comments for the query names it denies, which are the ones a proof has to
     * compute for itself.
     */
    @Test
    public void testReproducesRfc5155AppendixBQueryNameHashes() {
        DnsNsec3Hasher hasher = newHasher();
        // B.1, the "next closer" name and the wildcard at the closest encloser of a.c.x.w.example.
        assertEquals("0va5bpr2ou0vk0lbqeeljri88laipsfh", label(hasher, "c.x.w.example."));
        assertEquals("92pqneegtaue7pjatc3l3qnk738c6v5m", label(hasher, "*.x.w.example."));
        // B.3, the delegation covered by an opt-out record.
        assertEquals("4g6p9u5gvfshp30pqecj98b3maqbn1ck", label(hasher, "c.example."));
        // B.4 and B.5, the "next closer" name of a.z.w.example.
        assertEquals("qlu7gtfaeh0ek0c05ksfhdpbcgglbe03", label(hasher, "z.w.example."));
    }

    /**
     * RFC 5155, section 5: {@code IH(salt, x, 0) = H(x || salt)}. An implementation that read the Iterations field
     * as the total number of hashes rather than the number of extra ones is off by one for every name, which is
     * silent: it simply never matches anything.
     */
    @Test
    public void testIterationsCountAdditionalHashes() throws Exception {
        DnsNsec3Hasher hasher = newHasher();
        DnsName name = DnsName.fromString("example.");
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(name.toWireBytes());
        sha1.update(SALT);
        byte[] once = sha1.digest();
        assertArrayEquals(once, hasher.hash(name, DnsNsec3Hasher.HASH_ALGORITHM_SHA1, 0, SALT));
        sha1.update(once);
        sha1.update(SALT);
        assertArrayEquals(sha1.digest(), hasher.hash(name, DnsNsec3Hasher.HASH_ALGORITHM_SHA1, 1, SALT));
    }

    /**
     * RFC 5155, section 5 hashes the canonical form of RFC 4034, section 6.2, so the case a name arrives in cannot
     * change its hash. A resolver that randomises the case of its query names, per the 0x20 defence, sees exactly
     * this.
     */
    @Test
    public void testCanonicalFormIsDownCased() {
        DnsNsec3Hasher hasher = newHasher();
        assertEquals("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", label(hasher, "ExAmPlE."));
        assertEquals("b4um86eghhds6nea196smvmlo4ors995", label(hasher, "X.W.EXAMPLE."));
    }

    /**
     * RFC 5155, section 5, item 3: a wildcard name keeps its literal asterisk label and is not expanded.
     */
    @Test
    public void testWildcardLabelIsHashedLiterally() {
        DnsNsec3Hasher hasher = newHasher();
        assertEquals("r53bq7cc2uvmubfu5ocmm6pers9tk9en", label(hasher, "*.w.example."));
        assertNotEquals(label(hasher, "w.example."), label(hasher, "*.w.example."));
    }

    @Test
    public void testSaltChangesTheHash() {
        DnsNsec3Hasher hasher = newHasher();
        DnsName name = DnsName.fromString("example.");
        byte[] salted = hasher.hash(name, DnsNsec3Hasher.HASH_ALGORITHM_SHA1, ITERATIONS, SALT);
        byte[] unsalted = hasher.hash(name, DnsNsec3Hasher.HASH_ALGORITHM_SHA1, ITERATIONS, EMPTY_SALT);
        assertEquals(20, salted.length);
        assertEquals(20, unsalted.length);
        assertNotEquals(DnsNsec3Hasher.toLabel(salted), DnsNsec3Hasher.toLabel(unsalted));
    }

    /**
     * The memoisation the closest-encloser search depends on: hashing the same name again is free, and the budget
     * is charged once. Asserting the counter rather than the elapsed time is the only way to state this about the
     * validator rather than about the machine it ran on.
     */
    @Test
    public void testMemoisesAndChargesOncePerName() {
        DnssecBudget budget = newBudget(DnssecLimits.defaults());
        DnsNsec3Hasher hasher = new DnsNsec3Hasher(budget);
        DnsName name = DnsName.fromString("x.w.example.");
        byte[] first = hasher.hash(name, DnsNsec3Hasher.HASH_ALGORITHM_SHA1, ITERATIONS, SALT);
        assertEquals(1, budget.nsec3HashComputations());
        assertSame(first, hasher.hash(name, DnsNsec3Hasher.HASH_ALGORITHM_SHA1, ITERATIONS, SALT));
        // Case-insensitive, because the canonical form the hash is taken over is.
        assertSame(first, hasher.hash(DnsName.fromString("X.W.Example."),
                DnsNsec3Hasher.HASH_ALGORITHM_SHA1, ITERATIONS, SALT));
        assertEquals(1, budget.nsec3HashComputations());
        assertEquals(1, hasher.computedHashes());
        // Different parameters are a different hash and are paid for separately.
        hasher.hash(name, DnsNsec3Hasher.HASH_ALGORITHM_SHA1, ITERATIONS + 1, SALT);
        hasher.hash(name, DnsNsec3Hasher.HASH_ALGORITHM_SHA1, ITERATIONS, EMPTY_SALT);
        assertEquals(3, budget.nsec3HashComputations());
    }

    /**
     * The counter is a quota, not a statistic: once it is spent the hasher refuses rather than doing the work.
     */
    @Test
    public void testFailsClosedWhenTheBudgetIsExhausted() {
        DnssecBudget budget = newBudget(DnssecLimits.newBuilder().maxNsec3HashComputations(2).build());
        DnsNsec3Hasher hasher = new DnsNsec3Hasher(budget);
        hasher.hash(DnsName.fromString("a.example."), DnsNsec3Hasher.HASH_ALGORITHM_SHA1, 0, SALT);
        hasher.hash(DnsName.fromString("b.example."), DnsNsec3Hasher.HASH_ALGORITHM_SHA1, 0, SALT);
        DnssecLimitExceededException e = assertThrows(DnssecLimitExceededException.class, () ->
                hasher.hash(DnsName.fromString("c.example."), DnsNsec3Hasher.HASH_ALGORITHM_SHA1, 0, SALT));
        assertEquals("maxNsec3HashComputations", e.limitName());
        assertEquals(2, e.limit());
        assertEquals(2, budget.nsec3HashComputations());
        // A name already in the cache still answers, because it costs nothing.
        hasher.hash(DnsName.fromString("a.example."), DnsNsec3Hasher.HASH_ALGORITHM_SHA1, 0, SALT);
    }

    /**
     * RFC 5155, section 8.1 requires an unknown hash type to be ignored rather than to fail, so this has to be
     * askable without provoking an exception.
     */
    @Test
    public void testOnlySha1IsSupported() {
        assertTrue(DnsNsec3Hasher.isSupportedAlgorithm(DnsNsec3Hasher.HASH_ALGORITHM_SHA1));
        assertEquals(20, DnsNsec3Hasher.hashLength(DnsNsec3Hasher.HASH_ALGORITHM_SHA1));
        for (int algorithm : new int[] { 0, 2, 3, 255 }) {
            assertFalse(DnsNsec3Hasher.isSupportedAlgorithm(algorithm), "algorithm " + algorithm);
        }
        DnsNsec3Hasher hasher = newHasher();
        assertThrows(IllegalArgumentException.class,
                () -> hasher.hash(DnsName.fromString("example."), 2, 0, SALT));
        assertThrows(IllegalArgumentException.class, () -> DnsNsec3Hasher.hashLength(0));
    }

    @Test
    public void testRejectsAnIterationCountThatCannotBeOnTheWire() {
        DnsNsec3Hasher hasher = newHasher();
        assertThrows(IllegalArgumentException.class,
                () -> hasher.hash(DnsName.fromString("example."), DnsNsec3Hasher.HASH_ALGORITHM_SHA1, 65536, SALT));
        assertThrows(IllegalArgumentException.class,
                () -> hasher.hash(DnsName.fromString("example."), DnsNsec3Hasher.HASH_ALGORITHM_SHA1, -1, SALT));
    }

    /**
     * The label is the unpadded, case-insensitive base32hex of RFC 5155, section 3.3, so it decodes back to the
     * octets a proof compares.
     */
    @Test
    public void testToLabelRoundTrips() {
        DnsNsec3Hasher hasher = newHasher();
        byte[] hash = hasher.hash(DnsName.fromString("example."), DnsNsec3Hasher.HASH_ALGORITHM_SHA1,
                ITERATIONS, SALT);
        String label = DnsNsec3Hasher.toLabel(hash);
        assertEquals(32, label.length());
        assertArrayEquals(hash, Base32Hex.decode(label.getBytes(CharsetUtil.US_ASCII)));
        assertArrayEquals(hash, Base32Hex.decode(
                label.toLowerCase(Locale.US).getBytes(CharsetUtil.US_ASCII)));
    }
}
