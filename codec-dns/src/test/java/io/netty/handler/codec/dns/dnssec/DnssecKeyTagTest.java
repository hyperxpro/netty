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

import java.util.Base64;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class DnssecKeyTagTest {

    // RFC 5702, Section 6.1: example.net. 3600 IN DNSKEY 256 3 8 (...) ;{id = 9033 (zsk), size = 512b}
    private static final String RFC5702_6_1_KEY =
            "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=";

    // RFC 5702, Section 6.2: example.net. 3600 IN DNSKEY 256 3 10 (...) ;{id = 3740 (zsk), size = 1024b}
    private static final String RFC5702_6_2_KEY =
            "AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFDxj13tOnD9u/1kTg7"
                    + "cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL";

    // RFC 6605, Section 6.1: example.net. 3600 IN DNSKEY 257 3 13 (...), matching DS has key tag 55648.
    private static final String RFC6605_6_1_KEY =
            "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==";

    // RFC 6605, Section 6.2: example.net. 3600 IN DNSKEY 257 3 14 (...), matching DS has key tag 10771.
    private static final String RFC6605_6_2_KEY =
            "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8"
                    + "/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40";

    // RFC 8080, Section 6.1: example.com. 3600 IN DNSKEY 257 3 15 (...), matching DS has key tag 3613.
    private static final String RFC8080_6_1_KEY_A = "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=";

    // RFC 8080, Section 6.1, second example, matching DS has key tag 35217.
    private static final String RFC8080_6_1_KEY_B = "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=";

    // RFC 8080, Section 6.2: example.com. 3600 IN DNSKEY 257 3 16 (...), matching DS has key tag 9713.
    private static final String RFC8080_6_2_KEY_A =
            "3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA";

    // RFC 8080, Section 6.2, second example, matching DS has key tag 38353.
    private static final String RFC8080_6_2_KEY_B =
            "kkreGWoccSDmUBGAe7+zsbG6ZAFQp+syPmYUurBRQc3tDjeMCJcVMRDmgcNLp5HlHAMy12VoISsA";

    // RFC 4035, Appendix A: the example. zone signing key, "example. 3600 DNSKEY 256 3 5 (...)". The zone's own
    // RRSIGs name 38519 as their key tag.
    private static final String RFC4035_A_ZSK =
            "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBVrZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61e"
                    + "k8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFovBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZI"
                    + "ySFNsgEYvh0z2542lzMKR4Dh8uZffQ==";

    // RFC 4035, Appendix A: the example. key signing key, "example. 3600 DNSKEY 257 3 5 (...)". The RRSIG over the
    // DNSKEY RRset names 9465 as its key tag.
    private static final String RFC4035_A_KSK =
            "AQOeX7+baTmvpVHb2CcLnL1dMRWbuscRvHXlLnXwDzvqp4tZVKp1sZMepFb8MvxhhW3y/0QZ"
                    + "syCjczGJ1qk8vJe52iOhInKROVLRwxGpMfzPRLMlGybr51bOV/1se0ODacj3DomyB4QB5gKT"
                    + "Yot/K9alk5/j8vfd4jWCWD+E1Sze0Q==";

    private static byte[] key(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    private static byte[] rdata(int flags, int protocol, DnssecAlgorithm algorithm, byte[] publicKey) {
        byte[] rdata = new byte[4 + publicKey.length];
        rdata[0] = (byte) (flags >>> 8);
        rdata[1] = (byte) flags;
        rdata[2] = (byte) protocol;
        rdata[3] = (byte) algorithm.intValue();
        System.arraycopy(publicKey, 0, rdata, 4, publicKey.length);
        return rdata;
    }

    /**
     * Asserts that both overloads agree and that both produce the key tag the RFC states.
     */
    private static void assertKeyTag(int expected, int flags, DnssecAlgorithm algorithm, String base64) {
        byte[] publicKey = key(base64);
        assertEquals(expected, DnssecKeyTag.compute(rdata(flags, 3, algorithm, publicKey)));
        assertEquals(expected, DnssecKeyTag.compute(flags, 3, algorithm, publicKey));
    }

    @Test
    public void testRfc5702KeyTags() {
        assertKeyTag(9033, 256, DnssecAlgorithm.RSASHA256, RFC5702_6_1_KEY);
        assertKeyTag(3740, 256, DnssecAlgorithm.RSASHA512, RFC5702_6_2_KEY);
    }

    @Test
    public void testRfc6605KeyTags() {
        assertKeyTag(55648, 257, DnssecAlgorithm.ECDSAP256SHA256, RFC6605_6_1_KEY);
        assertKeyTag(10771, 257, DnssecAlgorithm.ECDSAP384SHA384, RFC6605_6_2_KEY);
    }

    @Test
    public void testRfc8080KeyTags() {
        assertKeyTag(3613, 257, DnssecAlgorithm.ED25519, RFC8080_6_1_KEY_A);
        assertKeyTag(35217, 257, DnssecAlgorithm.ED25519, RFC8080_6_1_KEY_B);
        assertKeyTag(9713, 257, DnssecAlgorithm.ED448, RFC8080_6_2_KEY_A);
        assertKeyTag(38353, 257, DnssecAlgorithm.ED448, RFC8080_6_2_KEY_B);
    }

    /**
     * RFC 4035, Appendix A is a complete signed zone rather than an isolated key, so the key tags it states are
     * cross-checked by the zone's own RRSIG and DS records. It is also the only vector here for algorithm 5, and the
     * only one whose flags differ between the two keys, which exercises the flags field of the fold.
     */
    @Test
    public void testRfc4035KeyTags() {
        assertKeyTag(38519, 256, DnssecAlgorithm.RSASHA1, RFC4035_A_ZSK);
        assertKeyTag(9465, 257, DnssecAlgorithm.RSASHA1, RFC4035_A_KSK);
    }

    /**
     * Errata 4552: the prose of RFC 4034, Appendix B says the 2-octet groups are summed "ignoring any carry bits",
     * which the reference implementation printed next to it contradicts. This RDATA is chosen so the two readings
     * disagree: the 2-octet groups sum to 261893, whose low 16 bits are 65285, while folding the retained carry back
     * in once gives 65288.
     */
    @Test
    public void testErrata4552CarryIsFoldedBackIn() {
        byte[] rdata = {
                (byte) 0xff, (byte) 0xff,             // flags
                (byte) 0xff,                          // protocol
                (byte) DnssecAlgorithm.RSASHA256.intValue(),
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
        };
        assertEquals(65288, DnssecKeyTag.compute(rdata));
        assertNotEquals(65285, DnssecKeyTag.compute(rdata));
    }

    /**
     * Errata 4552 also notes the calculation "is often the same as reduction modulo 65535, but not always". This
     * RDATA sums to exactly 65535, where the fold yields 65535 but a modulo-65535 reduction would yield 0.
     */
    @Test
    public void testKeyTagIsNotReductionModulo65535() {
        byte[] rdata = {
                0x00, 0x00,                           // flags
                0x00,                                 // protocol
                (byte) DnssecAlgorithm.RSASHA256.intValue(),
                (byte) 0xff, (byte) 0xf7
        };
        assertEquals(65535, DnssecKeyTag.compute(rdata));
    }

    @Test
    public void testKeyTagOfAllZeroRdataIsZero() {
        assertEquals(0, DnssecKeyTag.compute(new byte[4]));
    }

    /**
     * The algorithm field sits at RDATA octet 3, an odd offset, so RFC 4034 Appendix B adds it unshifted. A DNSKEY
     * that is all zeroes apart from its algorithm therefore has a key tag equal to the algorithm number itself,
     * which pins down both the field offset and the parity rule.
     */
    @Test
    public void testAlgorithmOctetIsAddedUnshifted() {
        assertEquals(DnssecAlgorithm.RSASHA256.intValue(),
                DnssecKeyTag.compute(0, 0, DnssecAlgorithm.RSASHA256, new byte[0]));
        assertEquals(DnssecAlgorithm.RSASHA256.intValue(),
                DnssecKeyTag.compute(new byte[] {0, 0, 0, (byte) DnssecAlgorithm.RSASHA256.intValue()}));
        assertEquals(DnssecAlgorithm.ED25519.intValue(),
                DnssecKeyTag.compute(0, 0, DnssecAlgorithm.ED25519, new byte[0]));
    }

    /**
     * The protocol field sits at RDATA octet 2, an even offset, so it is shifted left by eight before being added.
     */
    @Test
    public void testProtocolOctetIsShifted() {
        assertEquals((3 << 8) + DnssecAlgorithm.RSASHA256.intValue(),
                DnssecKeyTag.compute(0, 3, DnssecAlgorithm.RSASHA256, new byte[0]));
    }

    @Test
    public void testAlgorithm1IsRejected() {
        byte[] rdata = rdata(256, 3, DnssecAlgorithm.RSAMD5, new byte[] {1, 2, 3, 4});
        assertThrows(DnssecUnsupportedAlgorithmException.class, () -> DnssecKeyTag.compute(rdata));
        assertThrows(DnssecUnsupportedAlgorithmException.class,
                () -> DnssecKeyTag.compute(256, 3, DnssecAlgorithm.RSAMD5, new byte[] {1, 2, 3, 4}));
    }

    @Test
    public void testTruncatedRdataIsRejected() {
        for (int length = 0; length < 4; length++) {
            byte[] rdata = new byte[length];
            assertThrows(DnssecMalformedDataException.class, () -> DnssecKeyTag.compute(rdata));
        }
    }

    @Test
    public void testOutOfRangeHeaderFieldsAreRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> DnssecKeyTag.compute(0x10000, 3, DnssecAlgorithm.RSASHA256, new byte[0]));
        assertThrows(IllegalArgumentException.class,
                () -> DnssecKeyTag.compute(-1, 3, DnssecAlgorithm.RSASHA256, new byte[0]));
        assertThrows(IllegalArgumentException.class,
                () -> DnssecKeyTag.compute(256, 256, DnssecAlgorithm.RSASHA256, new byte[0]));
    }

    @Test
    public void testNullArgumentsAreRejected() {
        assertThrows(NullPointerException.class, () -> DnssecKeyTag.compute(null));
        assertThrows(NullPointerException.class, () -> DnssecKeyTag.compute(256, 3, null, new byte[0]));
        assertThrows(NullPointerException.class,
                () -> DnssecKeyTag.compute(256, 3, DnssecAlgorithm.RSASHA256, null));
    }

    /**
     * Cross-checks both overloads against a transliteration of the C reference implementation of RFC 4034,
     * Appendix B over pseudo-random RDATA, including lengths that leave the trailing group half-filled.
     */
    @Test
    public void testMatchesReferenceImplementation() {
        Random random = new Random(20260830L);
        for (int length = 0; length <= 200; length++) {
            byte[] publicKey = new byte[length];
            random.nextBytes(publicKey);
            int flags = random.nextInt(0x10000);
            int protocol = random.nextInt(0x100);
            byte[] rdata = rdata(flags, protocol, DnssecAlgorithm.RSASHA256, publicKey);

            int expected = referenceKeyTag(rdata);
            assertEquals(expected, DnssecKeyTag.compute(rdata), "rdata length " + rdata.length);
            assertEquals(expected, DnssecKeyTag.compute(flags, protocol, DnssecAlgorithm.RSASHA256, publicKey),
                    "rdata length " + rdata.length);
        }
    }

    /**
     * The reference implementation from RFC 4034, Appendix B, with the {@code unsigned long} accumulator widened to
     * a {@code long} as the RFC allows ("assumed to be 32 bits or larger").
     */
    private static int referenceKeyTag(byte[] key) {
        long ac = 0;
        for (int i = 0; i < key.length; i++) {
            ac += (i & 1) != 0 ? key[i] & 0xff : (long) (key[i] & 0xff) << 8;
        }
        ac += (ac >> 16) & 0xFFFF;
        return (int) (ac & 0xFFFF);
    }
}
