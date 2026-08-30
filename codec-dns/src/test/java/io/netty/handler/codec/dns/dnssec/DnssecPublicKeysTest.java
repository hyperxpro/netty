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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class DnssecPublicKeysTest {

    // RFC 5702, Section 6.1: the DNSKEY public key field of the RSASHA256 example, {id = 9033, size = 512b}.
    private static final byte[] RFC5702_6_1_KEY = decode(
            "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=");

    // RFC 5702, Section 6.1: the "Modulus:" field of the same key, given separately by the RFC.
    private static final byte[] RFC5702_6_1_MODULUS = decode(
            "wVwaxrHF2CK64aYKRUibLiH30KpPuPBjel7E8ZydQW1HYWHfoGmidzC2RnhwCC293hCzw+TFR2nqn8OVSY5t2Q==");

    // RFC 5702, Section 6.2: the DNSKEY public key field of the RSASHA512 example, {id = 3740, size = 1024b}.
    private static final byte[] RFC5702_6_2_KEY = decode(
            "AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFDxj13tOnD9u/1kTg7"
                    + "cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL");

    // RFC 5702, Section 6.2: the "Modulus:" field of the same key.
    private static final byte[] RFC5702_6_2_MODULUS = decode(
            "0eg1M5b563zoq4k5ZEOnWmd2/BvpjzedJVdfIsDcMuuhE5SQ3pfQ7qmdaeMlC6Nf8DKGoUPGPXe06cP27/WRODtxXquS"
                    + "UytkO0kJDk8KX8PtA0+yBWwy7UnZDyCkynO00Uuk8HPVtZeMO1pHtlAGVnc8VjXZlNKdyit99waaE4s=");

    // RFC 6605, Section 6.1: the P-256 example DNSKEY public key field.
    private static final byte[] RFC6605_6_1_KEY = decode(
            "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==");

    // RFC 6605, Section 6.2: the P-384 example DNSKEY public key field.
    private static final byte[] RFC6605_6_2_KEY = decode(
            "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8"
                    + "/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40");

    // RFC 8080, Section 6.1: the Ed25519 example DNSKEY public key field.
    private static final byte[] RFC8080_6_1_KEY = decode("l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=");

    // RFC 8080, Section 6.2: the Ed448 example DNSKEY public key field.
    private static final byte[] RFC8080_6_2_KEY =
            decode("3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA");

    private static byte[] decode(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    // ------------------------------------------------------------------------------------------------------ RSA

    /**
     * RFC 5702, Section 6.1 states the key is 512 bits, which is legal per RFC 5702, Section 2.1 but below the
     * hardening default, so the vector only decodes when the floor is lowered explicitly.
     */
    @Test
    public void testRfc5702Section61RsaSha256Key() {
        RSAPublicKey key = (RSAPublicKey) DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, RFC5702_6_1_KEY, 512);
        assertEquals(new BigInteger(1, RFC5702_6_1_MODULUS), key.getModulus());
        assertEquals(BigInteger.valueOf(65537), key.getPublicExponent());
        assertEquals(512, key.getModulus().bitLength());
    }

    @Test
    public void testRfc5702Section61KeyIsBelowTheDefaultFloor() {
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, RFC5702_6_1_KEY));
    }

    /**
     * RFC 5702, Section 6.2 states the key is 1024 bits, which meets both the RFC 5702, Section 2.2 minimum for
     * RSASHA512 and the hardening default.
     */
    @Test
    public void testRfc5702Section62RsaSha512Key() {
        RSAPublicKey key = (RSAPublicKey) DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA512, RFC5702_6_2_KEY);
        assertEquals(new BigInteger(1, RFC5702_6_2_MODULUS), key.getModulus());
        assertEquals(BigInteger.valueOf(65537), key.getPublicExponent());
        assertEquals(1024, key.getModulus().bitLength());
    }

    /**
     * The RFC 5702, Section 2.2 floor of 1024 bits for RSASHA512 is enforced even when the caller asks for less.
     */
    @Test
    public void testCallerCannotLowerTheRsaSha512FloorBelowTheRfcMinimum() {
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA512, RFC5702_6_1_KEY, 512));
    }

    @Test
    public void testRsaSha1SharesTheRfc3110Encoding() {
        for (DnssecAlgorithm algorithm :
                new DnssecAlgorithm[] {DnssecAlgorithm.RSASHA1, DnssecAlgorithm.RSASHA1_NSEC3_SHA1}) {
            RSAPublicKey key = (RSAPublicKey) DnssecPublicKeys.decode(algorithm, RFC5702_6_2_KEY);
            assertEquals(new BigInteger(1, RFC5702_6_2_MODULUS), key.getModulus());
        }
    }

    /**
     * A 256-octet exponent is the shortest one the 3-octet length form is allowed to describe, so this is the exact
     * boundary of the canonicality rule. The modulus is 2056 bits because SunRsaSign requires the exponent to be
     * smaller than the modulus, and caps the exponent at 64 bits once the modulus exceeds 3072 bits.
     */
    @Test
    public void testRsaThreeOctetExponentLength() {
        byte[] exponent = new byte[256];
        Arrays.fill(exponent, (byte) 0xff);
        exponent[0] = 0x01;
        byte[] modulus = new byte[257];
        Arrays.fill(modulus, (byte) 0xff);
        modulus[0] = (byte) 0x80;

        byte[] publicKey = new byte[3 + exponent.length + modulus.length];
        publicKey[0] = 0;
        publicKey[1] = (byte) (exponent.length >>> 8);
        publicKey[2] = (byte) exponent.length;
        System.arraycopy(exponent, 0, publicKey, 3, exponent.length);
        System.arraycopy(modulus, 0, publicKey, 3 + exponent.length, modulus.length);

        RSAPublicKey key = (RSAPublicKey) DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, publicKey);
        assertEquals(new BigInteger(1, exponent), key.getPublicExponent());
        assertEquals(new BigInteger(1, modulus), key.getModulus());
    }

    /**
     * RFC 3110, Section 2 allows an exponent of up to 4096 bits, but SunRsaSign refuses an exponent longer than 64
     * bits once the modulus exceeds 3072 bits, and refuses any exponent that is not smaller than the modulus.
     *
     * <p>Such a key is <em>legal but unusable here</em>, which is deliberately reported as an unsupported
     * algorithm rather than as malformed data. Malformed means the validator holds proof the zone is wrong and may
     * declare it Bogus; a limitation of the local JVM is no such proof, so the zone degrades to Insecure instead,
     * which is what RFC 4035 Section 5.2 already prescribes for anything the validator cannot process. Every
     * genuine RFC 3110 violation is caught before the KeyFactory is reached and still reports as malformed, which
     * the surrounding tests pin down.</p>
     */
    @Test
    public void testRsaExponentTheProviderRefusesIsReportedAsUnsupported() {
        byte[] exponent = new byte[256];
        Arrays.fill(exponent, (byte) 0xff);
        byte[] modulus = new byte[512];
        Arrays.fill(modulus, (byte) 0xff);

        byte[] publicKey = new byte[3 + exponent.length + modulus.length];
        publicKey[0] = 0;                                       // 3-octet exponent length form
        publicKey[1] = (byte) (exponent.length >>> 8);
        publicKey[2] = (byte) exponent.length;
        System.arraycopy(exponent, 0, publicKey, 3, exponent.length);
        System.arraycopy(modulus, 0, publicKey, 3 + exponent.length, modulus.length);

        DnssecUnsupportedAlgorithmException e = assertThrows(DnssecUnsupportedAlgorithmException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, publicKey));
        // The provider's own diagnostic must survive, so a caller can log why the key was skipped.
        assertNotNull(e.getCause(), "the provider's diagnostic must be preserved as the cause");
    }

    /**
     * RFC 3110, Section 2 reserves the 3-octet exponent length for exponents longer than 255 octets. Accepting the
     * short encoding would give one key two wire forms, hence two key tags and two DS digests.
     */
    @Test
    public void testRsaNonCanonicalThreeOctetExponentLengthIsRejected() {
        byte[] publicKey = new byte[3 + 3 + RFC5702_6_2_MODULUS.length];
        publicKey[0] = 0;
        publicKey[1] = 0;
        publicKey[2] = 3;                                       // length 3, which must use the 1-octet form
        publicKey[3] = 0x01;
        publicKey[4] = 0x00;
        publicKey[5] = 0x01;
        System.arraycopy(RFC5702_6_2_MODULUS, 0, publicKey, 6, RFC5702_6_2_MODULUS.length);

        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, publicKey));
    }

    @Test
    public void testRsaZeroExponentLengthIsRejected() {
        // The 3-octet form declaring length 0 is the only way to express a zero-length exponent.
        byte[] publicKey = new byte[3 + RFC5702_6_2_MODULUS.length];
        System.arraycopy(RFC5702_6_2_MODULUS, 0, publicKey, 3, RFC5702_6_2_MODULUS.length);
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, publicKey));
    }

    @Test
    public void testRsaEmptyModulusIsRejected() {
        byte[] publicKey = {0x03, 0x01, 0x00, 0x01};
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, publicKey));
    }

    /**
     * RFC 3110, Section 2: "Leading zero octets are prohibited in the exponent and modulus."
     */
    @Test
    public void testRsaLeadingZeroOctetsAreRejected() {
        byte[] withZeroExponent = new byte[4 + RFC5702_6_2_MODULUS.length];
        withZeroExponent[0] = 3;
        withZeroExponent[1] = 0x00;                             // leading zero in a 3-octet exponent
        withZeroExponent[2] = 0x01;
        withZeroExponent[3] = 0x01;
        System.arraycopy(RFC5702_6_2_MODULUS, 0, withZeroExponent, 4, RFC5702_6_2_MODULUS.length);
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, withZeroExponent));

        byte[] withZeroModulus = new byte[RFC5702_6_2_KEY.length + 1];
        System.arraycopy(RFC5702_6_2_KEY, 0, withZeroModulus, 0, 4);
        System.arraycopy(RFC5702_6_2_KEY, 4, withZeroModulus, 5, RFC5702_6_2_KEY.length - 4);
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, withZeroModulus));
    }

    /**
     * An exponent of 1 would make every signature verify against itself.
     *
     * <p>SunRsaSign happens to reject an exponent below 3 as well, so this assertion holds through either path. The
     * explicit check in the decoder is kept so the guarantee does not depend on which JCA provider is installed:
     * nothing in the JCA contract requires a provider to make this check.</p>
     */
    @Test
    public void testRsaExponentBelowThreeIsRejected() {
        for (int exponent = 1; exponent < 3; exponent++) {
            byte[] publicKey = new byte[2 + RFC5702_6_2_MODULUS.length];
            publicKey[0] = 1;
            publicKey[1] = (byte) exponent;
            System.arraycopy(RFC5702_6_2_MODULUS, 0, publicKey, 2, RFC5702_6_2_MODULUS.length);
            assertThrows(DnssecMalformedDataException.class,
                    () -> DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, publicKey));
        }
    }

    @Test
    public void testRsaTruncatedExponentIsRejected() {
        byte[] publicKey = {0x08, 0x01, 0x00, 0x01};            // declares 8 octets, only 3 present
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, publicKey));
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, new byte[0]));
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, new byte[] {0, 0x01}));
    }

    @Test
    public void testRsaModulusAboveTheCeilingIsRejected() {
        byte[] modulus = new byte[513];                         // 4104 bits once the leading octet is non-zero
        Arrays.fill(modulus, (byte) 0xff);
        byte[] publicKey = new byte[4 + modulus.length];
        publicKey[0] = 3;
        publicKey[1] = 0x01;
        publicKey[2] = 0x00;
        publicKey[3] = 0x01;
        System.arraycopy(modulus, 0, publicKey, 4, modulus.length);
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, publicKey));
    }

    // ---------------------------------------------------------------------------------------------------- ECDSA

    @Test
    public void testRfc6605Section61P256Key() {
        ECPublicKey key = (ECPublicKey) DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP256SHA256, RFC6605_6_1_KEY);
        assertEquals(new BigInteger(1, Arrays.copyOfRange(RFC6605_6_1_KEY, 0, 32)), key.getW().getAffineX());
        assertEquals(new BigInteger(1, Arrays.copyOfRange(RFC6605_6_1_KEY, 32, 64)), key.getW().getAffineY());
        assertEquals(256, ((ECFieldFp) key.getParams().getCurve().getField()).getP().bitLength());
    }

    @Test
    public void testRfc6605Section62P384Key() {
        ECPublicKey key = (ECPublicKey) DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP384SHA384, RFC6605_6_2_KEY);
        assertEquals(new BigInteger(1, Arrays.copyOfRange(RFC6605_6_2_KEY, 0, 48)), key.getW().getAffineX());
        assertEquals(new BigInteger(1, Arrays.copyOfRange(RFC6605_6_2_KEY, 48, 96)), key.getW().getAffineY());
        assertEquals(384, ((ECFieldFp) key.getParams().getCurve().getField()).getP().bitLength());
    }

    /**
     * The JDK's {@code KeyFactory("EC")} accepts an off-curve point, so this check exists only here.
     */
    @Test
    public void testEcdsaOffCurvePointIsRejected() {
        byte[] publicKey = RFC6605_6_1_KEY.clone();
        publicKey[publicKey.length - 1] ^= 0x01;
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP256SHA256, publicKey));

        byte[] p384 = RFC6605_6_2_KEY.clone();
        p384[p384.length - 1] ^= 0x01;
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP384SHA384, p384));
    }

    /**
     * A coordinate must be a field element, that is strictly less than the field prime, and the JDK does not check
     * it: {@code KeyFactory("EC")} accepts x == p.
     *
     * <p>This is a canonicality rule, not just a range check, and the vector below shows why. On both DNSSEC curves
     * {@code x == 0} is a real curve point, because b is a quadratic residue modulo p. Its canonical encoding is 32
     * (or 48) zero octets followed by y. Encoding the same point with {@code x == p} instead is a second, distinct
     * wire form of the very same key: the curve equation is computed modulo p, so {@code p} and {@code 0} satisfy it
     * identically. Two encodings mean two key tags and two DS digests for one key, which is exactly the ambiguity
     * CVE-2023-50387 turns into an amplification primitive. The range check is what rules the second form out.</p>
     */
    @Test
    public void testEcdsaNonCanonicalCoordinateIsRejected() {
        // The point (0, y) on P-256, where y = sqrt(b) mod p.
        byte[] p256Y = hex("66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4");
        byte[] p256P = hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

        byte[] canonical = new byte[64];
        System.arraycopy(p256Y, 0, canonical, 32, 32);
        ECPublicKey key = (ECPublicKey) DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP256SHA256, canonical);
        assertEquals(BigInteger.ZERO, key.getW().getAffineX());
        assertEquals(new BigInteger(1, p256Y), key.getW().getAffineY());

        // The same point re-encoded with x == p. It satisfies the curve equation, so only the range check stops it.
        byte[] nonCanonical = new byte[64];
        System.arraycopy(p256P, 0, nonCanonical, 0, 32);
        System.arraycopy(p256Y, 0, nonCanonical, 32, 32);
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP256SHA256, nonCanonical));

        // The same construction on P-384.
        byte[] p384Y = hex("c306610fb0ae5a159cf45c06069f22a6c5eb3641c602d42dea2c4b4f75550793"
                + "406d80d2b91ad54f9048bd487af1ade1");
        byte[] p384P = hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
                + "ffffffff0000000000000000ffffffff");

        byte[] canonical384 = new byte[96];
        System.arraycopy(p384Y, 0, canonical384, 48, 48);
        ECPublicKey key384 = (ECPublicKey) DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP384SHA384, canonical384);
        assertEquals(BigInteger.ZERO, key384.getW().getAffineX());

        byte[] nonCanonical384 = new byte[96];
        System.arraycopy(p384P, 0, nonCanonical384, 0, 48);
        System.arraycopy(p384Y, 0, nonCanonical384, 48, 48);
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP384SHA384, nonCanonical384));
    }

    /**
     * The y coordinate is range-checked by the same rule. Unlike x it cannot be demonstrated with a non-canonical
     * encoding of a real point: for every point on either curve, y + p needs more octets than the encoding has, so
     * an out-of-range y is always off-curve as well and the curve equation would reject it too. The check is kept
     * because it enforces the field-element rule directly rather than by accident.
     */
    @Test
    public void testEcdsaOutOfRangeYIsRejected() {
        byte[] p256P = hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
        byte[] badY = RFC6605_6_1_KEY.clone();
        System.arraycopy(p256P, 0, badY, 32, 32);
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP256SHA256, badY));
    }

    private static byte[] hex(String value) {
        byte[] decoded = new byte[value.length() / 2];
        for (int i = 0; i < decoded.length; i++) {
            decoded[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return decoded;
    }

    @Test
    public void testEcdsaAllZeroPointIsRejected() {
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP256SHA256, new byte[64]));
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP384SHA384, new byte[96]));
    }

    /**
     * RFC 6605, Section 4 gives no length prefix and no {@code 0x04} uncompressed-point marker, so a key carrying
     * one is the wrong length and must be rejected rather than silently mis-parsed.
     */
    @Test
    public void testEcdsaWrongLengthKeysAreRejected() {
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP256SHA256, new byte[63]));
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP256SHA256, new byte[65]));
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP256SHA256, new byte[0]));
        // The same key with an X9.62 0x04 prefix is 65 octets and must not be accepted.
        byte[] prefixed = new byte[65];
        prefixed[0] = 0x04;
        System.arraycopy(RFC6605_6_1_KEY, 0, prefixed, 1, 64);
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP256SHA256, prefixed));
        // A P-384 key offered as P-256 and vice versa.
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP256SHA256, RFC6605_6_2_KEY));
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP384SHA384, RFC6605_6_1_KEY));
    }

    // ---------------------------------------------------------------------------------------------------- EdDSA

    @Test
    public void testRfc8080Section61Ed25519Key() {
        assumeTrue(DnssecAlgorithm.ED25519.isSupported(), "Ed25519 requires Java 15 or newer");
        PublicKey key = DnssecPublicKeys.decode(DnssecAlgorithm.ED25519, RFC8080_6_1_KEY);
        assertNotNull(key);
        // The hand-built SubjectPublicKeyInfo must be byte-identical to what the JDK itself would emit.
        byte[] expected = new byte[12 + RFC8080_6_1_KEY.length];
        System.arraycopy(new byte[] {
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
        }, 0, expected, 0, 12);
        System.arraycopy(RFC8080_6_1_KEY, 0, expected, 12, RFC8080_6_1_KEY.length);
        assertArrayEquals(expected, key.getEncoded());
    }

    @Test
    public void testRfc8080Section62Ed448Key() {
        assumeTrue(DnssecAlgorithm.ED448.isSupported(), "Ed448 requires Java 15 or newer");
        PublicKey key = DnssecPublicKeys.decode(DnssecAlgorithm.ED448, RFC8080_6_2_KEY);
        byte[] expected = new byte[12 + RFC8080_6_2_KEY.length];
        System.arraycopy(new byte[] {
                0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x3a, 0x00
        }, 0, expected, 0, 12);
        System.arraycopy(RFC8080_6_2_KEY, 0, expected, 12, RFC8080_6_2_KEY.length);
        assertArrayEquals(expected, key.getEncoded());
    }

    @Test
    public void testEdDsaWrongLengthKeysAreRejected() {
        assumeTrue(DnssecAlgorithm.ED25519.isSupported() && DnssecAlgorithm.ED448.isSupported(),
                "EdDSA requires Java 15 or newer");
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ED25519, new byte[31]));
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ED25519, new byte[33]));
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ED25519, RFC8080_6_2_KEY));
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ED448, new byte[56]));
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ED448, new byte[58]));
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ED448, RFC8080_6_1_KEY));
    }

    // -------------------------------------------------------------------------------------------------- general

    @Test
    public void testUnsupportedAlgorithmsAreReportedSeparately() {
        DnssecAlgorithm[] unsupported = {
                DnssecAlgorithm.RSAMD5, DnssecAlgorithm.DSA, DnssecAlgorithm.DSA_NSEC3_SHA1,
                DnssecAlgorithm.ECC_GOST, DnssecAlgorithm.ECC_GOST12, DnssecAlgorithm.SM2SM3,
                DnssecAlgorithm.PRIVATEDNS, DnssecAlgorithm.PRIVATEOID, DnssecAlgorithm.valueOf(200)
        };
        for (DnssecAlgorithm algorithm : unsupported) {
            assertThrows(DnssecUnsupportedAlgorithmException.class,
                    () -> DnssecPublicKeys.decode(algorithm, RFC5702_6_2_KEY), algorithm.toString());
        }
    }

    /**
     * Both failures share a base class, so a caller that does not care can catch one type, while a caller mapping to
     * Insecure versus Bogus can tell them apart.
     */
    @Test
    public void testBothFailuresShareABaseClass() {
        assertThrows(DnssecException.class, () -> DnssecPublicKeys.decode(DnssecAlgorithm.DSA, RFC5702_6_2_KEY));
        assertThrows(DnssecException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP256SHA256, new byte[64]));
    }

    @Test
    public void testNullAndOutOfRangeArgumentsAreRejected() {
        assertThrows(NullPointerException.class, () -> DnssecPublicKeys.decode(null, RFC6605_6_1_KEY));
        assertThrows(NullPointerException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP256SHA256, null));
        assertThrows(IllegalArgumentException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, RFC5702_6_2_KEY, 0));
        assertThrows(IllegalArgumentException.class,
                () -> DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA256, RFC5702_6_2_KEY, -1));
    }

    /**
     * Proves the whole chain against a real published signature rather than against our own encoder: the key from
     * RFC 4035, Appendix A is decoded here, the {@code RRSIG} it produced over the apex {@code SOA} is normalised by
     * {@link DnssecSignatures#normalizeRsaSignature(byte[], int)}, and the JDK verifies the two against the
     * canonical form built below. Nothing in this test is self-generated, so it cannot pass by agreeing with a bug
     * in our own code.
     *
     * <p>It is also the only coverage here for algorithm 5, and its key uses the smallest exponent that is legal at
     * all, {@code e == 3}, which sits exactly on the boundary the decoder enforces.</p>
     *
     * <p>The signed data is {@code RRSIG_RDATA | RR}, per
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-3.1.8.1">RFC 4034, Section 3.1.8.1</a>, with the
     * RRSIG Signature field itself omitted and all names in canonical form. The names are assembled from literal
     * octets so that this test does not depend on a name type.</p>
     */
    @Test
    public void testRfc4035AppendixASoaSignatureVerifies() throws Exception {
        // example. 3600 IN DNSKEY 256 3 5 (...), the zone signing key, key tag 38519.
        byte[] dnskey = decode("AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBVrZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61e"
                + "k8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFovBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZI"
                + "ySFNsgEYvh0z2542lzMKR4Dh8uZffQ==");
        RSAPublicKey key = (RSAPublicKey) DnssecPublicKeys.decode(DnssecAlgorithm.RSASHA1, dnskey);
        assertEquals(1024, key.getModulus().bitLength());
        assertEquals(BigInteger.valueOf(3), key.getPublicExponent());
        assertEquals(38519, DnssecKeyTag.compute(256, 3, DnssecAlgorithm.RSASHA1, dnskey));

        // example. 3600 IN SOA ns1.example. bugs.x.w.example. 1081539377 3600 300 3600000 3600
        ByteArrayOutputStream soaRdata = new ByteArrayOutputStream();
        writeName(soaRdata, "ns1", "example");
        writeName(soaRdata, "bugs", "x", "w", "example");
        writeInt(soaRdata, 1081539377L);
        writeInt(soaRdata, 3600);
        writeInt(soaRdata, 300);
        writeInt(soaRdata, 3600000);
        writeInt(soaRdata, 3600);
        byte[] rdata = soaRdata.toByteArray();

        // example. 3600 RRSIG SOA 5 1 3600 20040509183619 20040409183619 38519 example. (...)
        ByteArrayOutputStream signedData = new ByteArrayOutputStream();
        writeShort(signedData, 6);              // type covered: SOA
        signedData.write(5);                    // algorithm: RSASHA1
        signedData.write(1);                    // labels: "example." has one
        writeInt(signedData, 3600);             // original TTL
        writeInt(signedData, 1084127779L);      // signature expiration, 20040509183619
        writeInt(signedData, 1081535779L);      // signature inception,  20040409183619
        writeShort(signedData, 38519);          // key tag
        writeName(signedData, "example");       // signer's name, canonical

        writeName(signedData, "example");       // owner, canonical
        writeShort(signedData, 6);              // type: SOA
        writeShort(signedData, 1);              // class: IN
        writeInt(signedData, 3600);             // the RRSIG original TTL, not the RR's own
        writeShort(signedData, rdata.length);
        signedData.write(rdata, 0, rdata.length);

        byte[] signature = decode("ONx0k36rcjaxYtcNgq6iQnpNV5+drqYAsC9h7TSJaHCqbhE67Sr6aH2xDUGcqQWu/n0UVzrF"
                + "vkgO9ebarZ0GWDKcuwlM6eNB5SiX2K74l5LWDA7S/Un/IbtDq4Ay8NMNLQI7Dw7n4p8/rjkB"
                + "jV7j86HyQgM5e7+miRAz8V01b0I=");
        int modulusLength = (key.getModulus().bitLength() + 7) / 8;
        byte[] normalized = DnssecSignatures.normalizeRsaSignature(signature, modulusLength);
        assertEquals(modulusLength, normalized.length);

        Signature verifier = Signature.getInstance(DnssecAlgorithm.RSASHA1.signatureAlgorithm());
        verifier.initVerify(key);
        verifier.update(signedData.toByteArray());
        assertTrue(verifier.verify(normalized), "RFC 4035 Appendix A apex SOA signature must verify");
    }

    /**
     * Writes labels in canonical wire form: a length octet per label, then the root label. The inputs here are
     * already lower-case ASCII, which is what canonical form requires.
     */
    private static void writeName(ByteArrayOutputStream out, String... labels) {
        for (String label : labels) {
            out.write(label.length());
            for (int i = 0; i < label.length(); i++) {
                out.write(label.charAt(i));
            }
        }
        out.write(0);
    }

    private static void writeShort(ByteArrayOutputStream out, int value) {
        out.write(value >>> 8 & 0xff);
        out.write(value & 0xff);
    }

    private static void writeInt(ByteArrayOutputStream out, long value) {
        out.write((int) (value >>> 24 & 0xff));
        out.write((int) (value >>> 16 & 0xff));
        out.write((int) (value >>> 8 & 0xff));
        out.write((int) (value & 0xff));
    }

    @Test
    public void testInputIsNotModified() {
        byte[] publicKey = RFC6605_6_1_KEY.clone();
        DnssecPublicKeys.decode(DnssecAlgorithm.ECDSAP256SHA256, publicKey);
        assertArrayEquals(RFC6605_6_1_KEY, publicKey);
    }
}
