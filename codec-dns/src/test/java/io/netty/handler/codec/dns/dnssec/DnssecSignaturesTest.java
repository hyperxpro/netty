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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class DnssecSignaturesTest {

    private static byte[] rawRS(String rHex, String sHex, int halfLength) {
        byte[] rawRS = new byte[halfLength * 2];
        byte[] r = new BigInteger(rHex, 16).toByteArray();
        byte[] s = new BigInteger(sHex, 16).toByteArray();
        copyRightAligned(r, rawRS, 0, halfLength);
        copyRightAligned(s, rawRS, halfLength, halfLength);
        return rawRS;
    }

    private static void copyRightAligned(byte[] value, byte[] target, int offset, int length) {
        // BigInteger.toByteArray() may prepend a sign octet; drop it, the value is known to fit.
        int start = value.length > length ? value.length - length : 0;
        int copied = value.length - start;
        System.arraycopy(value, start, target, offset + length - copied, copied);
    }

    /**
     * The branch that pads with a {@code 0x00} sign octet is the one every implementation forgets: it only triggers
     * when the top bit of the leading octet is set, which happens for roughly half of all signatures.
     */
    @Test
    public void testToDerPadsIntegersWhoseTopBitIsSet() {
        byte[] rawRS = new byte[64];
        rawRS[0] = (byte) 0x80;                                 // r starts with 0x80
        rawRS[31] = 0x01;
        rawRS[32] = (byte) 0xff;                                // s starts with 0xff
        rawRS[63] = 0x02;

        byte[] der = DnssecSignatures.toDer(rawRS, 32);
        assertStrictDer(der, rawRS, 32);

        // SEQUENCE, 0x46 content octets, then two INTEGERs of 0x21 octets each thanks to the sign padding.
        assertEquals(0x30, der[0] & 0xff);
        assertEquals(0x46, der[1] & 0xff);
        assertEquals(0x02, der[2] & 0xff);
        assertEquals(0x21, der[3] & 0xff);
        assertEquals(0x00, der[4] & 0xff);
        assertEquals(0x80, der[5] & 0xff);
        assertEquals(0x02, der[37] & 0xff);
        assertEquals(0x21, der[38] & 0xff);
        assertEquals(0x00, der[39] & 0xff);
        assertEquals(0xff, der[40] & 0xff);
        assertEquals(2 + 0x46, der.length);

        assertArrayEquals(Arrays.copyOfRange(rawRS, 0, 32), Arrays.copyOfRange(der, 5, 37));
        assertArrayEquals(Arrays.copyOfRange(rawRS, 32, 64), Arrays.copyOfRange(der, 40, 72));
    }

    @Test
    public void testToDerStripsLeadingZeroOctets() {
        byte[] rawRS = new byte[64];
        rawRS[31] = 0x01;                                       // r == 1
        rawRS[63] = 0x7f;                                       // s == 127, top bit clear

        byte[] der = DnssecSignatures.toDer(rawRS, 32);

        assertArrayEquals(new byte[] {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x7f}, der);
    }

    /**
     * A value that is exactly {@code 0x7f...} needs no padding while {@code 0x80...} does, so the two must differ by
     * exactly one octet.
     */
    @Test
    public void testToDerPaddingBoundary() {
        byte[] unpadded = new byte[64];
        unpadded[0] = 0x7f;
        unpadded[32] = 0x7f;
        byte[] padded = new byte[64];
        padded[0] = (byte) 0x80;
        padded[32] = (byte) 0x80;

        assertEquals(DnssecSignatures.toDer(unpadded, 32).length + 2, DnssecSignatures.toDer(padded, 32).length);
    }

    @Test
    public void testToDerRejectsZeroIntegers() {
        byte[] zeroR = new byte[64];
        zeroR[63] = 0x01;
        assertThrows(DnssecMalformedDataException.class, () -> DnssecSignatures.toDer(zeroR, 32));

        byte[] zeroS = new byte[64];
        zeroS[31] = 0x01;
        assertThrows(DnssecMalformedDataException.class, () -> DnssecSignatures.toDer(zeroS, 32));

        assertThrows(DnssecMalformedDataException.class, () -> DnssecSignatures.toDer(new byte[64], 32));
    }

    @Test
    public void testToDerRejectsWrongLengths() {
        assertThrows(DnssecMalformedDataException.class, () -> DnssecSignatures.toDer(new byte[63], 32));
        assertThrows(DnssecMalformedDataException.class, () -> DnssecSignatures.toDer(new byte[65], 32));
        assertThrows(DnssecMalformedDataException.class, () -> DnssecSignatures.toDer(new byte[0], 32));
        // A P-384 signature offered as P-256.
        assertThrows(DnssecMalformedDataException.class, () -> DnssecSignatures.toDer(new byte[96], 32));
    }

    /**
     * A half-length larger than P-384's would push the DER content past 127 octets, where the short-form length no
     * longer encodes it. That is a caller bug, not bad network data, so it is an IllegalArgumentException.
     */
    @Test
    public void testToDerRejectsUnsupportedHalfLengths() {
        assertThrows(IllegalArgumentException.class, () -> DnssecSignatures.toDer(new byte[132], 66));
        assertThrows(IllegalArgumentException.class, () -> DnssecSignatures.toDer(new byte[0], 0));
        assertThrows(IllegalArgumentException.class, () -> DnssecSignatures.toDer(new byte[0], -1));
        assertThrows(NullPointerException.class, () -> DnssecSignatures.toDer(null, 32));
    }

    /**
     * The largest signature P-384 can produce still fits the DER short form, so the conversion never needs the
     * long-form length.
     */
    @Test
    public void testToDerP384WorstCaseStaysInShortForm() {
        byte[] rawRS = new byte[96];
        Arrays.fill(rawRS, (byte) 0xff);
        byte[] der = DnssecSignatures.toDer(rawRS, 48);
        assertStrictDer(der, rawRS, 48);
        assertEquals(0x30, der[0] & 0xff);
        assertEquals(2 + 1 + 48 + 2 + 1 + 48, der[1] & 0xff);
        assertTrue((der[1] & 0xff) <= 127);
        assertEquals(2 + (der[1] & 0xff), der.length);
    }

    /**
     * Round-trips the conversion through a real verifier. {@code ...inP1363Format} consumes exactly the
     * {@code r || s} wire format DNSSEC uses, so signing with it and verifying the DER produced here proves the two
     * encodings describe the same signature. That algorithm name is Java 9+, hence the assumption; the test still
     * compiles at release 8 because it is only a string.
     *
     * <p><strong>Do not reduce this test to "does verify() return true".</strong> That is not a valid oracle for a
     * DER writer, and it was measured here rather than assumed: with the {@code 0x00} sign octet deliberately
     * removed from the encoder, 200 of 200 signatures still verified true on this JDK, 156 of which had a leading
     * octet with its top bit set. SunEC's parser accepts a negative INTEGER and verifies it anyway, so an encoder
     * that omits sign padding ships broken output that every verify-based test calls correct, until a strict
     * verifier such as BouncyCastle, or a future tightening of the JDK, rejects it. {@link #assertStrictDer} is
     * what actually holds the encoding to the specification, and removing it silently guts this test.</p>
     */
    @Test
    public void testToDerRoundTripsAgainstP1363() throws Exception {
        assumeTrue(isAvailable("SHA256withECDSAinP1363Format"), "SHA256withECDSAinP1363Format requires Java 9+");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom(new byte[32]));

        // Several signatures, so that the leading-octet distribution covers both the padded and unpadded branches.
        for (int i = 0; i < 32; i++) {
            KeyPair keyPair = generator.generateKeyPair();
            byte[] data = {(byte) i, 'n', 'e', 't', 't', 'y'};

            Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
            signer.initSign(keyPair.getPrivate());
            signer.update(data);
            byte[] rawRS = signer.sign();
            assertEquals(64, rawRS.length);

            byte[] der = DnssecSignatures.toDer(rawRS, 32);
            assertStrictDer(der, rawRS, 32);

            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(keyPair.getPublic());
            verifier.update(data);
            assertTrue(verifier.verify(der), "iteration " + i);
        }
    }

    /**
     * Parses a {@code SEQUENCE { INTEGER r, INTEGER s }} strictly and asserts it denotes the same two non-negative
     * integers as the raw {@code r || s} input. Enforces what DER requires and SunEC does not: a definite short-form
     * length that matches the content exactly, a non-empty INTEGER whose leading octet has its top bit clear, and a
     * minimal encoding, so a leading {@code 0x00} is present only when the octet after it needs the sign bit.
     */
    private static void assertStrictDer(byte[] der, byte[] rawRS, int halfLength) {
        assertEquals(0x30, der[0] & 0xff, "expected a SEQUENCE tag");
        int contentLength = der[1] & 0xff;
        assertTrue(contentLength <= 127, "length must use the short form");
        assertEquals(der.length, 2 + contentLength, "declared length must match the encoding");

        int index = 2;
        for (int half = 0; half < 2; half++) {
            assertEquals(0x02, der[index] & 0xff, "expected an INTEGER tag");
            int length = der[index + 1] & 0xff;
            assertTrue(length > 0, "an INTEGER must have at least one content octet");
            int content = index + 2;
            assertEquals(0, der[content] & 0x80, "INTEGER must be non-negative");
            if (der[content] == 0) {
                assertTrue(length > 1, "a lone 0x00 is not a valid non-zero INTEGER");
                assertNotEquals(0, der[content + 1] & 0x80, "leading 0x00 is only allowed to carry the sign bit");
            }

            byte[] encoded = Arrays.copyOfRange(der, content, content + length);
            byte[] raw = Arrays.copyOfRange(rawRS, half * halfLength, (half + 1) * halfLength);
            // The signed BigInteger constructor is the DER semantic; using it proves the sign octet is right.
            assertEquals(new BigInteger(1, raw), new BigInteger(encoded), "integer " + half);

            index = content + length;
        }
        assertEquals(der.length, index, "trailing octets after the SEQUENCE");
    }

    private static boolean isAvailable(String algorithm) {
        try {
            Signature.getInstance(algorithm);
            return true;
        } catch (NoSuchAlgorithmException ignored) {
            return false;
        }
    }

    // ------------------------------------------------------------------------------------------------------ RSA

    @Test
    public void testNormalizeRsaSignatureLeftPadsShortSignatures() {
        byte[] signature = {0x01, 0x02, 0x03};
        byte[] normalized = DnssecSignatures.normalizeRsaSignature(signature, 8);
        assertArrayEquals(new byte[] {0, 0, 0, 0, 0, 0x01, 0x02, 0x03}, normalized);
    }

    /**
     * RFC 3110, Section 3 permits leading zero octets in the signature, but SunRsaSign rejects any length other than
     * the modulus length outright, so they have to be stripped rather than passed through.
     */
    @Test
    public void testNormalizeRsaSignatureStripsLeadingZeroOctets() {
        byte[] signature = {0, 0, 0, 0x01, 0x02, 0x03};
        assertArrayEquals(new byte[] {0, 0x01, 0x02, 0x03}, DnssecSignatures.normalizeRsaSignature(signature, 4));
        assertArrayEquals(new byte[] {0x01, 0x02, 0x03}, DnssecSignatures.normalizeRsaSignature(signature, 3));
    }

    @Test
    public void testNormalizeRsaSignatureLeavesCorrectlySizedSignaturesAlone() {
        byte[] signature = {(byte) 0x80, 0x02, 0x03, 0x04};
        byte[] normalized = DnssecSignatures.normalizeRsaSignature(signature, 4);
        assertArrayEquals(signature, normalized);
        assertNotSame(signature, normalized, "must not alias the caller's array");
    }

    @Test
    public void testNormalizeRsaSignatureRejectsOverlongSignatures() {
        byte[] signature = {0, 0x01, 0x02, 0x03, 0x04};
        assertThrows(DnssecMalformedDataException.class,
                () -> DnssecSignatures.normalizeRsaSignature(signature, 3));
    }

    @Test
    public void testNormalizeRsaSignatureHandlesAllZeroInput() {
        assertArrayEquals(new byte[4], DnssecSignatures.normalizeRsaSignature(new byte[4], 4));
        assertArrayEquals(new byte[4], DnssecSignatures.normalizeRsaSignature(new byte[16], 4));
        assertArrayEquals(new byte[4], DnssecSignatures.normalizeRsaSignature(new byte[0], 4));
    }

    @Test
    public void testNormalizeRsaSignatureRejectsInvalidArguments() {
        assertThrows(NullPointerException.class, () -> DnssecSignatures.normalizeRsaSignature(null, 4));
        assertThrows(IllegalArgumentException.class,
                () -> DnssecSignatures.normalizeRsaSignature(new byte[4], 0));
        assertThrows(IllegalArgumentException.class,
                () -> DnssecSignatures.normalizeRsaSignature(new byte[4], -1));
    }

    /**
     * Proves the padding is what makes an otherwise valid RSA signature verify: SunRsaSign rejects the very same
     * signature carrying an extra leading zero octet with a length error before it looks at the bytes.
     */
    @Test
    public void testNormalizeRsaSignatureIsRequiredByTheProvider() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, new SecureRandom(new byte[32]));
        KeyPair keyPair = generator.generateKeyPair();
        byte[] data = "netty".getBytes("US-ASCII");

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign();
        assertEquals(128, signature.length);

        byte[] padded = new byte[signature.length + 1];
        System.arraycopy(signature, 0, padded, 1, signature.length);

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(data);
        assertThrows(SignatureException.class, () -> verifier.verify(padded));

        Signature retry = Signature.getInstance("SHA256withRSA");
        retry.initVerify(keyPair.getPublic());
        retry.update(data);
        assertTrue(retry.verify(DnssecSignatures.normalizeRsaSignature(padded, 128)));
    }

    @Test
    public void testRawRSHelperIsSelfConsistent() {
        // Guards the test helper itself, so a broken fixture cannot make the assertions above vacuous.
        byte[] rawRS = rawRS("01", "80", 32);
        assertEquals(64, rawRS.length);
        assertEquals(0x01, rawRS[31] & 0xff);
        assertEquals(0x80, rawRS[63] & 0xff);
        assertArrayEquals(new byte[] {0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, (byte) 0x80},
                DnssecSignatures.toDer(rawRS, 32));
    }
}
