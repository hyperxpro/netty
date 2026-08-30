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

import io.netty.util.internal.ObjectUtil;

import java.security.Signature;

/**
 * Converts the Signature field of an {@code RRSIG} record into the shape the JDK expects.
 *
 * <p>DNSSEC and the JCA disagree about signature framing for both remaining signature families, and in both cases
 * the disagreement is silent: feeding the wire bytes straight to {@link Signature#verify(byte[])} does not raise a
 * decoding error, it either throws a length exception or simply returns {@code false}, which a validator would
 * report as <em>Bogus</em>. The conversions here are what make an otherwise valid signature verify.</p>
 */
public final class DnssecSignatures {

    /**
     * The largest ECDSA half-signature this class accepts, in octets.
     *
     * <p><a href="https://www.rfc-editor.org/rfc/rfc6605.html#section-4">RFC 6605, Section 4</a> defines only P-256
     * (32 octets) and P-384 (48). Bounding the input here is what guarantees the DER SEQUENCE below never exceeds
     * 127 content octets, so the short-form length encoding always suffices and no long-form path is needed. A curve
     * with larger coordinates, such as P-521, would break that guarantee, and rejecting it outright is safer than
     * emitting silently malformed DER.</p>
     */
    private static final int MAXIMUM_ECDSA_HALF_LENGTH = 48;

    private static final int ASN1_SEQUENCE = 0x30;
    private static final int ASN1_INTEGER = 0x02;

    private DnssecSignatures() {
    }

    /**
     * Converts an ECDSA signature from its DNSSEC wire format to ASN.1 DER.
     *
     * <p><a href="https://www.rfc-editor.org/rfc/rfc6605.html#section-4">RFC 6605, Section 4</a> carries the two
     * signature integers as the fixed-width concatenation {@code r || s}, each padded to the coordinate size of the
     * curve. The JCA {@code SHA256withECDSA} and {@code SHA384withECDSA} signatures instead expect
     * {@code SEQUENCE { INTEGER r, INTEGER s }}, whose INTEGERs are minimally encoded and signed.</p>
     *
     * @param rawRS      the {@code r || s} value from the {@code RRSIG} Signature field. Never modified.
     * @param halfLength the width of each integer: 32 for {@link DnssecAlgorithm#ECDSAP256SHA256}, 48 for
     *                   {@link DnssecAlgorithm#ECDSAP384SHA384}.
     * @return a freshly allocated DER encoding suitable for {@link Signature#verify(byte[])}.
     * @throws IllegalArgumentException     if {@code halfLength} is not a width RFC 6605 defines. This one is a
     *                                      programming error rather than bad network data.
     * @throws DnssecMalformedDataException if {@code rawRS} is not exactly {@code 2 * halfLength} octets, or if
     *                                      either integer is zero, which no valid ECDSA signature contains.
     */
    public static byte[] toDer(byte[] rawRS, int halfLength) {
        ObjectUtil.checkNotNull(rawRS, "rawRS");
        ObjectUtil.checkPositive(halfLength, "halfLength");
        if (halfLength > MAXIMUM_ECDSA_HALF_LENGTH) {
            throw new IllegalArgumentException(
                    "halfLength: " + halfLength + " (expected: <= " + MAXIMUM_ECDSA_HALF_LENGTH + ')');
        }
        if (rawRS.length != halfLength * 2) {
            throw new DnssecMalformedDataException("ECDSA signature is " + rawRS.length + " octets, expected "
                    + halfLength * 2);
        }

        int rOffset = minimalOffset(rawRS, 0, halfLength);
        int sOffset = minimalOffset(rawRS, halfLength, halfLength);
        // r and s are both in [1, n-1]; a zero integer cannot come from a signer and would encode as a bare 0x00.
        if (rOffset == halfLength) {
            throw new DnssecMalformedDataException("ECDSA signature has a zero r");
        }
        if (sOffset == rawRS.length) {
            throw new DnssecMalformedDataException("ECDSA signature has a zero s");
        }

        // DER INTEGER is two's complement, so a leading octet with its top bit set needs a 0x00 sign octet.
        int rLength = halfLength - rOffset;
        int rPadding = (rawRS[rOffset] & 0x80) != 0 ? 1 : 0;
        int sLength = rawRS.length - sOffset;
        int sPadding = (rawRS[sOffset] & 0x80) != 0 ? 1 : 0;

        int contentLength = 2 + rPadding + rLength + 2 + sPadding + sLength;
        // Guaranteed by MAXIMUM_ECDSA_HALF_LENGTH: 2 + 1 + 48 + 2 + 1 + 48 == 102.
        assert contentLength <= 127 : "DER content length would need long form: " + contentLength;

        byte[] der = new byte[2 + contentLength];
        int index = 0;
        der[index++] = (byte) ASN1_SEQUENCE;
        der[index++] = (byte) contentLength;
        index = writeInteger(der, index, rawRS, rOffset, rLength, rPadding);
        writeInteger(der, index, rawRS, sOffset, sLength, sPadding);
        return der;
    }

    private static int writeInteger(byte[] der, int index, byte[] source, int offset, int length, int padding) {
        der[index++] = (byte) ASN1_INTEGER;
        der[index++] = (byte) (padding + length);
        if (padding != 0) {
            der[index++] = 0;
        }
        System.arraycopy(source, offset, der, index, length);
        return index + length;
    }

    /**
     * Returns the index of the first non-zero octet of the {@code length}-octet field starting at {@code offset}, or
     * {@code offset + length} if every octet is zero.
     */
    private static int minimalOffset(byte[] value, int offset, int length) {
        int end = offset + length;
        int index = offset;
        while (index < end && value[index] == 0) {
            index++;
        }
        return index;
    }

    /**
     * Normalises an RSA signature to exactly the length of the modulus that is meant to verify it.
     *
     * <p><a href="https://www.rfc-editor.org/rfc/rfc3110.html#section-3">RFC 3110, Section 3</a> states that
     * "leading zero bytes are permitted in the RSA/SHA1 algorithm signature", so a signer may legitimately publish a
     * signature that is longer, or a stripped one that is shorter, than the modulus. {@code SunRsaSign} accepts
     * neither: any length other than the modulus length fails with
     * {@code SignatureException: Bad signature length}, before the signature is even examined. Left-padding to the
     * modulus length is therefore required for interoperability, not an optimisation.</p>
     *
     * @param signature          the {@code RRSIG} Signature field. Never modified.
     * @param modulusLengthBytes the length of the signer's RSA modulus in octets, that is
     *                           {@code (modulus.bitLength() + 7) / 8}.
     * @return a freshly allocated array of exactly {@code modulusLengthBytes} octets.
     * @throws DnssecMalformedDataException if the signature still exceeds the modulus after leading zero octets are
     *                                      removed, which means it cannot have been produced by that key.
     */
    public static byte[] normalizeRsaSignature(byte[] signature, int modulusLengthBytes) {
        ObjectUtil.checkNotNull(signature, "signature");
        ObjectUtil.checkPositive(modulusLengthBytes, "modulusLengthBytes");

        int offset = minimalOffset(signature, 0, signature.length);
        int length = signature.length - offset;
        if (length > modulusLengthBytes) {
            throw new DnssecMalformedDataException("RSA signature is " + length
                    + " octets after stripping leading zeros, which exceeds the " + modulusLengthBytes
                    + "-octet modulus");
        }

        byte[] normalized = new byte[modulusLengthBytes];
        System.arraycopy(signature, offset, normalized, modulusLengthBytes - length, length);
        return normalized;
    }
}
