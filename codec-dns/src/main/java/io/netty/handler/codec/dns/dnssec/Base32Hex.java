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

import io.netty.handler.codec.CorruptedFrameException;
import io.netty.util.internal.ObjectUtil;

import java.util.Arrays;

/**
 * The base32hex alphabet of <a href="https://www.rfc-editor.org/rfc/rfc4648.html#section-7">RFC 4648, section 7</a>
 * without padding, which is how the hashed owner name of an NSEC3 record is written into a label.
 * <p>
 * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#section-3.3">RFC 5155, section 3.3</a>, as corrected by
 * <a href="https://www.rfc-editor.org/errata/eid3544">RFC 5155 erratum 3544</a>, calls for "an unpadded sequence of
 * case-insensitive base32hex digits", which is where both the absence of padding and the case-insensitivity of
 * {@link #decode(byte[], int, int)} come from. The erratum matters: RFC 5155 writes plain "base32" in several
 * places, including section 3 and section 3.2, while its own terminology in section 1.3 defines the term to mean
 * the extended hex alphabet. RFC 4648, section 7 warns that the two alphabets "should not be regarded as the
 * same", and they are not: using the plain base32 one silently yields a different hash, so every NSEC3 proof
 * fails.
 */
final class Base32Hex {

    private static final char[] ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUV".toCharArray();

    /**
     * Maps an ASCII octet to its 5-bit value, or to {@code -1} when it is not part of the alphabet.
     */
    private static final byte[] DECODE_TABLE = new byte[128];

    /**
     * Which lengths modulo 8 an unpadded encoding can have. A group of 8 characters carries 5 octets, and a final
     * partial group of 1, 3 or 6 characters carries fewer than 5 bits more than the octets it completes, so no input
     * can produce one.
     */
    private static final boolean[] VALID_LENGTH_REMAINDER = { true, false, true, false, true, true, false, true };

    static {
        Arrays.fill(DECODE_TABLE, (byte) -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            char c = ALPHABET[i];
            DECODE_TABLE[c] = (byte) i;
            // RFC 5155, section 3.3 calls the digits case-insensitive, and a resolver really does see both: DNS
            // names are case-insensitive, and a 0x20-randomising resolver flips the case of the name on purpose.
            if (c >= 'A' && c <= 'Z') {
                DECODE_TABLE[c + ('a' - 'A')] = (byte) i;
            }
        }
    }

    private Base32Hex() {
    }

    /**
     * Decodes {@code src} in full, see {@link #decode(byte[], int, int)}.
     */
    static byte[] decode(byte[] src) {
        ObjectUtil.checkNotNull(src, "src");
        return decode(src, 0, src.length);
    }

    /**
     * Decodes {@code length} unpadded base32hex characters starting at {@code offset} into the octets they encode.
     * Both cases are accepted, as RFC 5155, section 3.3 requires.
     * <p>
     * The decoding is strict: padding, characters outside the alphabet, lengths no input could produce, and
     * non-zero trailing bits are all rejected. Being lenient about any of those would make the encoding
     * non-injective, and an NSEC3 owner label is compared against a hash the resolver computed itself, so a second
     * spelling of the same hash is a second owner name that matches a given query name.
     *
     * @throws CorruptedFrameException if {@code src} is not a well-formed unpadded base32hex encoding
     */
    static byte[] decode(byte[] src, int offset, int length) {
        ObjectUtil.checkNotNull(src, "src");
        ObjectUtil.checkPositiveOrZero(offset, "offset");
        ObjectUtil.checkPositiveOrZero(length, "length");
        if (length > src.length - offset) {
            throw new IndexOutOfBoundsException("offset: " + offset + ", length: " + length + " (expected: offset + "
                    + "length <= " + src.length + ')');
        }
        if (!VALID_LENGTH_REMAINDER[length & 7]) {
            throw new CorruptedFrameException("base32hex input of length " + length
                    + " is not the unpadded encoding of any octet string");
        }
        byte[] dst = new byte[length * 5 / 8];
        int bitBuffer = 0;
        int bitCount = 0;
        int pos = 0;
        for (int i = 0; i < length; i++) {
            int c = src[offset + i] & 0xff;
            int value = c < DECODE_TABLE.length ? DECODE_TABLE[c] : -1;
            if (value < 0) {
                if (c == '=') {
                    throw new CorruptedFrameException("base32hex input is padded, at index " + i);
                }
                throw new CorruptedFrameException("invalid base32hex character 0x" + Integer.toHexString(c)
                        + " at index " + i);
            }
            bitBuffer = (bitBuffer << 5) | value;
            bitCount += 5;
            if (bitCount >= 8) {
                bitCount -= 8;
                dst[pos++] = (byte) (bitBuffer >>> bitCount);
            }
        }
        if (bitCount > 0 && (bitBuffer & ((1 << bitCount) - 1)) != 0) {
            throw new CorruptedFrameException("base32hex input has non-zero trailing bits");
        }
        return dst;
    }

    /**
     * Encodes {@code src} as unpadded, upper case base32hex.
     */
    static String encode(byte[] src) {
        ObjectUtil.checkNotNull(src, "src");
        StringBuilder buf = new StringBuilder((src.length * 8 + 4) / 5);
        int bitBuffer = 0;
        int bitCount = 0;
        for (byte b : src) {
            bitBuffer = (bitBuffer << 8) | (b & 0xff);
            bitCount += 8;
            while (bitCount >= 5) {
                bitCount -= 5;
                buf.append(ALPHABET[(bitBuffer >>> bitCount) & 0x1f]);
            }
        }
        if (bitCount > 0) {
            buf.append(ALPHABET[(bitBuffer << (5 - bitCount)) & 0x1f]);
        }
        return buf.toString();
    }
}
