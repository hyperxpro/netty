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

import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.util.internal.EmptyArrays;
import io.netty.util.internal.ObjectUtil;

import java.util.Arrays;

/**
 * The immutable {@code Type Bit Maps} field of an NSEC or NSEC3 record, which lists the RR types that exist at an
 * owner name. See <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-4.1.2">RFC 4034, section 4.1.2</a>.
 * <p>
 * The field is a sequence of window blocks, each {@code (window number, bitmap length, bitmap)}. A window covers 256
 * RR types and the bitmap holds one bit per type in network bit order, the most significant bit of the first octet
 * standing for the lowest type in the window.
 * <p>
 * An NSEC or NSEC3 record is what proves that a name or a type does <em>not</em> exist, so a resolver reaches a
 * "denial of existence" conclusion by finding a bit clear here. That makes a parser that can be talked into reading
 * the wrong bit as dangerous as one that accepts a bad signature, which is why this parser is strict about the
 * framing.
 */
public final class DnsTypeBitmap {

    /**
     * An empty bitmap, asserting that no type exists.
     */
    public static final DnsTypeBitmap EMPTY = new DnsTypeBitmap(EmptyArrays.EMPTY_BYTES, EmptyArrays.EMPTY_INTS);

    /**
     * A window number is a single octet and window numbers strictly ascend, so a field can never hold more blocks
     * than this. The check is kept explicit so the bound does not silently depend on the ascending-order check.
     */
    private static final int MAX_WINDOW_BLOCKS = 256;

    /**
     * A window covers 256 types, which is 32 octets of bitmap.
     */
    private static final int MAX_BITMAP_LENGTH = 32;

    /**
     * The name {@link DnsRecordType#valueOf(int)} gives a type it does not know a mnemonic for.
     */
    private static final String UNKNOWN = "UNKNOWN";

    private final byte[] wire;
    private final int[] types;

    private DnsTypeBitmap(byte[] wire, int[] types) {
        this.wire = wire;
        this.types = types;
    }

    /**
     * Reads and parses {@code length} octets of {@code Type Bit Maps} from {@code in}, advancing its reader index by
     * {@code length}.
     * <p>
     * A {@code length} of zero yields {@link #EMPTY}. That is legal:
     * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-6.4">RFC 6840, section 6.4</a> corrects the
     * grammar of RFC 5155, section 3.2.1 from {@code (...)+} to {@code (...)*}, and an NSEC3 that matches an empty
     * non-terminal carries exactly this.
     *
     * RFC 4034, section 4.1.2 says only that blocks "are present in the NSEC RR RDATA in increasing numerical
     * order"; this parser reads that as <em>strictly</em> increasing and rejects a repeated window number, which is
     * otherwise a way to set a bit twice and have a single-pass reader keep whichever of the two blocks it happens
     * to look at.
     *
     * @throws CorruptedFrameException if the field is truncated, its window numbers do not strictly ascend, a bitmap
     *                                 length is outside 1 to {@value #MAX_BITMAP_LENGTH}, or a block is all zero
     */
    public static DnsTypeBitmap decode(ByteBuf in, int length) {
        ObjectUtil.checkNotNull(in, "in");
        ObjectUtil.checkPositiveOrZero(length, "length");
        if (in.readableBytes() < length) {
            throw new CorruptedFrameException("truncated type bit maps field: " + length
                    + " octets announced but only " + in.readableBytes() + " readable");
        }
        if (length == 0) {
            return EMPTY;
        }
        byte[] wire = new byte[length];
        in.readBytes(wire);
        return new DnsTypeBitmap(wire, parse(wire));
    }

    /**
     * Returns {@code true} if this bitmap asserts that {@code type} exists at the owner name.
     */
    public boolean contains(DnsRecordType type) {
        return contains(ObjectUtil.checkNotNull(type, "type").intValue());
    }

    /**
     * Returns {@code true} if this bitmap asserts that the RR type with the value {@code type} exists at the owner
     * name.
     *
     * @throws IllegalArgumentException if {@code type} is not a 16-bit RR type
     */
    public boolean contains(int type) {
        if ((type & 0xffff) != type) {
            throw new IllegalArgumentException("type: " + type + " (expected: 0 ~ 65535)");
        }
        return Arrays.binarySearch(types, type) >= 0;
    }

    /**
     * Returns the RR types this bitmap asserts, in ascending order.
     * <p>
     * The bits are reported exactly as they appear on the wire. RFC 4034, section 4.1.2 says that "bits
     * representing pseudo-types MUST be clear" and that "if encountered, they MUST be ignored upon being read";
     * applying that is left to the caller, because dropping a bit here would quietly hide a malformed zone from
     * code that asked what the wire actually said. The octets {@link #writeTo(ByteBuf)} emits are unaffected
     * either way, since they are the ones that were parsed.
     */
    public int[] types() {
        return types.clone();
    }

    /**
     * Returns the number of RR types this bitmap asserts.
     */
    public int size() {
        return types.length;
    }

    /**
     * Returns {@code true} if this bitmap asserts no type at all.
     */
    public boolean isEmpty() {
        return types.length == 0;
    }

    /**
     * Returns the number of octets the wire form of this field occupies.
     */
    public int wireLength() {
        return wire.length;
    }

    /**
     * Writes this field to {@code out} exactly as it was read. The field lives inside signed RDATA, so it has to go
     * back out octet for octet or the signature over it no longer verifies.
     */
    public void writeTo(ByteBuf out) {
        ObjectUtil.checkNotNull(out, "out").writeBytes(wire);
    }

    /**
     * Two bitmaps are equal when they assert the same set of RR types, regardless of how that set was encoded.
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DnsTypeBitmap)) {
            return false;
        }
        return Arrays.equals(types, ((DnsTypeBitmap) obj).types);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(types);
    }

    /**
     * Returns the presentation form of this field: the RR type mnemonics in ascending order separated by a single
     * space, with a type that has no mnemonic written as {@code TYPEnnn} as described in
     * <a href="https://www.rfc-editor.org/rfc/rfc3597.html#section-5">RFC 3597, section 5</a>. An empty bitmap
     * yields an empty string.
     */
    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder(types.length << 3);
        for (int type : types) {
            if (buf.length() != 0) {
                buf.append(' ');
            }
            DnsRecordType recordType = DnsRecordType.valueOf(type);
            if (UNKNOWN.equals(recordType.name())) {
                buf.append("TYPE").append(type);
            } else {
                buf.append(recordType.name());
            }
        }
        return buf.toString();
    }

    private static int[] parse(byte[] wire) {
        int[] types = new int[16];
        int count = 0;
        int blocks = 0;
        int previousWindow = -1;
        int pos = 0;
        while (pos < wire.length) {
            if (pos + 2 > wire.length) {
                throw new CorruptedFrameException("truncated window block header at offset " + pos);
            }
            int window = wire[pos] & 0xff;
            int bitmapLength = wire[pos + 1] & 0xff;
            // A repeated or out-of-order window would let a producer set a bit for a type twice, once in a block a
            // single-pass reader keeps and once in a block it has already moved past.
            if (window <= previousWindow) {
                throw new CorruptedFrameException("window block " + window + " does not follow window block "
                        + previousWindow + " in strictly ascending order");
            }
            if (bitmapLength < 1 || bitmapLength > MAX_BITMAP_LENGTH) {
                throw new CorruptedFrameException("window block " + window + " has a bitmap length of "
                        + bitmapLength + " (expected: 1 ~ " + MAX_BITMAP_LENGTH + ')');
            }
            if (pos + 2 + bitmapLength > wire.length) {
                throw new CorruptedFrameException("truncated bitmap in window block " + window);
            }
            if (++blocks > MAX_WINDOW_BLOCKS) {
                throw new CorruptedFrameException("type bit maps field has more than " + MAX_WINDOW_BLOCKS
                        + " window blocks");
            }
            int countBefore = count;
            for (int i = 0; i < bitmapLength; i++) {
                int octet = wire[pos + 2 + i] & 0xff;
                if (octet == 0) {
                    continue;
                }
                for (int bit = 0; bit < 8; bit++) {
                    if ((octet & (0x80 >>> bit)) != 0) {
                        if (count == types.length) {
                            types = Arrays.copyOf(types, types.length << 1);
                        }
                        types[count++] = (window << 8) + (i << 3) + bit;
                    }
                }
            }
            // RFC 4034 section 4.1.2 says blocks with no types present MUST NOT be included, and an all-zero block
            // carries no information at all, so accepting one only widens the shapes a producer may take.
            if (count == countBefore) {
                throw new CorruptedFrameException("window block " + window + " has an all-zero bitmap");
            }
            // Trailing zero octets inside a block MUST be omitted by the producer, but they are accepted here.
            // Rejecting them would turn a merely non-conforming encoder into a BOGUS answer for a whole zone, and
            // it buys nothing: the field is covered by the RRSIG over the record, and a trailing zero octet asserts
            // no type, so it can neither add nor hide one.
            previousWindow = window;
            pos += 2 + bitmapLength;
        }
        // Windows ascend and bits are visited from the lowest type upwards, so the types are already ascending.
        return count == types.length ? types : Arrays.copyOf(types, count);
    }
}
