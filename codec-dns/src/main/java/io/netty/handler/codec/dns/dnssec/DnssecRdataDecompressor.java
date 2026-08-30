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
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecordType;

/**
 * Expands the compressed domain names that may appear inside the {@code RDATA} of a handful of record types.
 * <p>
 * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-6.2">RFC 4034, section 6.2</a> builds the canonical
 * form of a record from expanded names, so a validator cannot verify a signature over a compressed {@code SOA} or
 * {@code MX} unless the {@code RDATA} has been expanded first.
 * <p>
 * Which types those are is fixed by
 * <a href="https://www.rfc-editor.org/rfc/rfc3597.html#section-4">RFC 3597, section 4</a>: the types defined
 * before it whose {@code RDATA} a sender was allowed to compress. Every other type, known or not, is passed
 * through untouched. That is not laziness, it is the rule: RFC 3597 forbids compression in the {@code RDATA} of
 * any other type, so an octet that looks like a compression pointer there is data. Expanding it would turn two
 * different wire encodings into the same canonical form, which is exactly the kind of collision a signature must
 * not have.
 * <p>
 * The set and the field positions both come from {@link DnssecRdataLayout}, which {@link DnssecCanonicalizer}
 * reads as well so that the expanded octets and the canonical octets cannot drift apart.
 */
final class DnssecRdataDecompressor {

    /**
     * The largest {@code RDLENGTH} that fits the 16-bit field of RFC 1035, section 3.2.1.
     */
    private static final int MAX_RDLENGTH = 0xffff;

    private DnssecRdataDecompressor() {
    }

    /**
     * Returns the {@code RDATA} of the record at {@code offset} with every embedded domain name expanded, or
     * {@code null} when the octets that are already there are the right ones and should be used as they stand.
     * <p>
     * {@code null} is returned when the type cannot hold a name, when it can but none of its names were actually
     * compressed, and when the {@code RDATA} does not match the layout of its type although nothing in it is
     * compressed. The last case keeps a malformed record that needs no expansion decodable: its octets are
     * already what a signature would have to cover, and refusing to decode the whole message over one broken
     * record in an additional section would be a poor trade.
     *
     * @param in         the buffer holding the whole message
     * @param offset     the absolute index the {@code RDATA} starts at
     * @param length     the length of the {@code RDATA}
     * @param messageEnd the absolute index one past the last octet of the message
     * @param type       the type of the record
     * @throws CorruptedFrameException if a name in the {@code RDATA} is compressed but cannot be expanded, which
     *                                 leaves no way to produce the record's canonical form
     */
    static ByteBuf decompress(ByteBuf in, int offset, int length, int messageEnd, DnsRecordType type) {
        final DnssecRdataLayout layout = DnssecRdataLayout.compressibleLayoutOf(type);
        if (layout == null) {
            return null;
        }
        final int end = offset + length;
        final int[] starts = new int[layout.nameCount];
        final int[] encodedLengths = new int[layout.nameCount];
        final DnsName[] names = new DnsName[layout.nameCount];
        boolean compressed = false;
        int pos = offset + layout.prefixLength;
        if (pos > end) {
            return abandon(type, compressed, "the RDATA is shorter than the fixed fields of its type");
        }
        for (int i = 0; i < layout.characterStrings; i++) {
            if (pos >= end) {
                return abandon(type, compressed, "the RDATA ends inside its character-strings");
            }
            pos += 1 + in.getUnsignedByte(pos);
            if (pos > end) {
                return abandon(type, compressed, "a character-string runs past the end of the RDATA");
            }
        }
        for (int i = 0; i < layout.nameCount; i++) {
            if (pos >= end) {
                return abandon(type, compressed, "the RDATA ends before one of its names");
            }
            final int encoded;
            final DnsName decoded;
            try {
                encoded = DnsName.encodedLength(in, pos, messageEnd);
                if (pos + encoded > end) {
                    // A name that reaches past the RDATA would be read out of the next record.
                    return abandon(type, compressed || isPointer(in, pos),
                            "a name runs past the end of the RDATA");
                }
                // encodedLength stops either at the root label, which it counts as one octet, or at a compression
                // pointer, which it counts as two. So the name was compressed exactly when its last two octets
                // are a pointer.
                compressed |= encoded >= 2 && isPointer(in, pos + encoded - 2);
                decoded = DnsName.decode(in, pos, messageEnd);
            } catch (CorruptedFrameException cause) {
                return abandon(type, compressed || isPointer(in, pos), cause.getMessage());
            }
            starts[i] = pos;
            encodedLengths[i] = encoded;
            names[i] = decoded;
            pos += encoded;
        }
        if (layout.tailLength != DnssecRdataLayout.TAIL_REST && end - pos != layout.tailLength) {
            return abandon(type, compressed, "the RDATA has " + (end - pos)
                    + " octets after its last name where its type has " + layout.tailLength);
        }
        if (!compressed) {
            return null;
        }
        int expandedLength = length;
        for (int i = 0; i < layout.nameCount; i++) {
            expandedLength += names[i].wireLength() - encodedLengths[i];
        }
        if (expandedLength > MAX_RDLENGTH) {
            throw new CorruptedFrameException(type.name() + " record expands to " + expandedLength
                    + " octets of RDATA, which no longer fits an RDLENGTH");
        }
        ByteBuf out = in.alloc().buffer(expandedLength);
        try {
            int src = offset;
            for (int i = 0; i < layout.nameCount; i++) {
                out.writeBytes(in, src, starts[i] - src);
                names[i].writeTo(out);
                src = starts[i] + encodedLengths[i];
            }
            out.writeBytes(in, src, end - src);
            return out;
        } catch (Throwable cause) {
            out.release();
            throw cause;
        }
    }

    private static boolean isPointer(ByteBuf in, int offset) {
        return (in.getUnsignedByte(offset) & 0xc0) == 0xc0;
    }

    /**
     * Gives up on expanding: harmless when nothing was compressed, fatal when something was, because then the
     * canonical form of the record cannot be produced at all and guessing at it would be worse than failing.
     */
    private static ByteBuf abandon(DnsRecordType type, boolean compressed, String reason) {
        if (compressed) {
            throw new CorruptedFrameException(type.name()
                    + " record has a compressed name in its RDATA that cannot be expanded: " + reason);
        }
        return null;
    }
}
