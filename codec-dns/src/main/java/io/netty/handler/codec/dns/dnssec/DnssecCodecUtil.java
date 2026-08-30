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
import io.netty.util.internal.EmptyArrays;

/**
 * Bounds-checked readers for the fields of a DNSSEC {@code RDATA}.
 */
final class DnssecCodecUtil {

    private DnssecCodecUtil() {
    }

    /**
     * Verifies that a field of {@code needed} octets starting at {@code offset} fits inside the {@code RDATA}, which
     * ends at {@code end}.
     * <p>
     * A field that does not fit is always a hard error. Truncating the record instead and reporting the fields that
     * did fit would hand a validator a record that no signature covers, and silently dropping the record would turn
     * a corrupt answer into a missing one.
     */
    static void checkRemaining(DnsRecordType type, String field, int offset, int needed, int end) {
        int remaining = end - offset;
        if (needed > remaining) {
            throw new CorruptedFrameException(type.name() + " record is truncated in its " + field + ": " + needed
                    + " octets are needed but the RDATA has " + remaining + " left");
        }
    }

    /**
     * Verifies that the {@code RDATA} ends exactly at {@code offset}.
     * <p>
     * Only for layouts whose last field has a declared length. Octets after it are not padding to be ignored: they
     * are covered by the {@code RRSIG} over this record, so a reader that skips them and a reader that does not
     * would disagree about what a single signature signs.
     */
    static void checkFullyConsumed(DnsRecordType type, int offset, int end) {
        if (offset != end) {
            throw new CorruptedFrameException(type.name() + " record has " + (end - offset)
                    + " octets of trailing data after its last field");
        }
    }

    /**
     * Copies {@code length} octets out of {@code in}, starting at the absolute index {@code offset}. Neither index
     * of {@code in} is modified.
     */
    static byte[] readBytes(ByteBuf in, int offset, int length) {
        if (length == 0) {
            return EmptyArrays.EMPTY_BYTES;
        }
        byte[] bytes = new byte[length];
        in.getBytes(offset, bytes);
        return bytes;
    }

    /**
     * Decodes the domain name at {@code offset}, which must not be compressed, and must end at or before
     * {@code end}. Neither index of {@code in} is modified.
     * <p>
     * The {@code RRSIG} Signer's Name of
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-3.1.7">RFC 4034, section 3.1.7</a> and the
     * {@code NSEC} Next Domain Name of
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-4.1.1">section 4.1.1</a> are both required to be
     * uncompressed, as is any name in the {@code RDATA} of a type an implementation does not know, per
     * <a href="https://www.rfc-editor.org/rfc/rfc3597.html#section-4">RFC 3597, section 4</a>. A compression
     * pointer here is rejected rather than expanded: two different encodings that expand to the same name would
     * otherwise both be accepted for a single signature, which lets an attacker rewrite the octets of signed
     * {@code RDATA} while keeping the signature valid.
     *
     * @throws CorruptedFrameException if the name is truncated, compressed, or uses a reserved label type
     */
    static DnsName decodeUncompressedName(ByteBuf in, int offset, int end, DnsRecordType type, String field) {
        int pos = offset;
        for (;;) {
            if (pos >= end) {
                throw new CorruptedFrameException(type.name() + " record is truncated in its " + field);
            }
            int length = in.getUnsignedByte(pos);
            int labelType = length & 0xc0;
            if (labelType == 0xc0) {
                throw new CorruptedFrameException(type.name() + " record has a compressed " + field
                        + " at offset " + pos + ", which RFC 4034 does not allow");
            }
            if (labelType != 0) {
                throw new CorruptedFrameException(type.name() + " record has a reserved label type 0x"
                        + Integer.toHexString(labelType) + " in its " + field + " at offset " + pos);
            }
            pos += 1 + length;
            if (length == 0) {
                break;
            }
        }
        // The loop above is what rejects compression: it refuses every pointer before this line is reached.
        // DnsName.decode does not repeat that check, and its own rule that a pointer must point strictly
        // backwards has no lower bound at offset, so a pointer that got past the loop could still resolve to an
        // earlier octet of the message. Passing pos rather than end only stops a malformed name from reading past
        // its own terminator; do not weaken the loop on the assumption that this call re-checks anything.
        return DnsName.decode(in, offset, pos);
    }
}
