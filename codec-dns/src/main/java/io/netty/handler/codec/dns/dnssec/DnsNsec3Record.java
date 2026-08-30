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
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecordType;

/**
 * An {@code NSEC3} record, one link of the hashed chain that proves what does not exist in a zone without
 * disclosing what does. See <a href="https://www.rfc-editor.org/rfc/rfc5155.html#section-3">RFC 5155, section 3</a>.
 * <p>
 * The {@code RDATA} is
 * <pre>
 * hash algorithm (1 octet) | flags (1) | iterations (2) | salt length (1) | salt (salt length)
 *   | hash length (1) | next hashed owner name (hash length) | type bit maps (the rest of the RDATA)
 * </pre>
 * Unlike the owner name of the record, the next hashed owner name is the raw hash, not base32hex text, and it does
 * not carry the zone name.
 */
public final class DnsNsec3Record extends AbstractDnssecRecord {

    /**
     * The Opt-Out flag, the least significant bit of the Flags field. See
     * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#section-3.1.2.1">RFC 5155, section 3.1.2.1</a>.
     */
    public static final int FLAG_OPT_OUT = 0x01;

    /**
     * hash algorithm (1 octet), flags (1), iterations (2) and salt length (1).
     */
    private static final int FIXED_LENGTH = 5;

    private final int hashAlgorithm;
    private final int flags;
    private final int iterations;
    private final byte[] salt;
    private final byte[] nextHashedOwnerName;
    private final DnsTypeBitmap types;

    /**
     * Creates a new record by parsing {@code content} as {@code NSEC3} {@code RDATA}.
     *
     * @param name       the owner name as text, as {@link io.netty.handler.codec.dns.DnsRecord#name()} reports it
     * @param type       {@link DnsRecordType#NSEC3}
     * @param dnsClass   the class of the record
     * @param timeToLive the TTL of the record
     * @param owner      the wire form of the owner name
     * @param content    the {@code RDATA}; the record takes ownership of it and never modifies its indexes
     * @throws io.netty.handler.codec.CorruptedFrameException if a field runs past the end of the {@code RDATA} or
     *                                                        if the type bit maps field is malformed
     */
    public DnsNsec3Record(String name, DnsRecordType type, int dnsClass, long timeToLive, DnsName owner,
                          ByteBuf content) {
        super(name, checkType(type, DnsRecordType.NSEC3), dnsClass, timeToLive, owner, content);
        final int offset = content.readerIndex();
        final int end = content.writerIndex();
        DnssecCodecUtil.checkRemaining(type, "fixed fields", offset, FIXED_LENGTH, end);
        hashAlgorithm = content.getUnsignedByte(offset);
        flags = content.getUnsignedByte(offset + 1);
        iterations = content.getUnsignedShort(offset + 2);
        // The salt length is a single octet, so it is always 0 to 255; what has to be checked is that that many
        // octets are actually there.
        int saltLength = content.getUnsignedByte(offset + 4);
        int pos = offset + FIXED_LENGTH;
        DnssecCodecUtil.checkRemaining(type, "salt", pos, saltLength, end);
        salt = DnssecCodecUtil.readBytes(content, pos, saltLength);
        pos += saltLength;
        DnssecCodecUtil.checkRemaining(type, "hash length", pos, 1, end);
        int hashLength = content.getUnsignedByte(pos);
        pos++;
        DnssecCodecUtil.checkRemaining(type, "next hashed owner name", pos, hashLength, end);
        nextHashedOwnerName = DnssecCodecUtil.readBytes(content, pos, hashLength);
        pos += hashLength;
        types = DnsTypeBitmap.decode(content.slice(pos, end - pos), end - pos);
    }

    /**
     * Returns the Hash Algorithm field. RFC 5155 defines only {@code 1}, SHA-1.
     */
    public int hashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Returns the 8-bit Flags field. Every bit other than {@link #FLAG_OPT_OUT} is reserved and must be zero.
     */
    public int flags() {
        return flags;
    }

    /**
     * Returns {@code true} if the Opt-Out flag is set, which means this record may cover unsigned delegations and
     * therefore does <em>not</em> prove that the names it spans do not exist. See
     * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#section-6">RFC 5155, section 6</a>.
     */
    public boolean isOptOut() {
        return (flags & FLAG_OPT_OUT) != 0;
    }

    /**
     * Returns the Iterations field: how many extra times the hash is applied.
     * <a href="https://www.rfc-editor.org/rfc/rfc9276.html#section-3.1">RFC 9276, section 3.1</a> recommends that a
     * validator treat a large value as insecure rather than spend the work, and that zones use {@code 0}.
     */
    public int iterations() {
        return iterations;
    }

    /**
     * Returns the Salt field, which is empty when the Salt Length is zero.
     * <p>
     * The array is not copied; do not modify it.
     */
    public byte[] salt() {
        return salt;
    }

    /**
     * Returns the Next Hashed Owner Name field: the raw hash of the next owner name in hash order, without the zone
     * name and without base32hex encoding.
     * <p>
     * The array is not copied; do not modify it.
     */
    public byte[] nextHashedOwnerName() {
        return nextHashedOwnerName;
    }

    /**
     * Returns the Type Bit Maps field: the RR types that exist at the original owner name this record hashes.
     * <p>
     * An empty field is legal and means the record matches an empty non-terminal:
     * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-6.4">RFC 6840, section 6.4</a> corrects the
     * grammar of RFC 5155, section 3.2.1 from one-or-more blocks to zero-or-more for exactly that case.
     */
    public DnsTypeBitmap types() {
        return types;
    }

    @Override
    public DnsNsec3Record copy() {
        return replace(content().copy());
    }

    @Override
    public DnsNsec3Record duplicate() {
        return replace(content().duplicate());
    }

    @Override
    public DnsNsec3Record retainedDuplicate() {
        return replace(content().retainedDuplicate());
    }

    @Override
    public DnsNsec3Record replace(ByteBuf content) {
        try {
            return new DnsNsec3Record(name(), type(), dnsClass(), timeToLive(), owner(), content);
        } catch (Throwable cause) {
            content.release();
            throw cause;
        }
    }

    @Override
    public DnsNsec3Record retain() {
        super.retain();
        return this;
    }

    @Override
    public DnsNsec3Record retain(int increment) {
        super.retain(increment);
        return this;
    }

    @Override
    public DnsNsec3Record touch() {
        super.touch();
        return this;
    }

    @Override
    public DnsNsec3Record touch(Object hint) {
        super.touch(hint);
        return this;
    }
}
