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
 * An {@code NSEC3PARAM} record, which publishes at a zone apex the parameters its {@code NSEC3} records are
 * generated with. See <a href="https://www.rfc-editor.org/rfc/rfc5155.html#section-4">RFC 5155, section 4</a>.
 * <p>
 * The {@code RDATA} is
 * <pre>
 * hash algorithm (1 octet) | flags (1) | iterations (2) | salt length (1) | salt (salt length)
 * </pre>
 * which is an {@code NSEC3} without the hash and without the type bit maps. Every field has a declared length, so
 * anything after the salt is a malformed record rather than something to ignore.
 */
public final class DnsNsec3ParamRecord extends AbstractDnssecRecord {

    /**
     * hash algorithm (1 octet), flags (1), iterations (2) and salt length (1).
     */
    private static final int FIXED_LENGTH = 5;

    private final int hashAlgorithm;
    private final int flags;
    private final int iterations;
    private final byte[] salt;

    /**
     * Creates a new record by parsing {@code content} as {@code NSEC3PARAM} {@code RDATA}.
     *
     * @param name       the owner name as text, as {@link io.netty.handler.codec.dns.DnsRecord#name()} reports it
     * @param type       {@link DnsRecordType#NSEC3PARAM}
     * @param dnsClass   the class of the record
     * @param timeToLive the TTL of the record
     * @param owner      the wire form of the owner name
     * @param content    the {@code RDATA}; the record takes ownership of it and never modifies its indexes
     * @throws io.netty.handler.codec.CorruptedFrameException if a field runs past the end of the {@code RDATA}, or
     *                                                        if there are octets left after the salt
     */
    public DnsNsec3ParamRecord(String name, DnsRecordType type, int dnsClass, long timeToLive, DnsName owner,
                               ByteBuf content) {
        super(name, checkType(type, DnsRecordType.NSEC3PARAM), dnsClass, timeToLive, owner, content);
        final int offset = content.readerIndex();
        final int end = content.writerIndex();
        DnssecCodecUtil.checkRemaining(type, "fixed fields", offset, FIXED_LENGTH, end);
        hashAlgorithm = content.getUnsignedByte(offset);
        flags = content.getUnsignedByte(offset + 1);
        iterations = content.getUnsignedShort(offset + 2);
        int saltLength = content.getUnsignedByte(offset + 4);
        int pos = offset + FIXED_LENGTH;
        DnssecCodecUtil.checkRemaining(type, "salt", pos, saltLength, end);
        salt = DnssecCodecUtil.readBytes(content, pos, saltLength);
        DnssecCodecUtil.checkFullyConsumed(type, pos + saltLength, end);
    }

    /**
     * Reuses the fields already parsed from {@code record}: re-parsing a buffer a caller has read from would
     * fail, and {@code duplicate()} shares this record's reference count, so releasing on that failure would
     * free a buffer this record still holds.
     */
    private DnsNsec3ParamRecord(DnsNsec3ParamRecord record, ByteBuf content) {
        super(record.name(), record.type(), record.dnsClass(), record.timeToLive(), record.owner(), content);
        hashAlgorithm = record.hashAlgorithm;
        flags = record.flags;
        iterations = record.iterations;
        salt = record.salt;
    }

    /**
     * Returns the Hash Algorithm field. RFC 5155 defines only {@code 1}, SHA-1.
     */
    public int hashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Returns the 8-bit Flags field. RFC 5155, section 4.1.2 requires it to be zero and tells a server to ignore an
     * {@code NSEC3PARAM} whose flags are not; in particular the Opt-Out flag is not used here.
     */
    public int flags() {
        return flags;
    }

    /**
     * Returns the Iterations field: how many extra times the hash is applied when hashing an owner name in this
     * zone.
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

    @Override
    public DnsNsec3ParamRecord copy() {
        return new DnsNsec3ParamRecord(this, content().copy());
    }

    @Override
    public DnsNsec3ParamRecord duplicate() {
        return new DnsNsec3ParamRecord(this, content().duplicate());
    }

    @Override
    public DnsNsec3ParamRecord retainedDuplicate() {
        return new DnsNsec3ParamRecord(this, content().retainedDuplicate());
    }

    @Override
    public DnsNsec3ParamRecord replace(ByteBuf content) {
        try {
            return new DnsNsec3ParamRecord(name(), type(), dnsClass(), timeToLive(), owner(), content);
        } catch (Throwable cause) {
            content.release();
            throw cause;
        }
    }

    @Override
    public DnsNsec3ParamRecord retain() {
        super.retain();
        return this;
    }

    @Override
    public DnsNsec3ParamRecord retain(int increment) {
        super.retain(increment);
        return this;
    }

    @Override
    public DnsNsec3ParamRecord touch() {
        super.touch();
        return this;
    }

    @Override
    public DnsNsec3ParamRecord touch(Object hint) {
        super.touch(hint);
        return this;
    }
}
