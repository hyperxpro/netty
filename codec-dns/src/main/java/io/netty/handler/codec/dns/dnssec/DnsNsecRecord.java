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
 * An {@code NSEC} record, one link of the chain that proves what does not exist in a zone. See
 * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-4">RFC 4034, section 4</a>.
 * <p>
 * The {@code RDATA} is
 * <pre>
 * next domain name (a domain name) | type bit maps (the rest of the RDATA)
 * </pre>
 * The next domain name must not be compressed, see
 * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-4.1.1">RFC 4034, section 4.1.1</a>; a compression
 * pointer there is rejected rather than expanded. It is also not down-cased, because
 * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.1">RFC 6840, section 5.1</a> removed the
 * down-casing of names embedded in {@code RDATA} that RFC 4034, section 6.2 had required.
 */
public final class DnsNsecRecord extends AbstractDnssecRecord {

    private final DnsName nextDomainName;
    private final DnsTypeBitmap types;

    /**
     * Creates a new record by parsing {@code content} as {@code NSEC} {@code RDATA}.
     *
     * @param name       the owner name as text, as {@link io.netty.handler.codec.dns.DnsRecord#name()} reports it
     * @param type       {@link DnsRecordType#NSEC}
     * @param dnsClass   the class of the record
     * @param timeToLive the TTL of the record
     * @param owner      the wire form of the owner name
     * @param content    the {@code RDATA}; the record takes ownership of it and never modifies its indexes
     * @throws io.netty.handler.codec.CorruptedFrameException if the next domain name is truncated or compressed, or
     *                                                        if the type bit maps field is malformed
     */
    public DnsNsecRecord(String name, DnsRecordType type, int dnsClass, long timeToLive, DnsName owner,
                         ByteBuf content) {
        super(name, checkType(type, DnsRecordType.NSEC), dnsClass, timeToLive, owner, content);
        final int offset = content.readerIndex();
        final int end = content.writerIndex();
        nextDomainName = DnssecCodecUtil.decodeUncompressedName(content, offset, end, type, "next domain name");
        int bitmapOffset = offset + nextDomainName.wireLength();
        types = DnsTypeBitmap.decode(content.slice(bitmapOffset, end - bitmapOffset), end - bitmapOffset);
    }

    /**
     * Returns the Next Domain Name field: the owner name of the next RRset in the zone, in canonical order. In the
     * last {@code NSEC} of a zone this is the apex, which is how the chain closes.
     */
    public DnsName nextDomainName() {
        return nextDomainName;
    }

    /**
     * Returns the Type Bit Maps field: the RR types that exist at this record's owner name.
     * <p>
     * RFC 4034, section 4.1.2 writes the field as one or more blocks, so an {@code NSEC} with no block at all is
     * outside the grammar. It is accepted here and reported as {@link DnsTypeBitmap#EMPTY}, because a validator has
     * to test for the specific bits it cares about anyway and an empty bitmap asserts none of them.
     */
    public DnsTypeBitmap types() {
        return types;
    }

    @Override
    public DnsNsecRecord copy() {
        return replace(content().copy());
    }

    @Override
    public DnsNsecRecord duplicate() {
        return replace(content().duplicate());
    }

    @Override
    public DnsNsecRecord retainedDuplicate() {
        return replace(content().retainedDuplicate());
    }

    @Override
    public DnsNsecRecord replace(ByteBuf content) {
        try {
            return new DnsNsecRecord(name(), type(), dnsClass(), timeToLive(), owner(), content);
        } catch (Throwable cause) {
            content.release();
            throw cause;
        }
    }

    @Override
    public DnsNsecRecord retain() {
        super.retain();
        return this;
    }

    @Override
    public DnsNsecRecord retain(int increment) {
        super.retain(increment);
        return this;
    }

    @Override
    public DnsNsecRecord touch() {
        super.touch();
        return this;
    }

    @Override
    public DnsNsecRecord touch(Object hint) {
        super.touch(hint);
        return this;
    }
}
