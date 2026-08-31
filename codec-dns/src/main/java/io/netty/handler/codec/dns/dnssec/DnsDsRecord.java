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
 * A {@code DS} record, the delegation signer that links a parent zone to a child's {@code DNSKEY}. See
 * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-5">RFC 4034, section 5</a>.
 * <p>
 * The {@code RDATA} is
 * <pre>
 * key tag (2 octets) | algorithm (1) | digest type (1) | digest (the rest of the RDATA)
 * </pre>
 * The same layout is used by {@code CDS},
 * <a href="https://www.rfc-editor.org/rfc/rfc7344.html#section-3.1">RFC 7344, section 3.1</a>, which this class also
 * represents.
 * <p>
 * The digest is not checked against the length its digest type implies. A digest of the wrong length simply does not
 * match any {@code DNSKEY}, and rejecting it here would make the length check depend on whether this implementation
 * happens to know the digest type.
 */
public final class DnsDsRecord extends AbstractDnssecRecord {

    /**
     * key tag (2 octets), algorithm (1) and digest type (1).
     */
    private static final int FIXED_LENGTH = 4;

    private final int keyTag;
    private final DnssecAlgorithm algorithm;
    private final DnssecDigestType digestType;
    private final byte[] digest;

    /**
     * Creates a new record by parsing {@code content} as {@code DS} {@code RDATA}.
     *
     * @param name       the owner name as text, as {@link io.netty.handler.codec.dns.DnsRecord#name()} reports it
     * @param type       {@link DnsRecordType#DS} or {@link DnsRecordType#CDS}
     * @param dnsClass   the class of the record
     * @param timeToLive the TTL of the record
     * @param owner      the wire form of the owner name
     * @param content    the {@code RDATA}; the record takes ownership of it and never modifies its indexes
     * @throws io.netty.handler.codec.CorruptedFrameException if the {@code RDATA} is shorter than the four octets
     *                                                        the fixed fields need
     */
    public DnsDsRecord(String name, DnsRecordType type, int dnsClass, long timeToLive, DnsName owner,
                       ByteBuf content) {
        super(name, checkType(type, DnsRecordType.DS, DnsRecordType.CDS), dnsClass, timeToLive, owner, content);
        final int offset = content.readerIndex();
        final int end = content.writerIndex();
        DnssecCodecUtil.checkRemaining(type, "fixed fields", offset, FIXED_LENGTH, end);
        keyTag = content.getUnsignedShort(offset);
        algorithm = DnssecAlgorithm.valueOf(content.getUnsignedByte(offset + 2));
        digestType = DnssecDigestType.valueOf(content.getUnsignedByte(offset + 3));
        digest = DnssecCodecUtil.readBytes(content, offset + FIXED_LENGTH, end - offset - FIXED_LENGTH);
    }

    /**
     * Reuses the fields already parsed from {@code record}: re-parsing a buffer a caller has read from would
     * fail, and {@code duplicate()} shares this record's reference count, so releasing on that failure would
     * free a buffer this record still holds.
     */
    private DnsDsRecord(DnsDsRecord record, ByteBuf content) {
        super(record.name(), record.type(), record.dnsClass(), record.timeToLive(), record.owner(), content);
        keyTag = record.keyTag;
        algorithm = record.algorithm;
        digestType = record.digestType;
        digest = record.digest;
    }

    /**
     * Returns the key tag of the {@code DNSKEY} this record refers to. It is only a hint: RFC 4034, appendix B
     * warns that key tags are not unique, so a validator must try every key whose tag and algorithm match.
     */
    public int keyTag() {
        return keyTag;
    }

    /**
     * Returns the algorithm of the {@code DNSKEY} this record refers to.
     */
    public DnssecAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the algorithm the {@link #digest()} was computed with.
     */
    public DnssecDigestType digestType() {
        return digestType;
    }

    /**
     * Returns the Digest field, which RFC 4034, section 5.1.4 defines as the digest of
     * {@code owner name in canonical form || DNSKEY RDATA}.
     * <p>
     * The array is not copied; do not modify it.
     */
    public byte[] digest() {
        return digest;
    }

    @Override
    public DnsDsRecord copy() {
        return new DnsDsRecord(this, content().copy());
    }

    @Override
    public DnsDsRecord duplicate() {
        return new DnsDsRecord(this, content().duplicate());
    }

    @Override
    public DnsDsRecord retainedDuplicate() {
        return new DnsDsRecord(this, content().retainedDuplicate());
    }

    @Override
    public DnsDsRecord replace(ByteBuf content) {
        try {
            return new DnsDsRecord(name(), type(), dnsClass(), timeToLive(), owner(), content);
        } catch (Throwable cause) {
            content.release();
            throw cause;
        }
    }

    @Override
    public DnsDsRecord retain() {
        super.retain();
        return this;
    }

    @Override
    public DnsDsRecord retain(int increment) {
        super.retain(increment);
        return this;
    }

    @Override
    public DnsDsRecord touch() {
        super.touch();
        return this;
    }

    @Override
    public DnsDsRecord touch(Object hint) {
        super.touch(hint);
        return this;
    }
}
