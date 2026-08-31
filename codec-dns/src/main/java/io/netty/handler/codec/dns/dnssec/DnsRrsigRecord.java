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
 * An {@code RRSIG} record, the signature over one RRset. See
 * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-3">RFC 4034, section 3</a>.
 * <p>
 * The {@code RDATA} is
 * <pre>
 * type covered (2 octets) | algorithm (1) | labels (1) | original TTL (4) | signature expiration (4)
 *   | signature inception (4) | key tag (2) | signer's name (a domain name) | signature (the rest of the RDATA)
 * </pre>
 * The signer's name must not be compressed, see
 * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-3.1.7">RFC 4034, section 3.1.7</a>; a compression
 * pointer there is rejected rather than expanded.
 * <p>
 * The fields are reported as they were read. Whether {@link #labels()} is consistent with the owner name, whether
 * the validity period covers now, and whether the signer is allowed to sign this name are all checks RFC 4035,
 * section 5.3.1 puts on a validator.
 */
public final class DnsRrsigRecord extends AbstractDnssecRecord {

    /**
     * Everything up to and including the key tag: 2 + 1 + 1 + 4 + 4 + 4 + 2 octets.
     */
    private static final int FIXED_LENGTH = 18;

    private final DnsRecordType typeCovered;
    private final DnssecAlgorithm algorithm;
    private final int labels;
    private final long originalTtl;
    private final long expiration;
    private final long inception;
    private final int keyTag;
    private final DnsName signerName;
    private final byte[] signature;

    /**
     * Creates a new record by parsing {@code content} as {@code RRSIG} {@code RDATA}.
     *
     * @param name       the owner name as text, as {@link io.netty.handler.codec.dns.DnsRecord#name()} reports it
     * @param type       {@link DnsRecordType#RRSIG}
     * @param dnsClass   the class of the record
     * @param timeToLive the TTL of the record
     * @param owner      the wire form of the owner name
     * @param content    the {@code RDATA}; the record takes ownership of it and never modifies its indexes
     * @throws io.netty.handler.codec.CorruptedFrameException if a field runs past the end of the {@code RDATA}, or
     *                                                        if the signer's name is compressed
     */
    public DnsRrsigRecord(String name, DnsRecordType type, int dnsClass, long timeToLive, DnsName owner,
                          ByteBuf content) {
        super(name, checkType(type, DnsRecordType.RRSIG), dnsClass, timeToLive, owner, content);
        final int offset = content.readerIndex();
        final int end = content.writerIndex();
        DnssecCodecUtil.checkRemaining(type, "fixed fields", offset, FIXED_LENGTH, end);
        typeCovered = DnsRecordType.valueOf(content.getUnsignedShort(offset));
        algorithm = DnssecAlgorithm.valueOf(content.getUnsignedByte(offset + 2));
        labels = content.getUnsignedByte(offset + 3);
        originalTtl = content.getUnsignedInt(offset + 4);
        expiration = content.getUnsignedInt(offset + 8);
        inception = content.getUnsignedInt(offset + 12);
        keyTag = content.getUnsignedShort(offset + 16);
        signerName = DnssecCodecUtil.decodeUncompressedName(
                content, offset + FIXED_LENGTH, end, type, "signer's name");
        int signatureOffset = offset + FIXED_LENGTH + signerName.wireLength();
        signature = DnssecCodecUtil.readBytes(content, signatureOffset, end - signatureOffset);
    }

    /**
     * Reuses the fields already parsed from {@code record}: re-parsing a buffer a caller has read from would
     * fail, and {@code duplicate()} shares this record's reference count, so releasing on that failure would
     * free a buffer this record still holds.
     */
    private DnsRrsigRecord(DnsRrsigRecord record, ByteBuf content) {
        super(record.name(), record.type(), record.dnsClass(), record.timeToLive(), record.owner(), content);
        typeCovered = record.typeCovered;
        algorithm = record.algorithm;
        labels = record.labels;
        originalTtl = record.originalTtl;
        expiration = record.expiration;
        inception = record.inception;
        keyTag = record.keyTag;
        signerName = record.signerName;
        signature = record.signature;
    }

    /**
     * Returns the RR type of the RRset this signature covers.
     */
    public DnsRecordType typeCovered() {
        return typeCovered;
    }

    /**
     * Returns the algorithm the signature was made with.
     */
    public DnssecAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the Labels field: the number of labels in the original owner name of the covered RRset, not counting
     * the root and not counting a leading {@code *}. A validator compares it with the owner name to find out
     * whether the answer came from a wildcard, see
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.3.2">RFC 4035, section 5.3.2</a>.
     */
    public int labels() {
        return labels;
    }

    /**
     * Returns the Original TTL field as an unsigned 32-bit value. Signature verification uses this rather than the
     * TTL the record arrived with, because a cache decrements the latter.
     */
    public long originalTtl() {
        return originalTtl;
    }

    /**
     * Returns the Signature Expiration field, in seconds since 1 January 1970 UTC, as an unsigned 32-bit value.
     * <p>
     * RFC 4034, section 3.1.5 defines these timestamps to be compared using the serial number arithmetic of
     * <a href="https://www.rfc-editor.org/rfc/rfc1982.html">RFC 1982</a> rather than as plain integers, so that they
     * keep working past 2106. Comparing them with {@code &lt;} is wrong near the wrap-around.
     */
    public long expiration() {
        return expiration;
    }

    /**
     * Returns the Signature Inception field, in seconds since 1 January 1970 UTC, as an unsigned 32-bit value. See
     * {@link #expiration()} for how these are compared.
     */
    public long inception() {
        return inception;
    }

    /**
     * Returns the key tag of the {@code DNSKEY} that is supposed to have made this signature. Key tags are not
     * unique, so a validator has to try every key in the signer's RRset whose tag and algorithm match.
     */
    public int keyTag() {
        return keyTag;
    }

    /**
     * Returns the Signer's Name field, the owner name of the {@code DNSKEY} RRset that verifies this signature.
     */
    public DnsName signerName() {
        return signerName;
    }

    /**
     * Returns the Signature field, in the algorithm-specific encoding described by RFC 4034, section 3.1.8. Use
     * {@link DnssecSignatures} to turn it into the form the JDK expects.
     * <p>
     * The array is not copied; do not modify it.
     */
    public byte[] signature() {
        return signature;
    }

    @Override
    public DnsRrsigRecord copy() {
        return new DnsRrsigRecord(this, content().copy());
    }

    @Override
    public DnsRrsigRecord duplicate() {
        return new DnsRrsigRecord(this, content().duplicate());
    }

    @Override
    public DnsRrsigRecord retainedDuplicate() {
        return new DnsRrsigRecord(this, content().retainedDuplicate());
    }

    @Override
    public DnsRrsigRecord replace(ByteBuf content) {
        try {
            return new DnsRrsigRecord(name(), type(), dnsClass(), timeToLive(), owner(), content);
        } catch (Throwable cause) {
            content.release();
            throw cause;
        }
    }

    @Override
    public DnsRrsigRecord retain() {
        super.retain();
        return this;
    }

    @Override
    public DnsRrsigRecord retain(int increment) {
        super.retain(increment);
        return this;
    }

    @Override
    public DnsRrsigRecord touch() {
        super.touch();
        return this;
    }

    @Override
    public DnsRrsigRecord touch(Object hint) {
        super.touch(hint);
        return this;
    }
}
