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
 * A {@code DNSKEY} record, see
 * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-2">RFC 4034, section 2</a>.
 * <p>
 * The {@code RDATA} is
 * <pre>
 * flags (2 octets) | protocol (1) | algorithm (1) | public key (the rest of the RDATA)
 * </pre>
 * The same layout is used by {@code CDNSKEY},
 * <a href="https://www.rfc-editor.org/rfc/rfc7344.html#section-3.2">RFC 7344, section 3.2</a>, which this class also
 * represents.
 * <p>
 * Nothing beyond the layout is enforced. In particular a {@code protocol} other than the {@code 3} that RFC 4034,
 * section 2.1.2 mandates is decoded and reported rather than rejected, because that section makes it a reason to
 * treat the key as invalid <em>during signature verification</em>, which is a decision for a validator and not for a
 * decoder.
 */
public final class DnsDnskeyRecord extends AbstractDnssecRecord {

    /**
     * The Zone Key flag, bit 7 of the Flags field. See
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-2.1.1">RFC 4034, section 2.1.1</a>.
     */
    public static final int FLAG_ZONE_KEY = 0x0100;

    /**
     * The Secure Entry Point flag, bit 15 of the Flags field. See
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-2.1.1">RFC 4034, section 2.1.1</a> and
     * <a href="https://www.rfc-editor.org/rfc/rfc3757.html">RFC 3757</a>.
     */
    public static final int FLAG_SECURE_ENTRY_POINT = 0x0001;

    /**
     * The REVOKE flag, bit 8 of the Flags field. See
     * <a href="https://www.rfc-editor.org/rfc/rfc5011.html#section-2.1">RFC 5011, section 2.1</a>.
     */
    public static final int FLAG_REVOKE = 0x0080;

    /**
     * flags (2 octets), protocol (1) and algorithm (1).
     */
    private static final int FIXED_LENGTH = 4;

    private final int flags;
    private final int protocol;
    private final DnssecAlgorithm algorithm;
    private final byte[] publicKey;
    private int keyTag = -1;

    /**
     * Creates a new record by parsing {@code content} as {@code DNSKEY} {@code RDATA}.
     *
     * @param name       the owner name as text, as {@link io.netty.handler.codec.dns.DnsRecord#name()} reports it
     * @param type       {@link DnsRecordType#DNSKEY} or {@link DnsRecordType#CDNSKEY}
     * @param dnsClass   the class of the record
     * @param timeToLive the TTL of the record
     * @param owner      the wire form of the owner name
     * @param content    the {@code RDATA}; the record takes ownership of it and never modifies its indexes
     * @throws io.netty.handler.codec.CorruptedFrameException if the {@code RDATA} is shorter than the four octets
     *                                                        the fixed fields need
     */
    public DnsDnskeyRecord(String name, DnsRecordType type, int dnsClass, long timeToLive, DnsName owner,
                           ByteBuf content) {
        super(name, checkType(type, DnsRecordType.DNSKEY, DnsRecordType.CDNSKEY), dnsClass, timeToLive, owner,
                content);
        final int offset = content.readerIndex();
        final int end = content.writerIndex();
        DnssecCodecUtil.checkRemaining(type, "fixed fields", offset, FIXED_LENGTH, end);
        flags = content.getUnsignedShort(offset);
        protocol = content.getUnsignedByte(offset + 2);
        algorithm = DnssecAlgorithm.valueOf(content.getUnsignedByte(offset + 3));
        publicKey = DnssecCodecUtil.readBytes(content, offset + FIXED_LENGTH, end - offset - FIXED_LENGTH);
    }

    /**
     * Returns the 16-bit Flags field. Bits other than {@link #FLAG_ZONE_KEY}, {@link #FLAG_SECURE_ENTRY_POINT} and
     * {@link #FLAG_REVOKE} are reserved and, per RFC 4034, section 2.1.1, must be ignored; they are reported here
     * unchanged because they are covered by any {@code RRSIG} over this record.
     */
    public int flags() {
        return flags;
    }

    /**
     * Returns the 8-bit Protocol field, which RFC 4034, section 2.1.2 requires to be {@code 3}.
     */
    public int protocol() {
        return protocol;
    }

    /**
     * Returns the algorithm this key is for.
     */
    public DnssecAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the Public Key field, in the algorithm-specific encoding described by RFC 4034, section 2.1.4. Use
     * {@link DnssecPublicKeys} to turn it into a {@link java.security.PublicKey}.
     * <p>
     * The array is not copied; do not modify it.
     */
    public byte[] publicKey() {
        return publicKey;
    }

    /**
     * Returns the key tag of this key, as computed by
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#appendix-B">RFC 4034, appendix B</a>. This is the value
     * a {@code DS} or an {@code RRSIG} refers to; it identifies a key only approximately, so a validator has to be
     * prepared for more than one key in an RRset to carry the same tag.
     *
     * @throws DnssecUnsupportedAlgorithmException if the algorithm is {@link DnssecAlgorithm#RSAMD5}, whose key tag
     *                                             is computed differently and is not implemented
     */
    public int keyTag() {
        int tag = keyTag;
        if (tag < 0) {
            keyTag = tag = DnssecKeyTag.compute(flags, protocol, algorithm, publicKey);
        }
        return tag;
    }

    /**
     * Returns {@code true} if the Zone Key flag is set, which means the key signs the zone's RRsets. RFC 4035,
     * section 5.3.1 requires a validator to reject an {@code RRSIG} made by a key that does not have this set.
     */
    public boolean isZoneKey() {
        return (flags & FLAG_ZONE_KEY) != 0;
    }

    /**
     * Returns {@code true} if the Secure Entry Point flag is set. This is a hint that the key is used as the entry
     * point of the zone, and RFC 4034, section 2.1.1 explicitly says it must not be used to decide anything during
     * validation.
     */
    public boolean isSecureEntryPoint() {
        return (flags & FLAG_SECURE_ENTRY_POINT) != 0;
    }

    /**
     * Returns {@code true} if the REVOKE flag is set. A revoked key must not be used to validate anything, and RFC
     * 5011, section 2.1 notes that setting the bit changes the key tag, so a revoked key is not the key its
     * unrevoked {@code DS} refers to.
     */
    public boolean isRevoked() {
        return (flags & FLAG_REVOKE) != 0;
    }

    @Override
    public DnsDnskeyRecord copy() {
        return replace(content().copy());
    }

    @Override
    public DnsDnskeyRecord duplicate() {
        return replace(content().duplicate());
    }

    @Override
    public DnsDnskeyRecord retainedDuplicate() {
        return replace(content().retainedDuplicate());
    }

    @Override
    public DnsDnskeyRecord replace(ByteBuf content) {
        try {
            return new DnsDnskeyRecord(name(), type(), dnsClass(), timeToLive(), owner(), content);
        } catch (Throwable cause) {
            content.release();
            throw cause;
        }
    }

    @Override
    public DnsDnskeyRecord retain() {
        super.retain();
        return this;
    }

    @Override
    public DnsDnskeyRecord retain(int increment) {
        super.retain(increment);
        return this;
    }

    @Override
    public DnsDnskeyRecord touch() {
        super.touch();
        return this;
    }

    @Override
    public DnsDnskeyRecord touch(Object hint) {
        super.touch(hint);
        return this;
    }
}
