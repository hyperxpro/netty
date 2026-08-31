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
 * A {@link DnssecRecord} for a record type this package does not parse into fields: it carries the owner name's
 * wire form beside an undecoded {@code RDATA}.
 * <p>
 * This exists because an {@code RRSIG} covers ordinary types. Verifying a signature over an {@code A} RRset needs
 * the canonical form of each covered record, which
 * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.3.2">RFC 4035, section 5.3.2</a> builds from the
 * owner name's exact octets followed by the {@code RDATA}. {@link io.netty.handler.codec.dns.DnsRecord#name()}
 * cannot supply those octets, and by the time a validator runs, the message the record was read from is usually
 * gone. So {@link DnssecDnsRecordDecoder} gives every record an {@link #owner()}, not only the DNSSEC types.
 * <p>
 * Where the type's {@code RDATA} may itself contain compressed names, the {@code RDATA} held here has been
 * expanded; see {@link DnssecDnsRecordDecoder} for which types those are and why the rest are passed through
 * untouched.
 */
public class DefaultDnssecRawRecord extends AbstractDnssecRecord {

    /**
     * Creates a new record.
     *
     * @param name       the owner name as text, as {@link io.netty.handler.codec.dns.DnsRecord#name()} reports it
     * @param type       the type of the record
     * @param dnsClass   the class of the record
     * @param timeToLive the TTL of the record
     * @param owner      the wire form of the owner name
     * @param content    the {@code RDATA}; the record takes ownership of it and never modifies its indexes
     */
    public DefaultDnssecRawRecord(String name, DnsRecordType type, int dnsClass, long timeToLive, DnsName owner,
                                  ByteBuf content) {
        super(name, type, dnsClass, timeToLive, owner, content);
    }

    /**
     * Copies {@code record}'s fields onto {@code content} without going through {@link #replace(ByteBuf)}, which
     * a subclass may override to parse; see {@link DefaultDnssecPtrRecord}.
     */
    DefaultDnssecRawRecord(DefaultDnssecRawRecord record, ByteBuf content) {
        super(record.name(), record.type(), record.dnsClass(), record.timeToLive(), record.owner(), content);
    }

    @Override
    public DefaultDnssecRawRecord copy() {
        return new DefaultDnssecRawRecord(this, content().copy());
    }

    @Override
    public DefaultDnssecRawRecord duplicate() {
        return new DefaultDnssecRawRecord(this, content().duplicate());
    }

    @Override
    public DefaultDnssecRawRecord retainedDuplicate() {
        return new DefaultDnssecRawRecord(this, content().retainedDuplicate());
    }

    @Override
    public DefaultDnssecRawRecord replace(ByteBuf content) {
        return new DefaultDnssecRawRecord(name(), type(), dnsClass(), timeToLive(), owner(), content);
    }

    @Override
    public DefaultDnssecRawRecord retain() {
        super.retain();
        return this;
    }

    @Override
    public DefaultDnssecRawRecord retain(int increment) {
        super.retain(increment);
        return this;
    }

    @Override
    public DefaultDnssecRawRecord touch() {
        super.touch();
        return this;
    }

    @Override
    public DefaultDnssecRawRecord touch(Object hint) {
        super.touch(hint);
        return this;
    }
}
