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
import io.netty.handler.codec.dns.DefaultDnsRecordDecoder;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsPtrRecord;
import io.netty.handler.codec.dns.DnsRecordType;

/**
 * A {@code PTR} record that is both a {@link DnsPtrRecord} and a {@link DnssecRecord}.
 * <p>
 * {@link io.netty.handler.codec.dns.DefaultDnsRecordDecoder} turns a {@code PTR} into a
 * {@link io.netty.handler.codec.dns.DefaultDnsPtrRecord}, which has a {@link #hostname()} but no {@code RDATA} and
 * so cannot be canonicalised or verified. This type keeps the {@code RDATA} and the owner name's octets that
 * DNSSEC needs without taking {@link #hostname()} away from code that already relies on it.
 */
public final class DefaultDnssecPtrRecord extends DefaultDnssecRawRecord implements DnsPtrRecord {

    private final String hostname;

    /**
     * Creates a new record.
     *
     * @param name       the owner name as text, as {@link io.netty.handler.codec.dns.DnsRecord#name()} reports it
     * @param dnsClass   the class of the record
     * @param timeToLive the TTL of the record
     * @param owner      the wire form of the owner name
     * @param content    the {@code RDATA}, with any compression already expanded; the record takes ownership of it
     */
    public DefaultDnssecPtrRecord(String name, int dnsClass, long timeToLive, DnsName owner, ByteBuf content) {
        super(name, DnsRecordType.PTR, dnsClass, timeToLive, owner, content);
        // The RDATA is a bare domain name and has already been expanded, so this reads the same text the
        // superclass decoder would have produced, without touching the buffer's indexes.
        hostname = DefaultDnsRecordDecoder.decodeName(content.duplicate());
    }

    @Override
    public String hostname() {
        return hostname;
    }

    @Override
    public DefaultDnssecPtrRecord replace(ByteBuf content) {
        try {
            return new DefaultDnssecPtrRecord(name(), dnsClass(), timeToLive(), owner(), content);
        } catch (Throwable cause) {
            content.release();
            throw cause;
        }
    }

    @Override
    public DefaultDnssecPtrRecord copy() {
        return replace(content().copy());
    }

    @Override
    public DefaultDnssecPtrRecord duplicate() {
        return replace(content().duplicate());
    }

    @Override
    public DefaultDnssecPtrRecord retainedDuplicate() {
        return replace(content().retainedDuplicate());
    }

    @Override
    public DefaultDnssecPtrRecord retain() {
        super.retain();
        return this;
    }

    @Override
    public DefaultDnssecPtrRecord retain(int increment) {
        super.retain(increment);
        return this;
    }

    @Override
    public DefaultDnssecPtrRecord touch() {
        super.touch();
        return this;
    }

    @Override
    public DefaultDnssecPtrRecord touch(Object hint) {
        super.touch(hint);
        return this;
    }
}
