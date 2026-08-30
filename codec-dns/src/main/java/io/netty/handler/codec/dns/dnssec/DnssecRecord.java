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
import io.netty.handler.codec.dns.DnsRawRecord;

/**
 * A DNSSEC resource record whose {@code RDATA} has been parsed into typed fields.
 * <p>
 * Every implementation is also a {@link DnsRawRecord} whose {@link #content()} still holds the {@code RDATA} exactly
 * as it arrived, so a record can be re-encoded octet for octet. That matters more here than for other record types:
 * an {@code RRSIG} is computed over the {@code RDATA} of the records it covers, so re-encoding a record from its
 * parsed fields rather than from the octets it was decoded from risks producing something the signature no longer
 * covers.
 * <p>
 * {@code equals} and {@code hashCode} are the ones {@link io.netty.handler.codec.dns.AbstractDnsRecord} defines:
 * they compare the name, type, class and TTL, and not the {@code RDATA}. Two {@code DNSKEY}s of one RRset are
 * therefore equal to each other, so code that has to tell the members of an RRset apart, which is most of what
 * DNSSEC does, must compare {@link #content()} itself.
 */
public interface DnssecRecord extends DnsRawRecord {

    /**
     * Returns the wire form of this record's owner name.
     * <p>
     * This is not the same as {@link #name()}. {@code name()} is produced by decoding each label as UTF-8, which is
     * lossy for the arbitrary octets a label may hold, so it cannot be turned back into the octets that were
     * signed. DNSSEC canonicalisation and signature verification need those octets, and this is where they are.
     */
    DnsName owner();

    @Override
    DnssecRecord copy();

    @Override
    DnssecRecord duplicate();

    @Override
    DnssecRecord retainedDuplicate();

    /**
     * Returns a new record of the same type holding {@code content} as its {@code RDATA}.
     * <p>
     * {@code content} is parsed, so the returned record's accessors always describe the octets it holds. This
     * method takes ownership of {@code content}: it is released if it cannot be parsed.
     *
     * @throws io.netty.handler.codec.CorruptedFrameException if {@code content} is not valid {@code RDATA} for this
     *                                                        record type
     */
    @Override
    DnssecRecord replace(ByteBuf content);

    @Override
    DnssecRecord retain();

    @Override
    DnssecRecord retain(int increment);

    @Override
    DnssecRecord touch();

    @Override
    DnssecRecord touch(Object hint);
}
