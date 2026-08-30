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
import io.netty.handler.codec.dns.DefaultDnsRawRecord;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.util.internal.ObjectUtil;

/**
 * Skeletal {@link DnssecRecord} that keeps the owner name's wire form beside the {@code RDATA} and leaves the
 * {@code RDATA} itself untouched, so that {@link #content()} always re-encodes to the octets the record was decoded
 * from.
 */
abstract class AbstractDnssecRecord extends DefaultDnsRawRecord implements DnssecRecord {

    private final DnsName owner;

    AbstractDnssecRecord(String name, DnsRecordType type, int dnsClass, long timeToLive, DnsName owner,
                         ByteBuf content) {
        super(name, type, dnsClass, timeToLive, content);
        this.owner = ObjectUtil.checkNotNull(owner, "owner");
    }

    /**
     * Checks that {@code type} is one of the types this record implements and returns it.
     */
    static DnsRecordType checkType(DnsRecordType type, DnsRecordType expected) {
        if (ObjectUtil.checkNotNull(type, "type").intValue() != expected.intValue()) {
            throw new IllegalArgumentException("type: " + type + " (expected: " + expected + ')');
        }
        return type;
    }

    /**
     * Checks that {@code type} is one of the two types this record implements and returns it. {@code DS} and
     * {@code CDS}, and {@code DNSKEY} and {@code CDNSKEY}, share an {@code RDATA} layout and therefore an
     * implementation.
     */
    static DnsRecordType checkType(DnsRecordType type, DnsRecordType expected, DnsRecordType alsoExpected) {
        int value = ObjectUtil.checkNotNull(type, "type").intValue();
        if (value != expected.intValue() && value != alsoExpected.intValue()) {
            throw new IllegalArgumentException("type: " + type + " (expected: " + expected + " or "
                    + alsoExpected + ')');
        }
        return type;
    }

    @Override
    public final DnsName owner() {
        return owner;
    }

    @Override
    public abstract DnssecRecord copy();

    @Override
    public abstract DnssecRecord duplicate();

    @Override
    public abstract DnssecRecord retainedDuplicate();

    @Override
    public abstract DnssecRecord replace(ByteBuf content);

    @Override
    public DnssecRecord retain() {
        super.retain();
        return this;
    }

    @Override
    public DnssecRecord retain(int increment) {
        super.retain(increment);
        return this;
    }

    @Override
    public DnssecRecord touch() {
        super.touch();
        return this;
    }

    @Override
    public DnssecRecord touch(Object hint) {
        super.touch(hint);
        return this;
    }
}
