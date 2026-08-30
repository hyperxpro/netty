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
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordType;

/**
 * A {@link DefaultDnsRecordDecoder} that decodes every record into a {@link DnssecRecord}, so that a validator can
 * reconstruct the canonical form of anything an {@code RRSIG} covers.
 * <p>
 * The DNSSEC types become typed records: {@link DnsDnskeyRecord} for {@code DNSKEY} and {@code CDNSKEY},
 * {@link DnsDsRecord} for {@code DS} and {@code CDS}, {@link DnsRrsigRecord}, {@link DnsNsecRecord},
 * {@link DnsNsec3Record} and {@link DnsNsec3ParamRecord}. Everything else becomes a
 * {@link DefaultDnssecRawRecord}, except {@code PTR}, which becomes a {@link DefaultDnssecPtrRecord} so that it is
 * still a {@link io.netty.handler.codec.dns.DnsPtrRecord}. All of them are
 * {@link io.netty.handler.codec.dns.DnsRawRecord}s whose {@link DnssecRecord#content()} is the {@code RDATA}, so
 * code that already casts to {@code DnsRawRecord} keeps working.
 * <p>
 * <b>Why every type and not only the DNSSEC ones.</b> An {@code RRSIG} covers ordinary types: {@code A},
 * {@code AAAA}, {@code MX}, {@code SOA}. Verifying one needs the canonical form of each covered record, which
 * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.3.2">RFC 4035, section 5.3.2</a> starts with the
 * owner name's exact wire octets. {@link DnsRecord#name()} cannot supply them: it has been through a UTF-8 decode
 * and is lossy for a label holding arbitrary octets. So this decoder reads each owner name a second time, in wire
 * form, and hands it to the record as {@link DnssecRecord#owner()}. Compression pointers in the owner name are
 * resolved against the whole message, which is why the eight-argument hook that supplies {@code nameOffset}
 * exists.
 * <p>
 * <b>{@code RDATA} compression.</b> Canonical form also requires the names inside {@code RDATA} to be expanded.
 * {@link DnssecRdataDecompressor} does that, byte for byte, for exactly the types
 * <a href="https://www.rfc-editor.org/rfc/rfc3597.html#section-4">RFC 3597, section 4</a> allows compression in:
 * {@code NS}, {@code MD}, {@code MF}, {@code CNAME}, {@code SOA}, {@code MB}, {@code MG}, {@code MR},
 * {@code PTR}, {@code MINFO}, {@code MX}, {@code RP}, {@code AFSDB}, {@code RT}, {@code SIG}, {@code PX},
 * {@code NXT}, {@code SRV} and {@code NAPTR}. The {@code RDATA} of every other type is passed through untouched,
 * because RFC 3597 forbids compression there and an octet that looks like a pointer is data; expanding it would
 * map two wire encodings onto one signed preimage. Note that this is <em>not</em> the same set of types as the
 * one whose {@code RDATA} names are down-cased when canonicalising.
 * <p>
 * <b>Differences from the superclass.</b> {@code PTR} keeps its {@link io.netty.handler.codec.dns.DnsPtrRecord}
 * interface but is now also a {@code DnsRawRecord}. {@code CNAME}, {@code NS} and {@code MX}, which the
 * superclass already expanded by rendering the name as text and encoding the text again, are expanded here
 * without that round trip, so a label holding octets that are not printable ASCII survives. Owner names are read
 * with {@link DnsName}, which is stricter than the superclass: it rejects a compression pointer that does not
 * point strictly backwards. In one place this decoder is more lenient: the superclass rejects an {@code MX} whose
 * {@code RDATA} is shorter than three octets, while here such a record is passed through, because its octets hold
 * no compression pointer and so are already the ones a signature would have to cover.
 * <p>
 * Because this decoder handles every type itself, the seven-argument
 * {@link #decodeRecord(String, DnsRecordType, int, long, ByteBuf, int, int)} is never reached. Subclasses that
 * want to add their own record types should override the eight-argument overload and delegate to {@code super}
 * for the rest.
 * <p>
 * This class is thread-safe and stateless. Use {@link #INSTANCE} unless you are subclassing it.
 */
public class DnssecDnsRecordDecoder extends DefaultDnsRecordDecoder {

    /**
     * A shared instance.
     */
    public static final DnssecDnsRecordDecoder INSTANCE = new DnssecDnsRecordDecoder();

    private static final int DNSKEY = DnsRecordType.DNSKEY.intValue();
    private static final int CDNSKEY = DnsRecordType.CDNSKEY.intValue();
    private static final int DS = DnsRecordType.DS.intValue();
    private static final int CDS = DnsRecordType.CDS.intValue();
    private static final int RRSIG = DnsRecordType.RRSIG.intValue();
    private static final int NSEC = DnsRecordType.NSEC.intValue();
    private static final int NSEC3 = DnsRecordType.NSEC3.intValue();
    private static final int NSEC3PARAM = DnsRecordType.NSEC3PARAM.intValue();
    private static final int PTR = DnsRecordType.PTR.intValue();

    /**
     * Creates a new instance.
     */
    public DnssecDnsRecordDecoder() {
    }

    @Override
    protected DnsRecord decodeRecord(String name, DnsRecordType type, int dnsClass, long timeToLive,
                                     ByteBuf in, int offset, int length, int nameOffset) throws Exception {
        // in holds the whole message, so compression pointers in the owner name resolve against all of it.
        final int messageEnd = in.writerIndex();
        final DnsName owner = DnsName.decode(in, nameOffset, messageEnd);

        ByteBuf content = DnssecRdataDecompressor.decompress(in, offset, length, messageEnd, type);
        final boolean expanded = content != null;
        if (!expanded) {
            content = in.retainedDuplicate();
        }
        try {
            if (!expanded) {
                content.setIndex(offset, offset + length);
            }
            DnsRecord record = newRecord(name, type, dnsClass, timeToLive, owner, content);
            content = null;
            return record;
        } finally {
            if (content != null) {
                content.release();
            }
        }
    }

    private static DnssecRecord newRecord(String name, DnsRecordType type, int dnsClass, long timeToLive,
                                          DnsName owner, ByteBuf content) {
        int value = type.intValue();
        if (value == DNSKEY || value == CDNSKEY) {
            return new DnsDnskeyRecord(name, type, dnsClass, timeToLive, owner, content);
        }
        if (value == DS || value == CDS) {
            return new DnsDsRecord(name, type, dnsClass, timeToLive, owner, content);
        }
        if (value == RRSIG) {
            return new DnsRrsigRecord(name, type, dnsClass, timeToLive, owner, content);
        }
        if (value == NSEC) {
            return new DnsNsecRecord(name, type, dnsClass, timeToLive, owner, content);
        }
        if (value == NSEC3) {
            return new DnsNsec3Record(name, type, dnsClass, timeToLive, owner, content);
        }
        if (value == NSEC3PARAM) {
            return new DnsNsec3ParamRecord(name, type, dnsClass, timeToLive, owner, content);
        }
        if (value == PTR) {
            return new DefaultDnssecPtrRecord(name, dnsClass, timeToLive, owner, content);
        }
        return new DefaultDnssecRawRecord(name, type, dnsClass, timeToLive, owner, content);
    }
}
