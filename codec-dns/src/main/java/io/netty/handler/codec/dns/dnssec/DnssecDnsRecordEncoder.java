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
import io.netty.handler.codec.dns.DefaultDnsRecordEncoder;
import io.netty.handler.codec.dns.DnsRecord;

/**
 * A {@link DefaultDnsRecordEncoder} that writes a {@link DnssecRecord} back exactly as it was decoded.
 * <p>
 * The superclass already writes the {@code RDATA} of any {@link io.netty.handler.codec.dns.DnsRawRecord} verbatim,
 * so the {@code RDATA} of a {@link DnssecRecord} round-trips without help. The owner name does not: the superclass
 * encodes {@link DnsRecord#name()}, which is the record's name after a UTF-8 decode and an
 * {@link java.net.IDN#toASCII(String)} pass, and a label holding octets that are not printable ASCII does not
 * survive that. This encoder writes {@link DnssecRecord#owner()} instead, which is the name's original octets, so
 * decoding and re-encoding a DNSSEC record reproduces the input byte for byte and a signature over it still
 * verifies.
 * <p>
 * Names are never compressed, which is what
 * <a href="https://www.rfc-editor.org/rfc/rfc3597.html#section-4">RFC 3597, section 4</a> requires for the
 * {@code RDATA} of these types and what the superclass does for owner names as well.
 * <p>
 * This class is thread-safe and stateless. Use {@link #INSTANCE} unless you are subclassing it.
 */
public class DnssecDnsRecordEncoder extends DefaultDnsRecordEncoder {

    /**
     * A shared instance.
     */
    public static final DnssecDnsRecordEncoder INSTANCE = new DnssecDnsRecordEncoder();

    /**
     * Creates a new instance.
     */
    public DnssecDnsRecordEncoder() {
    }

    @Override
    public void encodeRecord(DnsRecord record, ByteBuf out) throws Exception {
        if (record instanceof DnssecRecord) {
            encodeDnssecRecord((DnssecRecord) record, out);
        } else {
            super.encodeRecord(record, out);
        }
    }

    private static void encodeDnssecRecord(DnssecRecord record, ByteBuf out) {
        record.owner().writeTo(out);
        out.writeShort(record.type().intValue());
        out.writeShort(record.dnsClass());
        out.writeInt((int) record.timeToLive());

        ByteBuf content = record.content();
        int contentLength = content.readableBytes();
        out.writeShort(contentLength);
        out.writeBytes(content, content.readerIndex(), contentLength);
    }
}
