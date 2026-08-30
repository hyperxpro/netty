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
package io.netty.handler.codec.dns;

/**
 * The default {@link DnsOptPseudoRecord} implementation: an
 * <a href="https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1">EDNS(0) OPT pseudo-record</a> carrying no
 * options, which is what an endpoint sends when it only needs to advertise a payload size and the header flags.
 * <p>
 * Use {@link #withDnssecOk(int)} to set the {@code DO} bit of
 * <a href="https://www.rfc-editor.org/rfc/rfc3225.html">RFC 3225</a>. A resolver that does not set {@code DO}
 * is not signalling DNSSEC awareness, and servers will omit RRSIG, NSEC and NSEC3 records from their answers
 * unless those types were asked for by name.
 */
public final class DefaultDnsOptPseudoRecord extends AbstractDnsOptPseudoRrRecord {

    /**
     * The {@code DO} ({@code DNSSEC OK}) bit, the most significant bit of the 16-bit {@code flags} field.
     * See <a href="https://www.rfc-editor.org/rfc/rfc3225.html#section-3">RFC 3225, section 3</a>.
     */
    public static final int FLAG_DNSSEC_OK = 0x8000;

    /**
     * Creates a new instance with an {@code EXTENDED-RCODE}, {@code VERSION} and {@code flags} of zero.
     *
     * @param maxPayloadSize the suggested maximum UDP payload size in bytes, encoded into the {@code CLASS}
     *                       field
     */
    public DefaultDnsOptPseudoRecord(int maxPayloadSize) {
        super(maxPayloadSize);
    }

    /**
     * Creates a new instance.
     *
     * @param maxPayloadSize the suggested maximum UDP payload size in bytes, encoded into the {@code CLASS}
     *                       field
     * @param extendedRcode  the upper 8 bits of the extended 12-bit {@code RCODE}; the lower 4 bits are carried
     *                       by the DNS message header
     * @param version        the EDNS version, {@code 0} for EDNS(0)
     * @param flags          the 16-bit {@code flags} field, which holds {@code DO} and {@code Z}; see
     *                       {@link #FLAG_DNSSEC_OK}
     */
    public DefaultDnsOptPseudoRecord(int maxPayloadSize, int extendedRcode, int version, int flags) {
        super(maxPayloadSize, extendedRcode, version, flags);
    }

    /**
     * Creates a new instance with the {@code DO} ({@code DNSSEC OK}) bit set, signalling that the sender
     * understands DNSSEC and wants the server to include DNSSEC records in its response.
     *
     * @param maxPayloadSize the suggested maximum UDP payload size in bytes. DNSSEC responses are considerably
     *                       larger than unsigned ones, so a value well above the 512-byte floor of RFC 1035 is
     *                       needed to avoid truncation and a TCP retry.
     */
    public static DefaultDnsOptPseudoRecord withDnssecOk(int maxPayloadSize) {
        return new DefaultDnsOptPseudoRecord(maxPayloadSize, 0, 0, FLAG_DNSSEC_OK);
    }

    /**
     * Returns {@code true} if the {@code DO} ({@code DNSSEC OK}) bit is set.
     */
    public boolean isDnssecOk() {
        return (flags() & FLAG_DNSSEC_OK) != 0;
    }
}
