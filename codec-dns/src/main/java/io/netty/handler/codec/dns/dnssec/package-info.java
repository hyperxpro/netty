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

/**
 * Building blocks for
 * <a href="https://www.rfc-editor.org/rfc/rfc4033.html">DNS Security Extensions (DNSSEC)</a>.
 *
 * <p>The cryptographic half of this package operates on raw {@code byte[]} taken straight off the wire:
 * {@link io.netty.handler.codec.dns.dnssec.DnssecPublicKeys} turns the {@code DNSKEY} public key field into a
 * {@link java.security.PublicKey}, {@link io.netty.handler.codec.dns.dnssec.DnssecSignatures} converts {@code RRSIG}
 * signatures into the shapes the JDK accepts, and {@link io.netty.handler.codec.dns.dnssec.DnssecKeyTag} computes the
 * key tag of a {@code DNSKEY} RDATA. The registries are modelled by
 * {@link io.netty.handler.codec.dns.dnssec.DnssecAlgorithm} and
 * {@link io.netty.handler.codec.dns.dnssec.DnssecDigestType}, whose implementation requirements follow
 * <a href="https://www.rfc-editor.org/rfc/rfc9904.html">RFC 9904</a>, as amended by
 * <a href="https://www.rfc-editor.org/rfc/rfc9906.html">RFC 9906</a>.
 *
 * <p>The wire half turns the DNSSEC record types into typed records:
 * {@link io.netty.handler.codec.dns.dnssec.DnsDnskeyRecord},
 * {@link io.netty.handler.codec.dns.dnssec.DnsDsRecord}, {@link io.netty.handler.codec.dns.dnssec.DnsRrsigRecord},
 * {@link io.netty.handler.codec.dns.dnssec.DnsNsecRecord},
 * {@link io.netty.handler.codec.dns.dnssec.DnsNsec3Record} and
 * {@link io.netty.handler.codec.dns.dnssec.DnsNsec3ParamRecord}, decoded by
 * {@link io.netty.handler.codec.dns.dnssec.DnssecDnsRecordDecoder} and written back unchanged by
 * {@link io.netty.handler.codec.dns.dnssec.DnssecDnsRecordEncoder}. They keep their original {@code RDATA},
 * because an {@code RRSIG} covers the octets rather than the fields. Every other type is decoded into a
 * {@link io.netty.handler.codec.dns.dnssec.DefaultDnssecRawRecord} rather than being left alone, so that it too
 * carries the owner name's wire octets: an {@code RRSIG} covers ordinary types, and their canonical form starts
 * with those octets.
 *
 * <p>{@link io.netty.handler.codec.dns.dnssec.DnssecValidator} puts the two halves together and walks the chain of
 * trust from a {@link io.netty.handler.codec.dns.dnssec.DnssecTrustAnchor} down to the name that was asked about,
 * reaching one of the four states of {@link io.netty.handler.codec.dns.dnssec.DnssecStatus}. It still performs no
 * I/O: the {@code DNSKEY} and {@code DS} lookups the walk needs come from a
 * {@link io.netty.handler.codec.dns.dnssec.DnssecRecordFetcher} the caller supplies, and every query that fetcher
 * sends must carry {@code DO=1} and {@code CD=1}. The verdict comes back as a
 * {@link io.netty.handler.codec.dns.dnssec.DnssecValidationResult}, which holds no buffers and is safe to log,
 * cache and pass between threads.
 *
 * <p>The rule the engine turns on, and the one worth knowing before reading any of it: a failure to <em>prove</em>
 * security is <em>Insecure</em> or <em>Indeterminate</em>, and only a proof of <em>inconsistency</em> is
 * <em>Bogus</em>. Exceeding one of the {@link io.netty.handler.codec.dns.dnssec.DnssecLimits} is Bogus for the same
 * reason: a limit an attacker can provoke must not be a way to reach the weaker verdict.
 *
 * <p>A <em>validating stub resolver</em> built on this package only provides real protection when the channel
 * between the stub and the recursive server it queries is itself trusted; see
 * <a href="https://www.rfc-editor.org/rfc/rfc4033.html#section-7">RFC 4033, section 7</a>. Without a secured
 * channel an attacker who can rewrite the responses can also strip the DNSSEC records and the {@code AD} bit, and
 * the stub then has nothing left to validate. Run the queries over a transport that authenticates the server, or
 * validate against a recursive server reached over a trusted link.
 */
package io.netty.handler.codec.dns.dnssec;
