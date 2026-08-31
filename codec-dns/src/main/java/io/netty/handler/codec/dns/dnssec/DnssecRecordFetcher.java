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

import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.util.concurrent.Future;

/**
 * Supplies the {@code DNSKEY} and {@code DS} lookups a {@link DnssecValidator} needs in order to walk a chain of
 * trust. This is the one thing the validator cannot do for itself, and keeping it an interface is what keeps
 * {@code codec-dns} free of I/O.
 *
 * <p>An implementation <strong>MUST</strong> send each query with both of these set:
 * <ul>
 *   <li><strong>{@code DO}</strong>, the DNSSEC OK bit of
 *   <a href="https://www.rfc-editor.org/rfc/rfc3225.html">RFC 3225</a>, so that the server returns the
 *   {@code RRSIG}, {@code NSEC} and {@code NSEC3} records at all.
 *   {@link io.netty.handler.codec.dns.DefaultDnsOptPseudoRecord#withDnssecOk(int)} builds the {@code OPT} record
 *   that carries it.</li>
 *   <li><strong>{@code CD}</strong>, Checking Disabled, per
 *   <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.9">RFC 6840, Section 5.9</a>.
 *   {@link io.netty.handler.codec.dns.DnsMessage#setCheckingDisabled(boolean)} sets it, and it reaches the wire
 *   only because {@link io.netty.handler.codec.dns.DnsQueryEncoder} now encodes the {@code Z} field.</li>
 * </ul>
 *
 * <p>{@code CD} is the one that is easy to leave out and the one whose absence is hardest to diagnose. Without it
 * an upstream validating resolver answers {@code SERVFAIL} for anything it considers Bogus and strips the records
 * that would let this validator disagree, so the chain walk cannot reach an independent verdict: it sees the
 * upstream's opinion rather than the zone's data. A validator that trusts someone else's verdict is not
 * validating.
 *
 * <p>A fetch that fails — a refused query, a malformed response, a transport error, or a timeout — makes the
 * validation {@link DnssecStatus#INDETERMINATE}, never {@link DnssecStatus#BOGUS} and never
 * {@link DnssecStatus#INSECURE}. The validator could not obtain the material it needed, which is "unknown" and not
 * "unsigned": an attacker who can drop packets must not thereby be able to strip DNSSEC from a signed zone, and
 * must not be able to make a working zone look forged either. Complete the returned {@link Future} exceptionally
 * rather than completing it with an empty result, so that the cause survives into
 * {@link DnssecValidationResult#cause()}.
 *
 * <p>An implementation should apply its own per-query timeout. The validator has a wall-clock backstop of
 * {@link DnssecLimits#validationTimeoutMillis()} for the whole validation, but a query that never answers should
 * be failed by whoever sent it.
 *
 * <p>{@link #fetch(DnsName, DnsRecordType)} is called on the {@link io.netty.util.concurrent.EventExecutor} the
 * validation runs on and must not block it. The returned {@link Future} may complete on any thread; the validator
 * hops back to its own executor before touching validation state.
 *
 * <p>Implementations must be thread-safe if the {@link DnssecValidator} holding them is shared, which is the
 * intended usage.
 */
public interface DnssecRecordFetcher {

    /**
     * Looks up {@code name}/{@code type} in class {@code IN}, with {@code DO=1} and {@code CD=1}.
     *
     * <p>The response must be decoded with {@link DnssecDnsRecordDecoder}, or the records will not carry the wire
     * form of their owner names and nothing signed over them can be reconstructed. Wrap the decoded response with
     * {@link DnssecFetchResult#fromResponse(io.netty.handler.codec.dns.DnsResponse)}, which retains the records it
     * keeps, and then release the response.
     *
     * <p>The validator takes ownership of the {@link DnssecFetchResult} the future completes with and releases it
     * exactly once, including when the validation has already reached a verdict by the time the future
     * completes.
     *
     * @param name the owner name to query, in wire form.
     * @param type the RR type to query, {@link DnsRecordType#DNSKEY} or {@link DnsRecordType#DS} in practice.
     * @return a future that completes with the response, or fails if the lookup did not produce one. Never
     *         {@code null}, and never completed with {@code null}.
     */
    Future<DnssecFetchResult> fetch(DnsName name, DnsRecordType type);
}
