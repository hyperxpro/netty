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

import java.util.List;

/**
 * Remembers the apex {@code DNSKEY} RRset of a zone that a {@link DnssecValidator} has <em>already</em> validated,
 * so that the next validation under the same zone does not have to fetch and re-verify it.
 *
 * <p>A validator calls {@link #put(DnsName, List, long, long)} only once the RRset has been shown to be the zone's
 * real key set: a {@code DS} record from the parent, or a trust anchor, matched one specific key, and an
 * {@code RRSIG} <em>made by that key</em> validated over the whole RRset. Nothing partially validated is ever
 * stored, which is what keeps this cache from becoming the publication point for an answer that has not yet
 * reached a verdict.
 *
 * <p>The consequence for a caller is direct: <strong>an instance shared between two validators shares trust
 * between them.</strong> A validator configured with different trust anchors, a different clock, or different
 * {@link DnssecLimits} will happily use keys the other one accepted, because the cache records the conclusion and
 * not the reasoning that reached it. Give each set of trust anchors its own cache, or use
 * {@link #noop()} and pay for the lookups.
 *
 * <p>This cache never holds a reference-counted object. {@link #put(DnsName, List, long, long)} copies the
 * {@code RDATA} it needs, and {@link #get(DnsName, long)} returns freshly built records that the <em>caller</em>
 * owns and must release. That is deliberate: a cache that owned buffer reference counts would have to release them
 * on eviction, on replacement and on clear, from whichever thread happened to trigger it, and getting one of those
 * wrong is a use-after-free rather than a stale answer.
 *
 * <p>An implementation must be thread-safe. {@link DnssecValidator} is shareable and each validation runs on the
 * {@link io.netty.util.concurrent.EventExecutor} its caller supplied, so one cache is reached from as many threads
 * as there are event loops.
 */
public interface DnssecKeyCache {

    /**
     * Returns a validator that caches nothing. Every validation then fetches and re-verifies every {@code DNSKEY}
     * RRset it needs, which is slower and is the only configuration in which no trust is shared between
     * validations.
     */
    static DnssecKeyCache noop() {
        return NoopDnssecKeyCache.INSTANCE;
    }

    /**
     * Returns the validated apex {@code DNSKEY} RRset of {@code zone}, or {@code null} if none is cached or the
     * cached one has expired.
     *
     * @param zone              the apex name of the zone, in wire form.
     * @param currentTimeMillis the validator's notion of "now", taken from its {@link DnssecClock}, so that a
     *                          validator with a pinned clock does not have entries expire out from under it
     *                          according to the system clock.
     * @return newly created records the caller owns and must release, or {@code null}. Never an empty list: an
     *         empty key set is not a fact worth remembering.
     */
    List<DnsDnskeyRecord> get(DnsName zone, long currentTimeMillis);

    /**
     * Stores the validated apex {@code DNSKEY} RRset of {@code zone}.
     *
     * <p>The records are copied, not retained; the caller keeps ownership of the ones it passed in.
     *
     * @param zone              the apex name of the zone, in wire form. Every record in {@code keys} must have it
     *                          as its owner.
     * @param keys              the validated key set. An empty list is ignored.
     * @param ttlSeconds        how long the entry may be used for. A caller should pass the smallest TTL in the
     *                          RRset, further reduced to the remaining validity of the {@code RRSIG} that
     *                          authenticated it, as
     *                          <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.3.3">RFC 4035,
     *                          Section 5.3.3</a> requires. A value of {@code 0} or less stores nothing.
     * @param currentTimeMillis the validator's notion of "now".
     */
    void put(DnsName zone, List<DnsDnskeyRecord> keys, long ttlSeconds, long currentTimeMillis);

    /**
     * Discards every entry. The obvious use is a trust-anchor change, after which nothing already concluded is
     * still justified.
     */
    void clear();
}
