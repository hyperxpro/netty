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

import io.netty.util.concurrent.EventExecutor;
import io.netty.util.internal.ObjectUtil;

/**
 * Builds a {@link DnssecValidator}. Obtained from {@link DnssecValidator#newBuilder()}.
 *
 * <p>The only setting without a default is {@link #fetcher(DnssecRecordFetcher)}: a validator that cannot look up
 * a {@code DNSKEY} or a {@code DS} cannot walk a chain of trust, and there is no sensible fallback for it inside a
 * codec.
 *
 * <p>The clock and the limits are shared with the {@link DnssecSignatureVerifier}, and this builder will not let
 * them diverge. A verifier judging {@code RRSIG} validity by the system clock inside a validation whose budget
 * runs on a pinned one is not a configuration anybody wants; it is a test that passes in June and fails in July.
 * So {@link #verifier(DnssecSignatureVerifier)} adopts the verifier's own clock and limits, and calling
 * {@link #clock(DnssecClock)} or {@link #limits(DnssecLimits)} with something else as well is rejected at
 * {@link #build()} rather than silently resolved.
 *
 * <p>Not thread-safe. Build on one thread; the {@link DnssecValidator} that comes out is immutable and
 * shareable.
 */
public final class DnssecValidatorBuilder {

    private DnssecTrustAnchors trustAnchors = DnssecTrustAnchors.iana();
    private DnssecRecordFetcher fetcher;
    private DnssecSignatureVerifier verifier;
    private DnssecLimits limits;
    private DnssecKeyCache keyCache;
    private DnssecClock clock;
    private EventExecutor executor;

    DnssecValidatorBuilder() {
    }

    /**
     * Sets the trust anchors the chain of trust starts from. Defaults to {@link DnssecTrustAnchors#iana()}.
     *
     * <p>Anchors are applied at the deepest configured name that is an ancestor-or-equal of the name being
     * validated, and anchors at a shallower name are never merged in as a fallback; see
     * {@link DnssecTrustAnchors#anchorsFor(io.netty.handler.codec.dns.DnsName)}.
     */
    public DnssecValidatorBuilder trustAnchors(DnssecTrustAnchors trustAnchors) {
        this.trustAnchors = ObjectUtil.checkNotNull(trustAnchors, "trustAnchors");
        return this;
    }

    /**
     * Sets how the validator performs the {@code DNSKEY} and {@code DS} lookups its chain walk needs. Required.
     *
     * <p>Read {@link DnssecRecordFetcher} before writing one: every query it sends must have {@code DO=1} and
     * {@code CD=1}, and without {@code CD} the validator is reduced to believing whatever the upstream resolver
     * decided.
     */
    public DnssecValidatorBuilder fetcher(DnssecRecordFetcher fetcher) {
        this.fetcher = ObjectUtil.checkNotNull(fetcher, "fetcher");
        return this;
    }

    /**
     * Sets the signature verifier, whose {@link DnssecSignatureVerifier#clock() clock} and
     * {@link DnssecSignatureVerifier#limits() limits} the validator then adopts.
     *
     * <p>Defaults to a verifier built from {@link #clock(DnssecClock)} and {@link #limits(DnssecLimits)}.
     */
    public DnssecValidatorBuilder verifier(DnssecSignatureVerifier verifier) {
        this.verifier = ObjectUtil.checkNotNull(verifier, "verifier");
        return this;
    }

    /**
     * Sets the hardening limits. Defaults to {@link DnssecLimits#defaults()}.
     *
     * <p>Exceeding any of them is {@link DnssecStatus#BOGUS}, never {@link DnssecStatus#INSECURE}: a limit an
     * attacker can provoke on demand must not be a way to strip DNSSEC from a signed zone.
     */
    public DnssecValidatorBuilder limits(DnssecLimits limits) {
        this.limits = ObjectUtil.checkNotNull(limits, "limits");
        return this;
    }

    /**
     * Sets where validated {@code DNSKEY} RRsets are remembered. Defaults to a fresh
     * {@link DefaultDnssecKeyCache}; pass {@link DnssecKeyCache#noop()} to cache nothing.
     *
     * <p>Sharing one cache between validators configured with different trust anchors shares trust between them;
     * see {@link DnssecKeyCache}.
     */
    public DnssecValidatorBuilder keyCache(DnssecKeyCache keyCache) {
        this.keyCache = ObjectUtil.checkNotNull(keyCache, "keyCache");
        return this;
    }

    /**
     * Sets the clock the validation deadline and the {@code RRSIG} validity periods are judged against. Defaults
     * to {@link DnssecClock#SYSTEM}.
     */
    public DnssecValidatorBuilder clock(DnssecClock clock) {
        this.clock = ObjectUtil.checkNotNull(clock, "clock");
        return this;
    }

    /**
     * Sets the executor {@link DnssecValidator#validate(io.netty.handler.codec.dns.DnsName,
     * io.netty.handler.codec.dns.DnsRecordType, io.netty.handler.codec.dns.DnsResponse)} runs validations on.
     *
     * <p>Optional: the four-argument
     * {@link DnssecValidator#validate(io.netty.handler.codec.dns.DnsName,
     * io.netty.handler.codec.dns.DnsRecordType, io.netty.handler.codec.dns.DnsResponse, EventExecutor)} takes one
     * per call, which is what a validator shared between channels wants — each response is then validated on the
     * event loop that received it.
     */
    public DnssecValidatorBuilder executor(EventExecutor executor) {
        this.executor = ObjectUtil.checkNotNull(executor, "executor");
        return this;
    }

    /**
     * Builds the validator.
     *
     * @throws IllegalStateException if no {@link #fetcher(DnssecRecordFetcher)} was set, or if an explicit
     *                               {@link #verifier(DnssecSignatureVerifier)} disagrees with an explicit
     *                               {@link #clock(DnssecClock)} or {@link #limits(DnssecLimits)}.
     */
    public DnssecValidator build() {
        if (fetcher == null) {
            throw new IllegalStateException("fetcher not set: a validator cannot walk a chain of trust without one");
        }
        DnssecClock effectiveClock = clock;
        DnssecLimits effectiveLimits = limits;
        DnssecSignatureVerifier effectiveVerifier = verifier;
        if (effectiveVerifier != null) {
            if (effectiveClock != null && effectiveClock != effectiveVerifier.clock()) {
                throw new IllegalStateException("clock and verifier.clock() differ: the RRSIG validity periods and "
                        + "the validation deadline would be judged against two different notions of now");
            }
            if (effectiveLimits != null && effectiveLimits != effectiveVerifier.limits()) {
                throw new IllegalStateException("limits and verifier.limits() differ: the per-RRset and "
                        + "per-validation signature budgets would be taken from two different configurations");
            }
            effectiveClock = effectiveVerifier.clock();
            effectiveLimits = effectiveVerifier.limits();
        } else {
            if (effectiveClock == null) {
                effectiveClock = DnssecClock.SYSTEM;
            }
            if (effectiveLimits == null) {
                effectiveLimits = DnssecLimits.defaults();
            }
            effectiveVerifier = new DnssecSignatureVerifier(effectiveClock, effectiveLimits);
        }
        DnssecKeyCache effectiveKeyCache = keyCache != null ? keyCache : new DefaultDnssecKeyCache();
        return new DnssecValidator(trustAnchors, fetcher, effectiveVerifier, effectiveLimits, effectiveKeyCache,
                effectiveClock, executor);
    }
}
