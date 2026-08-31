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

import io.netty.util.internal.ObjectUtil;

/**
 * The work one validation has left, measured against a {@link DnssecLimits}.
 *
 * <p>A budget is created once, at the start of a validation, and spent as the validation proceeds. Each
 * {@code spendXxx()} method consumes one unit and throws {@link DnssecLimitExceededException} when there is none
 * left; the counter is not advanced in that case, so a counter never exceeds its limit and
 * {@link #signatureVerifications()} and friends can be asserted on exactly.
 *
 * <p>Those read-only counters exist so that the bound can be tested for what it is. "The validation finished
 * quickly" is a statement about the machine it ran on; "the validation performed at most 32 signature
 * verifications" is a statement about the validator, and only the second one is worth asserting.
 *
 * <p>There is deliberately no way to reset, refill or reuse a budget: no {@code reset()}, no mutable limits, and a
 * deadline fixed at construction. A quota that a retry can put back is not a quota, and a validator that starts
 * again after a failure while carrying the same budget object must find it as depleted as it left it. Unbound's
 * <a href="https://www.cve.org/CVERecord?id=CVE-2026-50045">CVE-2026-50045</a> was exactly this: work quotas that
 * were restored whenever validation restarted, so an attacker who could provoke restarts could spend the quota
 * arbitrarily many times. A caller that needs a fresh budget must construct a fresh validation.
 *
 * <p>Not thread-safe, and deliberately so. A budget belongs to a single validation, which runs on a single thread;
 * making the counters atomic would cost every validation something in order to support a sharing pattern that would
 * be a bug. Sharing one budget across concurrent validations is undefined and would under-count.
 */
public final class DnssecBudget {

    private final DnssecLimits limits;
    private final DnssecClock clock;
    private final long startTimeMillis;
    private final long deadlineMillis;

    private int signatureVerifications;
    private int fetches;
    private int nsec3HashComputations;
    private int dsMatchFailures;
    private int delegations;
    private int cnameLinks;

    /**
     * Creates a budget for one validation, starting the clock immediately.
     *
     * @param limits the limits to enforce.
     * @param clock  the clock the deadline is measured against; also the clock the validation should judge
     *               {@code RRSIG} validity by, so that both agree on what "now" is.
     */
    public DnssecBudget(DnssecLimits limits, DnssecClock clock) {
        this.limits = ObjectUtil.checkNotNull(limits, "limits");
        this.clock = ObjectUtil.checkNotNull(clock, "clock");
        startTimeMillis = clock.currentTimeMillis();
        long deadline = startTimeMillis + limits.validationTimeoutMillis();
        // A clock close to Long.MAX_VALUE would wrap the deadline into the past and expire the budget instantly.
        deadlineMillis = deadline < startTimeMillis ? Long.MAX_VALUE : deadline;
    }

    /**
     * Returns the limits this budget enforces.
     */
    public DnssecLimits limits() {
        return limits;
    }

    /**
     * Returns the clock this budget was created with.
     */
    public DnssecClock clock() {
        return clock;
    }

    /**
     * Returns the value {@link #clock()} reported when this budget was created, in epoch milliseconds.
     */
    public long startTimeMillis() {
        return startTimeMillis;
    }

    /**
     * Returns the epoch milliseconds after which this validation is out of time, which is
     * {@link #startTimeMillis()} plus {@link DnssecLimits#validationTimeoutMillis()}.
     */
    public long deadlineMillis() {
        return deadlineMillis;
    }

    /**
     * Returns the milliseconds left before {@link #deadlineMillis()}, or {@code 0} once it has passed.
     */
    public long remainingMillis() {
        long remaining = deadlineMillis - clock.currentTimeMillis();
        return remaining > 0 ? remaining : 0;
    }

    /**
     * Returns {@code true} if {@link #deadlineMillis()} has passed.
     */
    public boolean isExpired() {
        return clock.currentTimeMillis() > deadlineMillis;
    }

    /**
     * Throws if this validation is out of time.
     *
     * <p>Call this at the points where a validation can loop or recurse, so that work which is bounded in count but
     * not in cost, such as verifying signatures over a very large RRset, cannot run indefinitely.
     *
     * <p>Running out of time is a {@link DnssecLimitExceededException}, hence
     * {@link DnssecFailureReason#LIMIT_EXCEEDED} and {@link DnssecStatus#BOGUS}, and not
     * {@link DnssecFailureReason#TIMEOUT}. The distinction is not pedantry: the records that made the validation
     * slow came from whoever is being validated, so if slowness produced an insecure answer they would be able to
     * choose it. {@link DnssecFailureReason#TIMEOUT} is for a lookup that never answered, which leaves the
     * validator with nothing at all to judge.
     *
     * @throws DnssecLimitExceededException if the deadline has passed.
     */
    public void checkDeadline() {
        if (isExpired()) {
            throw new DnssecLimitExceededException("validationTimeoutMillis", limits.validationTimeoutMillis());
        }
    }

    /**
     * Consumes one of the {@link DnssecLimits#maxSignatureVerificationsPerValidation()} signature verifications this
     * validation may perform.
     *
     * <p>Spend this immediately before the verification, not after, so that a verification which throws or hangs has
     * still been paid for.
     *
     * @throws DnssecLimitExceededException if the limit has been reached.
     */
    public void spendSignatureVerification() {
        int limit = limits.maxSignatureVerificationsPerValidation();
        if (signatureVerifications >= limit) {
            throw new DnssecLimitExceededException("maxSignatureVerificationsPerValidation", limit);
        }
        signatureVerifications++;
    }

    /**
     * Returns how many signature verifications have been spent so far, never more than
     * {@link DnssecLimits#maxSignatureVerificationsPerValidation()}.
     */
    public int signatureVerifications() {
        return signatureVerifications;
    }

    /**
     * Consumes one of the {@link DnssecLimits#maxFetches()} lookups this validation may issue.
     *
     * @throws DnssecLimitExceededException if the limit has been reached.
     */
    public void spendFetch() {
        int limit = limits.maxFetches();
        if (fetches >= limit) {
            throw new DnssecLimitExceededException("maxFetches", limit);
        }
        fetches++;
    }

    /**
     * Returns how many lookups have been spent so far, never more than {@link DnssecLimits#maxFetches()}.
     */
    public int fetches() {
        return fetches;
    }

    /**
     * Consumes one of the {@link DnssecLimits#maxNsec3HashComputations()} {@code NSEC3} hash computations this
     * validation may perform.
     *
     * <p>One unit is one complete hash of one name, whatever iteration count that name's {@code NSEC3} parameters
     * ask for; the iteration count itself is bounded separately by {@link DnssecLimits#maxNsec3Iterations()}, and
     * the two together are what bound the product that
     * <a href="https://www.cve.org/CVERecord?id=CVE-2023-50868">CVE-2023-50868</a> exploited.
     *
     * @throws DnssecLimitExceededException if the limit has been reached.
     */
    public void spendNsec3HashComputation() {
        int limit = limits.maxNsec3HashComputations();
        if (nsec3HashComputations >= limit) {
            throw new DnssecLimitExceededException("maxNsec3HashComputations", limit);
        }
        nsec3HashComputations++;
    }

    /**
     * Returns how many {@code NSEC3} hash computations have been spent so far, never more than
     * {@link DnssecLimits#maxNsec3HashComputations()}.
     */
    public int nsec3HashComputations() {
        return nsec3HashComputations;
    }

    /**
     * Consumes one of the {@link DnssecLimits#maxDsMatchFailures()} failed {@code DS} to {@code DNSKEY} matches this
     * validation may absorb. Spend it only when the digest was computed and did not match, since a match that never
     * cost a digest costs nothing to allow.
     *
     * @throws DnssecLimitExceededException if the limit has been reached.
     */
    public void spendDsMatchFailure() {
        int limit = limits.maxDsMatchFailures();
        if (dsMatchFailures >= limit) {
            throw new DnssecLimitExceededException("maxDsMatchFailures", limit);
        }
        dsMatchFailures++;
    }

    /**
     * Returns how many failed {@code DS} matches have been spent so far, never more than
     * {@link DnssecLimits#maxDsMatchFailures()}.
     */
    public int dsMatchFailures() {
        return dsMatchFailures;
    }

    /**
     * Consumes one of the {@link DnssecLimits#maxDelegationDepth()} delegations this validation may follow down from
     * the trust anchor.
     *
     * @throws DnssecLimitExceededException if the limit has been reached.
     */
    public void spendDelegation() {
        int limit = limits.maxDelegationDepth();
        if (delegations >= limit) {
            throw new DnssecLimitExceededException("maxDelegationDepth", limit);
        }
        delegations++;
    }

    /**
     * Returns how many delegations have been spent so far, never more than
     * {@link DnssecLimits#maxDelegationDepth()}.
     *
     * <p>A count rather than a depth: a validator that walks back up and down again pays for both directions, which
     * is what makes it a bound on work rather than on shape.
     */
    public int delegations() {
        return delegations;
    }

    /**
     * Consumes one of the {@link DnssecLimits#maxCnameChainLength()} {@code CNAME} or {@code DNAME} links this
     * validation may follow.
     *
     * @throws DnssecLimitExceededException if the limit has been reached.
     */
    public void spendCnameLink() {
        int limit = limits.maxCnameChainLength();
        if (cnameLinks >= limit) {
            throw new DnssecLimitExceededException("maxCnameChainLength", limit);
        }
        cnameLinks++;
    }

    /**
     * Returns how many alias links have been spent so far, never more than
     * {@link DnssecLimits#maxCnameChainLength()}.
     */
    public int cnameLinks() {
        return cnameLinks;
    }

    @Override
    public String toString() {
        return "DnssecBudget(signatureVerifications: " + signatureVerifications + '/'
                + limits.maxSignatureVerificationsPerValidation()
                + ", fetches: " + fetches + '/' + limits.maxFetches()
                + ", nsec3HashComputations: " + nsec3HashComputations + '/' + limits.maxNsec3HashComputations()
                + ", dsMatchFailures: " + dsMatchFailures + '/' + limits.maxDsMatchFailures()
                + ", delegations: " + delegations + '/' + limits.maxDelegationDepth()
                + ", cnameLinks: " + cnameLinks + '/' + limits.maxCnameChainLength()
                + ", deadlineMillis: " + deadlineMillis + ')';
    }
}
