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

import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.DecoderException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnssecBudgetTest {

    /**
     * A clock the test moves by hand, which is what makes the deadline assertions deterministic instead of a race
     * against the machine.
     */
    private static final class FakeClock implements DnssecClock {

        private long millis;

        FakeClock(long millis) {
            this.millis = millis;
        }

        void advance(long delta) {
            millis += delta;
        }

        void set(long millis) {
            this.millis = millis;
        }

        @Override
        public long currentTimeMillis() {
            return millis;
        }
    }

    private static DnssecBudget newBudget(DnssecLimits limits) {
        return new DnssecBudget(limits, new FakeClock(1000000L));
    }

    @Test
    public void testRejectsNullArguments() {
        assertThrows(NullPointerException.class, () -> new DnssecBudget(null, DnssecClock.SYSTEM));
        assertThrows(NullPointerException.class, () -> new DnssecBudget(DnssecLimits.defaults(), null));
    }

    @Test
    public void testStartsEmpty() {
        DnssecBudget budget = newBudget(DnssecLimits.defaults());
        assertEquals(0, budget.signatureVerifications());
        assertEquals(0, budget.fetches());
        assertEquals(0, budget.nsec3HashComputations());
        assertEquals(0, budget.dsMatchFailures());
        assertEquals(0, budget.delegations());
        assertEquals(0, budget.cnameLinks());
        assertSame(DnssecLimits.defaults(), budget.limits());
    }

    /**
     * The point of the counters: the bound is asserted as a count of operations, which is a property of the
     * validator, rather than as an elapsed time, which is a property of the machine the test happens to run on.
     */
    @Test
    public void testSignatureVerificationsAreBoundedExactly() {
        DnssecLimits limits = DnssecLimits.newBuilder()
                .maxSignatureVerificationsPerRrset(2)
                .maxSignatureVerificationsPerValidation(5)
                .build();
        DnssecBudget budget = newBudget(limits);

        // An attacker-shaped loop: keep asking until it is refused.
        int spent = 0;
        for (int i = 0; i < 1000; i++) {
            try {
                budget.spendSignatureVerification();
                spent++;
            } catch (DnssecLimitExceededException e) {
                assertEquals("maxSignatureVerificationsPerValidation", e.limitName());
                assertEquals(5L, e.limit());
                break;
            }
        }
        assertEquals(5, spent);
        assertEquals(5, budget.signatureVerifications());
    }

    /**
     * A refused spend must not advance the counter, otherwise a caller that swallows the exception could push a
     * counter past its own limit and the getters would stop being a truthful account of the work done.
     */
    @Test
    public void testRefusedSpendDoesNotAdvanceTheCounter() {
        DnssecBudget budget = newBudget(DnssecLimits.newBuilder().maxFetches(1).build());
        budget.spendFetch();
        assertEquals(1, budget.fetches());
        for (int i = 0; i < 5; i++) {
            assertThrows(DnssecLimitExceededException.class, budget::spendFetch);
        }
        assertEquals(1, budget.fetches());
    }

    /**
     * Unbound's CVE-2026-50045 was a quota that validation restarts put back. A budget carried across a retry must
     * stay as depleted as it was left, so there is no reset and re-running the same work simply fails immediately.
     */
    @Test
    public void testExhaustedBudgetIsNotRestoredByARetry() {
        DnssecBudget budget = newBudget(DnssecLimits.newBuilder().maxNsec3HashComputations(3).build());
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                for (;;) {
                    budget.spendNsec3HashComputation();
                }
            } catch (DnssecLimitExceededException expected) {
                // The whole quota is spent on the first attempt and none of it comes back.
                assertEquals("maxNsec3HashComputations", expected.limitName());
            }
            assertEquals(3, budget.nsec3HashComputations());
        }
    }

    @Test
    public void testEveryCounterHasItsOwnLimit() {
        DnssecLimits limits = DnssecLimits.newBuilder()
                .maxSignatureVerificationsPerRrset(1)
                .maxSignatureVerificationsPerValidation(1)
                .maxFetches(2)
                .maxNsec3HashComputations(3)
                .maxDsMatchFailures(4)
                .maxDelegationDepth(5)
                .maxCnameChainLength(6)
                .build();
        DnssecBudget budget = newBudget(limits);

        spendUntilRefused(budget, "maxSignatureVerificationsPerValidation");
        spendUntilRefused(budget, "maxFetches");
        spendUntilRefused(budget, "maxNsec3HashComputations");
        spendUntilRefused(budget, "maxDsMatchFailures");
        spendUntilRefused(budget, "maxDelegationDepth");
        spendUntilRefused(budget, "maxCnameChainLength");

        assertEquals(1, budget.signatureVerifications());
        assertEquals(2, budget.fetches());
        assertEquals(3, budget.nsec3HashComputations());
        assertEquals(4, budget.dsMatchFailures());
        assertEquals(5, budget.delegations());
        assertEquals(6, budget.cnameLinks());
    }

    private static void spendUntilRefused(DnssecBudget budget, String limitName) {
        for (int i = 0; i < 1000; i++) {
            try {
                spend(budget, limitName);
            } catch (DnssecLimitExceededException e) {
                assertEquals(limitName, e.limitName());
                return;
            }
        }
        throw new AssertionError(limitName + " was never refused");
    }

    private static void spend(DnssecBudget budget, String limitName) {
        if ("maxSignatureVerificationsPerValidation".equals(limitName)) {
            budget.spendSignatureVerification();
        } else if ("maxFetches".equals(limitName)) {
            budget.spendFetch();
        } else if ("maxNsec3HashComputations".equals(limitName)) {
            budget.spendNsec3HashComputation();
        } else if ("maxDsMatchFailures".equals(limitName)) {
            budget.spendDsMatchFailure();
        } else if ("maxDelegationDepth".equals(limitName)) {
            budget.spendDelegation();
        } else if ("maxCnameChainLength".equals(limitName)) {
            budget.spendCnameLink();
        } else {
            throw new AssertionError("unknown limit: " + limitName);
        }
    }

    @Test
    public void testDeadlineIsFixedAtConstruction() {
        FakeClock clock = new FakeClock(1000L);
        DnssecLimits limits = DnssecLimits.newBuilder().validationTimeoutMillis(500L).build();
        DnssecBudget budget = new DnssecBudget(limits, clock);

        assertEquals(1000L, budget.startTimeMillis());
        assertEquals(1500L, budget.deadlineMillis());
        assertEquals(500L, budget.remainingMillis());
        assertFalse(budget.isExpired());
        budget.checkDeadline();

        // Exactly at the deadline is still inside it.
        clock.set(1500L);
        assertFalse(budget.isExpired());
        assertEquals(0L, budget.remainingMillis());
        budget.checkDeadline();

        clock.advance(1L);
        assertTrue(budget.isExpired());
        assertEquals(0L, budget.remainingMillis());
        DnssecLimitExceededException e =
                assertThrows(DnssecLimitExceededException.class, budget::checkDeadline);
        assertEquals("validationTimeoutMillis", e.limitName());
        assertEquals(500L, e.limit());
    }

    /**
     * Running out of time is a limit breach, not a network timeout: the records that made the validation slow came
     * from the party being validated, so it must fail Bogus rather than downgrade the answer.
     */
    @Test
    public void testDeadlineBreachIsALimitExceededException() {
        FakeClock clock = new FakeClock(0L);
        DnssecBudget budget = new DnssecBudget(DnssecLimits.newBuilder().validationTimeoutMillis(1L).build(), clock);
        clock.set(1000L);
        DnssecLimitExceededException e =
                assertThrows(DnssecLimitExceededException.class, budget::checkDeadline);
        assertSame(DnssecStatus.BOGUS, DnssecFailureReason.LIMIT_EXCEEDED.impliedStatus());
        assertTrue(e.getMessage().contains("validationTimeoutMillis"), e.getMessage());
    }

    /**
     * Pins the hierarchy the Javadoc of {@link DnssecLimitExceededException} tells callers to rely on. A validation
     * drives wire parsers that report their failures as {@link CorruptedFrameException}, a sibling of
     * {@link DnssecException} under {@link DecoderException} rather than a subclass of it, so
     * {@code catch (DnssecException)} silently misses a truncated name or a malformed NSEC type bit map and
     * {@link DecoderException} is the narrowest type that covers both. If anything ever reparents these, the advice
     * in that Javadoc becomes wrong and this fails.
     */
    @Test
    public void testDecoderExceptionIsTheNarrowestCatchForTheWholeValidationPath() {
        assertTrue(DnssecException.class.isAssignableFrom(DnssecLimitExceededException.class));
        assertTrue(DecoderException.class.isAssignableFrom(DnssecException.class));
        assertTrue(DecoderException.class.isAssignableFrom(CorruptedFrameException.class));
        assertFalse(DnssecException.class.isAssignableFrom(CorruptedFrameException.class));

        FakeClock clock = new FakeClock(0L);
        DnssecBudget budget = new DnssecBudget(DnssecLimits.newBuilder().validationTimeoutMillis(1L).build(), clock);
        clock.set(1000L);
        assertThrows(DecoderException.class, budget::checkDeadline);
    }

    /**
     * A clock near the end of the long range must not wrap the deadline into the past and expire the budget before
     * it has done anything.
     */
    @Test
    public void testDeadlineDoesNotOverflow() {
        FakeClock clock = new FakeClock(Long.MAX_VALUE - 10L);
        DnssecBudget budget = new DnssecBudget(DnssecLimits.defaults(), clock);
        assertEquals(Long.MAX_VALUE, budget.deadlineMillis());
        assertFalse(budget.isExpired());
        budget.checkDeadline();
    }

    @Test
    public void testToStringShowsSpendAgainstLimits() {
        DnssecBudget budget = newBudget(DnssecLimits.defaults());
        budget.spendFetch();
        String text = budget.toString();
        assertTrue(text.startsWith("DnssecBudget("), text);
        assertTrue(text.contains("fetches: 1/24"), text);
        assertTrue(text.contains("signatureVerifications: 0/32"), text);
    }
}
