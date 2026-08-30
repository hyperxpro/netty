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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnssecClockTest {

    /**
     * The system clock must report epoch milliseconds, not nanoseconds and not an arbitrary origin, because an
     * {@code RRSIG} validity window is stated in seconds since the epoch. The window used here is wide enough never
     * to need revisiting and narrow enough to catch a clock on the wrong scale or with the wrong origin.
     */
    @Test
    public void testSystemClockReportsEpochMillis() {
        assertNotNull(DnssecClock.SYSTEM);
        long now = DnssecClock.SYSTEM.currentTimeMillis();
        long reference = System.currentTimeMillis();
        assertTrue(Math.abs(reference - now) < 60000L, "SYSTEM reported " + now + ", System reported " + reference);
        // 2020-01-01T00:00:00Z and 2100-01-01T00:00:00Z.
        assertTrue(now > 1577836800000L, "not after 2020: " + now);
        assertTrue(now < 4102444800000L, "not before 2100: " + now);
    }

    @Test
    public void testSystemClockHasStableToString() {
        assertEquals("DnssecClock.SYSTEM", DnssecClock.SYSTEM.toString());
    }

    /**
     * A pinned clock is the whole point of the abstraction: the RFC 6605 example signatures expired on 2010-09-09
     * and cannot be exercised at all against the wall clock.
     */
    @Test
    public void testClockCanBePinnedToAnExpiredRfcExample() {
        final long rfc6605ExpirationMillis = 1284001200000L;
        DnssecClock pinned = new DnssecClock() {
            @Override
            public long currentTimeMillis() {
                return rfc6605ExpirationMillis - 1L;
            }
        };
        assertEquals(rfc6605ExpirationMillis - 1L, pinned.currentTimeMillis());
        assertTrue(pinned.currentTimeMillis() < DnssecClock.SYSTEM.currentTimeMillis());
    }
}
