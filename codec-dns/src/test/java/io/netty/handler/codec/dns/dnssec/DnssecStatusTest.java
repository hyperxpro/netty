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
import static org.junit.jupiter.api.Assertions.assertSame;

public class DnssecStatusTest {

    /**
     * The four states of RFC 4033, Section 5, no more and no fewer. A fifth state, or a missing one, would mean
     * somebody has collapsed two of them, which is the mistake the enum exists to prevent.
     */
    @Test
    public void testFourSecurityStates() {
        assertEquals(4, DnssecStatus.values().length);
        assertSame(DnssecStatus.SECURE, DnssecStatus.valueOf("SECURE"));
        assertSame(DnssecStatus.INSECURE, DnssecStatus.valueOf("INSECURE"));
        assertSame(DnssecStatus.BOGUS, DnssecStatus.valueOf("BOGUS"));
        assertSame(DnssecStatus.INDETERMINATE, DnssecStatus.valueOf("INDETERMINATE"));
    }
}
