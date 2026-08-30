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

/**
 * The source of wall-clock time a validation uses, so that the time against which signatures are judged can be
 * pinned.
 *
 * <p>DNSSEC is unusual among Netty's protocols in that correctness depends on absolute time. The Signature
 * Inception and Signature Expiration fields of an {@code RRSIG} are seconds since the UNIX epoch compared using the
 * serial number arithmetic of <a href="https://www.rfc-editor.org/rfc/rfc1982.html">RFC 1982</a>, see
 * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-3.1.5">RFC 4034, Section 3.1.5</a>, and a validator
 * with a wrong clock rejects perfectly good signatures or, worse, accepts expired ones.</p>
 *
 * <p>This is not an aesthetic nicety, it is what makes the specifications testable:</p>
 * <ul>
 *   <li>The worked examples in <a href="https://www.rfc-editor.org/rfc/rfc6605.html#section-6">RFC 6605,
 *   Section 6</a> carry signatures that expired on 2010-09-09, and those in
 *   <a href="https://www.rfc-editor.org/rfc/rfc5702.html#section-6">RFC 5702, Section 6</a> expire on 2030-01-01.
 *   Without a pinned clock the first set can never be exercised end to end and the second silently stops being
 *   exercised on a date nobody will be watching for.</li>
 *   <li>The RFC 1982 wrap-around, which is the whole reason the comparison is not a plain {@code <}, only happens
 *   at times roughly 68 years away from the values in the record. It is unreachable without control of the clock.</li>
 * </ul>
 *
 * <p>Deliberately not {@link io.netty.util.concurrent.Ticker}: that abstraction is built on
 * {@link System#nanoTime()}, which is monotonic and has no defined relationship to the epoch, whereas an
 * {@code RRSIG} is stamped in wall-clock seconds. A monotonic clock is the right tool for the validation deadline
 * of {@link DnssecBudget} and the wrong one for signature validity, and mixing them up produces a validator that
 * happens to work until the machine's clock is stepped.</p>
 */
public interface DnssecClock {

    /**
     * A clock that reports {@link System#currentTimeMillis()}.
     */
    DnssecClock SYSTEM = new DnssecClock() {
        @Override
        public long currentTimeMillis() {
            return System.currentTimeMillis();
        }

        @Override
        public String toString() {
            return "DnssecClock.SYSTEM";
        }
    };

    /**
     * Returns the current time in milliseconds since 1970-01-01T00:00:00Z, on the same scale as
     * {@link System#currentTimeMillis()}.
     *
     * <p>Implementations should be cheap enough to call once per record, and must be safe to call from whichever
     * thread drives the validation.</p>
     */
    long currentTimeMillis();
}
