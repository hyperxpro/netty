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
 * Raised by {@link DnssecBudget} when a validation asks for more work, or more time, than the {@link DnssecLimits}
 * it was given allow.
 *
 * <p>This is a hard failure. It maps to {@link DnssecFailureReason#LIMIT_EXCEEDED} and therefore to
 * {@link DnssecStatus#BOGUS}, never to {@link DnssecStatus#INSECURE}: the records that drive the work come from the
 * other side of the wire, so whoever supplies them decides whether a limit is reached, and a limit breach that
 * downgraded a zone to <em>Insecure</em> would be a downgrade oracle rather than a defence.</p>
 *
 * <p>{@link #limitName()} names the knob that ran out, which is what an operator needs in order to decide whether a
 * limit is genuinely too tight or whether they are looking at an attack.</p>
 *
 * <p><strong>To cover the whole validation path, catch
 * {@link io.netty.handler.codec.DecoderException DecoderException}, not {@link DnssecException}.</strong> This class
 * is a {@link DnssecException}, which is itself a {@code DecoderException}, but the wire parsers a validation drives
 * report their own failures as {@link io.netty.handler.codec.CorruptedFrameException CorruptedFrameException}, which
 * is a <em>sibling</em> {@code DecoderException} and not a {@code DnssecException}. A truncated name or a malformed
 * {@code NSEC} type bit map therefore slips straight through a {@code catch (DnssecException)} and surfaces as a
 * decode failure at the pipeline instead of becoming the {@link DnssecStatus#BOGUS} verdict it is: the answer is
 * inconsistent with what the zone signed, which is precisely a validation failure. {@code DecoderException} is the
 * narrowest type that covers both.</p>
 */
public final class DnssecLimitExceededException extends DnssecException {

    private static final long serialVersionUID = -4297013281539672847L;

    private final String limitName;
    private final long limit;

    /**
     * Creates a new instance.
     *
     * @param limitName the name of the exhausted limit, for example {@code "maxFetches"}.
     * @param limit     the value of that limit.
     */
    public DnssecLimitExceededException(String limitName, long limit) {
        super("DNSSEC validation limit exceeded: " + ObjectUtil.checkNotNull(limitName, "limitName")
                + " (limit: " + limit + ')');
        this.limitName = limitName;
        this.limit = limit;
    }

    /**
     * Returns the name of the limit that was exhausted, which is the name of the corresponding
     * {@link DnssecLimits} accessor.
     */
    public String limitName() {
        return limitName;
    }

    /**
     * Returns the value of the exhausted limit, in whatever unit that limit is expressed in.
     */
    public long limit() {
        return limit;
    }
}
