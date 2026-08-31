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
import io.netty.util.internal.ObjectUtil;

import java.util.Collections;
import java.util.List;

/**
 * What a {@link DnssecValidator} concluded about one response: the security state, why it reached it, and the
 * chain of reasoning that got it there.
 *
 * <p>Nothing here is reference-counted and nothing here points into the response that was validated. Everything the
 * validator retained is released before this object is published, so it may be logged, cached, put on a queue or
 * handed to another thread without any further thought about lifetimes. That is also why it does not carry the
 * validated RRsets: doing so would make the result own the answer's buffers, and the caller would have to release
 * a verdict.
 *
 * <p>{@link #status()} is {@link DnssecFailureReason#impliedStatus()} of {@link #reason()}, so the two can never
 * disagree. Only {@link DnssecStatus#SECURE} means the data may be relied on. The three failure states are not
 * interchangeable:
 * <ul>
 *   <li>{@link DnssecStatus#INSECURE} is a <em>proof</em> that the data is unsigned — an authenticated denial of
 *   the {@code DS} RRset at a delegation, an opt-out span, or a delegation whose {@code DS} records name only
 *   algorithms this build cannot evaluate. {@link #insecureDelegation()} names the cut where that happened.</li>
 *   <li>{@link DnssecStatus#BOGUS} is a proof of <em>inconsistency</em>: something is signed and the signature does
 *   not hold up. Exceeding any of the {@link DnssecLimits} lands here too, so that provoking a limit is not a way
 *   to obtain the weaker Insecure verdict.</li>
 *   <li>{@link DnssecStatus#INDETERMINATE} is the absence of an opinion: no trust anchor covers the name, or a
 *   lookup the chain walk needed never answered. {@link #cause()} carries the failure in the second case. It is
 *   not a licence to use the data.</li>
 * </ul>
 *
 * <p>{@link #trace()} is the human-readable record of the walk — the zones whose keys were established, the
 * delegations followed, the RRsets verified, and the step that ended it. It is what {@code delv} prints, and it is
 * the difference between "Bogus" and an operator being able to act on "Bogus". It is diagnostic output: its
 * contents are not part of the API contract and must not be parsed.
 */
public final class DnssecValidationResult {

    private final DnssecFailureReason reason;
    private final String message;
    private final DnsName signerName;
    private final DnsName insecureDelegation;
    private final Throwable cause;
    private final List<String> trace;
    private final DnssecBudget budget;

    DnssecValidationResult(DnssecFailureReason reason, String message, DnsName signerName,
                           DnsName insecureDelegation, Throwable cause, List<String> trace, DnssecBudget budget) {
        this.reason = ObjectUtil.checkNotNull(reason, "reason");
        this.message = ObjectUtil.checkNotNull(message, "message");
        this.signerName = signerName;
        this.insecureDelegation = insecureDelegation;
        this.cause = cause;
        this.trace = Collections.unmodifiableList(trace);
        this.budget = ObjectUtil.checkNotNull(budget, "budget");
    }

    /**
     * Returns {@code true} if the response validated, that is if {@link #status()} is
     * {@link DnssecStatus#SECURE}.
     */
    public boolean isSecure() {
        return reason == DnssecFailureReason.NONE;
    }

    /**
     * Returns the security state, which is {@link DnssecFailureReason#impliedStatus()} of {@link #reason()}.
     */
    public DnssecStatus status() {
        return reason.impliedStatus();
    }

    /**
     * Returns the machine-readable reason. {@link DnssecFailureReason#extendedDnsErrorCode()} maps it onto the
     * <a href="https://www.rfc-editor.org/rfc/rfc8914.html">RFC 8914</a> Extended DNS Error registry, so a resolver
     * relaying this verdict can emit it unchanged.
     */
    public DnssecFailureReason reason() {
        return reason;
    }

    /**
     * Returns a human-readable explanation of {@link #reason()}, never {@code null}.
     */
    public String message() {
        return message;
    }

    /**
     * Returns the zone whose keys authenticated the answer, or {@code null} if none did.
     *
     * <p>This is the zone the chain walk arrived at, not the Signer's Name an {@code RRSIG} claimed. The two agree
     * whenever the answer is Secure, precisely because the walk decides which keys are offered to the verifier and
     * the verifier only considers an {@code RRSIG} whose Signer's Name is the owner of one of them.
     */
    public DnsName signerName() {
        return signerName;
    }

    /**
     * Returns the delegation at which the chain of trust ended, or {@code null} if it did not end early.
     *
     * <p>Non-{@code null} exactly when {@link #status()} is {@link DnssecStatus#INSECURE} for a proven-unsigned
     * delegation: this is the child zone whose {@code DS} RRset was proven absent, was covered by an opt-out span,
     * or named only algorithms this build cannot evaluate. Everything at or below it is unsigned as far as this
     * validator is concerned.
     */
    public DnsName insecureDelegation() {
        return insecureDelegation;
    }

    /**
     * Returns the failure that stopped the validation, or {@code null} if none did.
     *
     * <p>Non-{@code null} for an {@link DnssecStatus#INDETERMINATE} caused by a
     * {@link DnssecRecordFetcher#fetch(DnsName, io.netty.handler.codec.dns.DnsRecordType) fetch} that failed, in
     * which case it is that fetch's cause. A validator never invents one: an absent cause means the verdict came
     * from the data rather than from a broken lookup.
     */
    public Throwable cause() {
        return cause;
    }

    /**
     * Returns the steps the validation took, oldest first. Unmodifiable, never {@code null}, and diagnostic only.
     */
    public List<String> trace() {
        return trace;
    }

    /**
     * Returns the work quota of this validation, with its counters at the values they finished on: how many
     * signatures were verified, lookups issued, delegations followed and alias links taken.
     *
     * <p>One budget belongs to one {@code validate} call and is never reset by anything the response can provoke,
     * which is what Unbound's <a href="https://www.cve.org/CVERecord?id=CVE-2026-50045">CVE-2026-50045</a> got
     * wrong. Reading the counters after the future has completed is safe: completing the future publishes them.
     */
    public DnssecBudget budget() {
        return budget;
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder(128);
        buf.append("DnssecValidationResult(").append(status()).append(", ").append(reason).append(": ")
                .append(message);
        if (signerName != null) {
            buf.append(", signed by ").append(signerName);
        }
        if (insecureDelegation != null) {
            buf.append(", insecure from ").append(insecureDelegation);
        }
        return buf.append(')').toString();
    }
}
