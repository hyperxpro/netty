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
 * One of the four security states a DNSSEC validator may reach for a response, defined by
 * <a href="https://www.rfc-editor.org/rfc/rfc4033.html#section-5">RFC 4033, Section 5</a> and used by
 * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-4.3">RFC 4035, Section 4.3</a>.
 *
 * <p>The operative rule, stated plainly, because getting it wrong is how a half-finished validator turns into a
 * bypass: <strong>a failure to <em>prove</em> security is {@link #INSECURE} or {@link #INDETERMINATE}; only a proof
 * of <em>inconsistency</em> is {@link #BOGUS}.</strong> The two failure directions are not interchangeable and must
 * never be collapsed into a single "not secure" verdict:</p>
 * <ul>
 *   <li>Reporting a genuine forgery as {@link #INSECURE} hands the attacker the answer, because an application that
 *   treats <em>Insecure</em> as "this zone is simply unsigned" will use data a validator has already shown to be
 *   inconsistent with the chain of trust.</li>
 *   <li>Reporting a legitimately unsigned zone as {@link #BOGUS} breaks resolution for the majority of the DNS,
 *   which is still unsigned, and pushes operators to disable validation altogether.</li>
 * </ul>
 *
 * <p>The direction in which a specific failure resolves is fixed by {@link DnssecFailureReason#impliedStatus()};
 * anything an attacker can provoke on demand, such as exhausting a work limit, must resolve to {@link #BOGUS} so
 * that provoking it is not a downgrade.</p>
 */
public enum DnssecStatus {

    /**
     * "The validating resolver has a trust anchor, has a chain of trust, and is able to verify all the signatures in
     * the response", per <a href="https://www.rfc-editor.org/rfc/rfc4033.html#section-5">RFC 4033, Section 5</a>.
     *
     * <p>This is the only state in which the data may be relied on as authentic. It is also the only state that
     * justifies setting the {@code AD} bit on a response, see
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-3.2.3">RFC 4035, Section 3.2.3</a>.</p>
     */
    SECURE,

    /**
     * "The validating resolver has a trust anchor, a chain of trust, and, at some delegation point, signed proof of
     * the non-existence of a {@code DS} record", per
     * <a href="https://www.rfc-editor.org/rfc/rfc4033.html#section-5">RFC 4033, Section 5</a>. The zone is proven to
     * be unsigned, so there is nothing to validate and the data is served as it would be without DNSSEC.
     *
     * <p>Reaching this state requires an actual proof, either an authenticated denial of the {@code DS} RRset or one
     * of the "treat as unsigned" rules such as
     * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.2">RFC 6840, Section 5.2</a> for a delegation
     * whose {@code DS} records all use algorithms or digest types the validator cannot evaluate. A validator that
     * simply gave up must not report {@code INSECURE}: that would let anyone able to induce the failure strip DNSSEC
     * protection from a signed zone.</p>
     */
    INSECURE,

    /**
     * "The validating resolver has a trust anchor and a secure delegation indicating that subsidiary data is signed,
     * but the response fails to validate", per
     * <a href="https://www.rfc-editor.org/rfc/rfc4033.html#section-5">RFC 4033, Section 5</a>: a missing, expired or
     * forged signature, a broken chain of trust, or an incomplete denial of existence.
     *
     * <p>RFC 4033 notes that this may indicate an attack, but may equally be a configuration error or data
     * corruption. Either way the data must not be returned to the application; a resolver answers {@code SERVFAIL},
     * per <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.5">RFC 4035, Section 5.5</a>.</p>
     */
    BOGUS,

    /**
     * "There is no trust anchor that would indicate that a specific portion of the tree is secure", per
     * <a href="https://www.rfc-editor.org/rfc/rfc4033.html#section-5">RFC 4033, Section 5</a>. The validator has no
     * opinion at all, because it never had the material to form one.
     *
     * <p>This package also uses {@code INDETERMINATE} for a validation that could not be carried out because the
     * data it needed never arrived, for example a {@code DS} or {@code DNSKEY} lookup that failed or timed out.
     * {@code INDETERMINATE} is <strong>not</strong> a licence to serve the data as if it had been checked: it means
     * "unknown", not "unsigned". A resolver that cannot complete validation answers {@code SERVFAIL} rather than
     * downgrading the answer to {@link #INSECURE}.</p>
     */
    INDETERMINATE
}
