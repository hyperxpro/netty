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

/**
 * What {@link DnssecSignatureVerifier} concluded about one RRset.
 *
 * <p>This is a verdict about a single RRset and its {@code RRSIG}s, not about a whole answer. It says nothing about
 * whether the key that validated the signature is itself trusted, whether the records are in bailiwick, or whether
 * a wildcard answer came with the denial-of-existence proof it needs. Those belong to the chain of trust, which
 * builds on this.</p>
 *
 * <p>{@link #status()} is derived from {@link #reason()} through {@link DnssecFailureReason#impliedStatus()}, so
 * the two can never disagree. The distinction that matters is between {@link DnssecStatus#BOGUS} and
 * {@link DnssecStatus#INSECURE}: <em>Bogus</em> means the verifier holds proof that the answer is inconsistent with
 * what the zone signed, and <em>Insecure</em> means it could not evaluate the material at all, which
 * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.2">RFC 4035, Section 5.2</a> treats as unsigned.
 * Conflating them in either direction is how half-validators become bypasses.</p>
 */
public final class DnssecVerificationResult {

    private final DnssecFailureReason reason;
    private final String message;
    private final DnsRrsigRecord signature;
    private final DnsDnskeyRecord key;
    private final DnsName signedOwner;
    private final boolean wildcardExpanded;

    private DnssecVerificationResult(DnssecFailureReason reason, String message, DnsRrsigRecord signature,
                                     DnsDnskeyRecord key, DnsName signedOwner, boolean wildcardExpanded) {
        this.reason = reason;
        this.message = message;
        this.signature = signature;
        this.key = key;
        this.signedOwner = signedOwner;
        this.wildcardExpanded = wildcardExpanded;
    }

    static DnssecVerificationResult secure(DnsRrsigRecord signature, DnsDnskeyRecord key, DnsName signedOwner,
                                           boolean wildcardExpanded) {
        return new DnssecVerificationResult(DnssecFailureReason.NONE,
                "verified by DNSKEY " + key.keyTag() + ' ' + key.algorithm() + " over " + signedOwner,
                signature, key, signedOwner, wildcardExpanded);
    }

    static DnssecVerificationResult failed(DnssecFailureReason reason, String message) {
        return new DnssecVerificationResult(ObjectUtil.checkNotNull(reason, "reason"),
                ObjectUtil.checkNotNull(message, "message"), null, null, null, false);
    }

    /**
     * Returns {@code true} if the RRset carries a valid signature made by one of the offered keys, that is if
     * {@link #status()} is {@link DnssecStatus#SECURE}.
     *
     * <p>"Secure" here is relative to the keys that were offered. Whether those keys are the zone's real keys is a
     * question about the chain of trust and is answered elsewhere.</p>
     */
    public boolean isSecure() {
        return reason == DnssecFailureReason.NONE;
    }

    /**
     * Returns the verdict, which is {@link DnssecFailureReason#impliedStatus()} of {@link #reason()}.
     */
    public DnssecStatus status() {
        return reason.impliedStatus();
    }

    /**
     * Returns why verification ended as it did, or {@link DnssecFailureReason#NONE} if it succeeded. Where several
     * {@code RRSIG}s failed for different reasons this is the one that got furthest through the checks, since that
     * is the one that tells an operator the most.
     */
    public DnssecFailureReason reason() {
        return reason;
    }

    /**
     * Returns a human-readable explanation, never {@code null}. Intended for logs and for the message of an
     * exception a caller raises; the machine-readable form is {@link #reason()}.
     */
    public String message() {
        return message;
    }

    /**
     * Returns the {@code RRSIG} that validated the RRset, or {@code null} if none did.
     *
     * <p><a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.4">RFC 6840, Section 5.4</a>: any single
     * valid {@code RRSIG} is sufficient, so this is the first one that verified and the others were not examined.
     * That is not only permitted but wanted; BIND's
     * <a href="https://www.cve.org/CVERecord?id=CVE-2026-11605">CVE-2026-11605</a> came of continuing to verify
     * signatures after one had already succeeded.</p>
     */
    public DnsRrsigRecord signature() {
        return signature;
    }

    /**
     * Returns the {@code DNSKEY} whose signature verified, or {@code null} if none did. A caller walking a chain of
     * trust needs this to know which key it now has to justify.
     */
    public DnsDnskeyRecord key() {
        return key;
    }

    /**
     * Returns the owner name the signature was actually computed over, or {@code null} if verification failed.
     *
     * <p>This is the RRset's own owner name for an ordinary answer, and the wildcard name {@code *.} followed by
     * the rightmost {@code RRSIG} Labels labels when {@link #isWildcardExpanded()} is {@code true}.</p>
     */
    public DnsName signedOwner() {
        return signedOwner;
    }

    /**
     * Returns {@code true} if the answer was synthesised from a wildcard, so that the signature covers
     * {@link #signedOwner()} rather than the name in the response.
     *
     * <p><strong>A caller must not treat such an answer as authentic on this result alone.</strong> RFC 4035,
     * Section 5.3.4 requires it to additionally obtain an authenticated denial of existence for the queried name:
     * without it, a valid wildcard signature can be replayed over a name the zone answers explicitly, which is a
     * substitution of one answer for another rather than a forgery of either.</p>
     */
    public boolean isWildcardExpanded() {
        return wildcardExpanded;
    }

    @Override
    public String toString() {
        return "DnssecVerificationResult(" + status() + ", " + reason + ": " + message
                + (wildcardExpanded ? ", wildcard expanded" : "") + ')';
    }
}
