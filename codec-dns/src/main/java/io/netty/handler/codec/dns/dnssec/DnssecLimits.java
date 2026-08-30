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
 * The bounds a DNSSEC validation is willing to work within, immutable once built.
 *
 * <p><a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.4">RFC 4035, Section 5.4</a> already tells a
 * validator that it "MUST bound the work it performs"; the decade since has turned that sentence into a list of
 * named vulnerabilities. Every knob here exists because some validator did not have it:</p>
 * <ul>
 *   <li><a href="https://www.cve.org/CVERecord?id=CVE-2023-50387">CVE-2023-50387</a>, KeyTrap: a single response can
 *   demand tens of thousands of signature verifications, because the key tag is a checksum rather than an
 *   identifier and a conforming validator is told to try every key that matches it.</li>
 *   <li><a href="https://www.cve.org/CVERecord?id=CVE-2023-50868">CVE-2023-50868</a>, NSEC3 closest-encloser: the
 *   number of hash computations a proof can demand is a product of records and iterations.</li>
 * </ul>
 *
 * <p>The defaults are taken from what deployed validators settled on after those disclosures and are quoted on each
 * accessor. They are deliberately generous enough not to reject real zones and deliberately far below what an
 * attacker needs.</p>
 *
 * <p>Reaching a limit is {@link DnssecFailureReason#LIMIT_EXCEEDED}, and therefore
 * {@link DnssecStatus#BOGUS}. Anything else would let whoever chose the records choose the security state.</p>
 *
 * <pre>
 * DnssecLimits limits = DnssecLimits.newBuilder()
 *         .maxNsec3Iterations(50)
 *         .validationTimeoutMillis(2000)
 *         .build();
 * </pre>
 */
public final class DnssecLimits {

    private static final DnssecLimits DEFAULTS = new Builder().build();

    private final int maxSignatureVerificationsPerRrset;
    private final int maxSignatureVerificationsPerValidation;
    private final int maxDsMatchFailures;
    private final int maxDnskeysPerKeyTag;
    private final int maxDnskeysPerRrset;
    private final int maxDsRecordsPerRrset;
    private final int maxNsec3Iterations;
    private final int maxNsec3IterationsHardFail;
    private final int maxNsec3HashComputations;
    private final int maxNsec3SaltLength;
    private final int maxNsecRecordsPerProof;
    private final int maxNsec3RecordsPerProof;
    private final int maxDelegationDepth;
    private final int maxFetches;
    private final int maxCnameChainLength;
    private final int maxRecordsPerSection;
    private final int minimumRsaKeySizeBits;
    private final long validationTimeoutMillis;
    private final long clockSkewSeconds;
    private final boolean allowSha1Signatures;
    private final boolean allowSha1DsDigest;

    private DnssecLimits(Builder builder) {
        maxSignatureVerificationsPerRrset = builder.maxSignatureVerificationsPerRrset;
        maxSignatureVerificationsPerValidation = builder.maxSignatureVerificationsPerValidation;
        maxDsMatchFailures = builder.maxDsMatchFailures;
        maxDnskeysPerKeyTag = builder.maxDnskeysPerKeyTag;
        maxDnskeysPerRrset = builder.maxDnskeysPerRrset;
        maxDsRecordsPerRrset = builder.maxDsRecordsPerRrset;
        maxNsec3Iterations = builder.maxNsec3Iterations;
        maxNsec3IterationsHardFail = builder.maxNsec3IterationsHardFail;
        maxNsec3HashComputations = builder.maxNsec3HashComputations;
        maxNsec3SaltLength = builder.maxNsec3SaltLength;
        maxNsecRecordsPerProof = builder.maxNsecRecordsPerProof;
        maxNsec3RecordsPerProof = builder.maxNsec3RecordsPerProof;
        maxDelegationDepth = builder.maxDelegationDepth;
        maxFetches = builder.maxFetches;
        maxCnameChainLength = builder.maxCnameChainLength;
        maxRecordsPerSection = builder.maxRecordsPerSection;
        minimumRsaKeySizeBits = builder.minimumRsaKeySizeBits;
        validationTimeoutMillis = builder.validationTimeoutMillis;
        clockSkewSeconds = builder.clockSkewSeconds;
        allowSha1Signatures = builder.allowSha1Signatures;
        allowSha1DsDigest = builder.allowSha1DsDigest;
    }

    /**
     * Returns the shared instance holding the default value of every knob, as documented on each accessor.
     */
    public static DnssecLimits defaults() {
        return DEFAULTS;
    }

    /**
     * Returns a new {@link Builder} pre-loaded with the defaults.
     */
    public static Builder newBuilder() {
        return new Builder();
    }

    /**
     * Returns a new {@link Builder} pre-loaded with the values of {@code limits}, so a single knob can be changed
     * without restating the rest.
     *
     * @param limits the limits to copy.
     */
    public static Builder newBuilder(DnssecLimits limits) {
        return new Builder(ObjectUtil.checkNotNull(limits, "limits"));
    }

    /**
     * The greatest number of signature verifications that may be attempted for one RRset. Defaults to {@code 8},
     * which is Unbound's {@code MAX_VALIDATE_AT_ONCE}, dnsjava's {@code max_validate_rrsigs} and the figure
     * Akamai published after KeyTrap.
     *
     * <p><strong>This limit deliberately violates
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.3.1">RFC 4035, Section 5.3.1</a></strong>,
     * which requires a validator to try <em>every</em> {@code DNSKEY} whose owner name, algorithm and key tag match
     * the {@code RRSIG} before declaring the RRset bogus. Honouring that unconditionally is
     * <a href="https://www.cve.org/CVERecord?id=CVE-2023-50387">CVE-2023-50387</a> (KeyTrap): the key tag of
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#appendix-B">RFC 4034, Appendix B</a> is a 16-bit
     * checksum, not a unique identifier, so a zone may publish arbitrarily many keys that all "match" one signature
     * and force a verification each.</p>
     *
     * <p>The deviation is where the specification is heading rather than a private shortcut:
     * <a href="https://www.rfc-editor.org/errata/eid8037">RFC 4035 Errata 8037</a>, Held for Document Update,
     * proposes changing that {@code MUST} to a {@code SHOULD} and cites the CVE as the reason.</p>
     *
     * <p>The cost of the deviation is a false negative in the pathological case where a legitimate zone publishes
     * more than this many colliding keys, which does not happen by accident.</p>
     */
    public int maxSignatureVerificationsPerRrset() {
        return maxSignatureVerificationsPerRrset;
    }

    /**
     * The greatest number of signature verifications that may be attempted across a whole validation, however many
     * RRsets it touches. Defaults to {@code 32}.
     *
     * <p>The per-RRset limit alone is not enough. A response may carry many RRsets, each within its own budget, so
     * the total work stays quadratic in the size of the response: this is the "KeySigTrap" shape of KeyTrap, where
     * <em>n</em> keys and <em>n</em> signatures multiply. dnsjava has no per-message cap and is quadratic for
     * exactly that reason.</p>
     *
     * <p>Must be at least {@link #maxSignatureVerificationsPerRrset()}, otherwise the per-RRset limit could never be
     * reached and one of the two would be silently dead.</p>
     */
    public int maxSignatureVerificationsPerValidation() {
        return maxSignatureVerificationsPerValidation;
    }

    /**
     * The greatest number of {@code DS} records that may fail to match a {@code DNSKEY} before the delegation is
     * abandoned. Defaults to {@code 4}, which is dnsjava's {@code max_ds_match_failures}.
     *
     * <p>Matching a {@code DS} means hashing a candidate {@code DNSKEY}, so a parent that publishes many
     * non-matching {@code DS} records buys a digest computation each. A real delegation needs one or two.</p>
     */
    public int maxDsMatchFailures() {
        return maxDsMatchFailures;
    }

    /**
     * The greatest number of {@code DNSKEY} records sharing a single key tag that may be considered. Defaults to
     * {@code 2}.
     *
     * <p>This is the narrowest and most direct answer to KeyTrap. Key tags are not unique, and a collision is cheap
     * to manufacture, so a zone can publish a wall of keys that all appear to match one signature. Two is enough for
     * the accidental collisions that occur in practice during a key roll, and far short of the "LockCram" primitive
     * that piles colliding keys into one RRset.</p>
     */
    public int maxDnskeysPerKeyTag() {
        return maxDnskeysPerKeyTag;
    }

    /**
     * The greatest number of {@code DNSKEY} records accepted in one zone's key set. Defaults to {@code 16}.
     *
     * <p>A zone in the middle of an algorithm roll publishes a handful; anything approaching this many is a zone
     * trying to make the validator's grouping and matching work expensive.</p>
     */
    public int maxDnskeysPerRrset() {
        return maxDnskeysPerRrset;
    }

    /**
     * The greatest number of {@code DS} records accepted in one delegation. Defaults to {@code 16}.
     */
    public int maxDsRecordsPerRrset() {
        return maxDsRecordsPerRrset;
    }

    /**
     * The greatest {@code NSEC3} iteration count that is still validated. Defaults to {@code 100}.
     *
     * <p><a href="https://www.rfc-editor.org/rfc/rfc9276.html#appendix-A">RFC 9276, Appendix A</a> describes exactly
     * this two-threshold scheme: above a first bound the validator should "return an insecure response", and above a
     * second, higher bound a "SERVFAIL" (bogus). A count above this one is reported as
     * {@link DnssecFailureReason#NSEC3_ITERATIONS_TOO_HIGH}; RFC 9276, Section 3.1 asks zones to publish an
     * iteration count of zero, so no correctly operated zone is affected.</p>
     */
    public int maxNsec3Iterations() {
        return maxNsec3Iterations;
    }

    /**
     * The {@code NSEC3} iteration count above which the answer is rejected outright rather than downgraded.
     * Defaults to {@code 500}, the higher of the two bounds of
     * <a href="https://www.rfc-editor.org/rfc/rfc9276.html#appendix-A">RFC 9276, Appendix A</a>.
     *
     * <p>A count above this is {@link DnssecFailureReason#LIMIT_EXCEEDED} and therefore
     * {@link DnssecStatus#BOGUS}. Keeping the "insecure" band between
     * {@link #maxNsec3Iterations()} and this value narrow is what stops the softer threshold from being a useful
     * downgrade lever.</p>
     *
     * <p>Must be at least {@link #maxNsec3Iterations()}.</p>
     */
    public int maxNsec3IterationsHardFail() {
        return maxNsec3IterationsHardFail;
    }

    /**
     * The greatest number of {@code NSEC3} hash computations one validation may perform. Defaults to {@code 64}.
     *
     * <p>The iteration bound alone is not sufficient, because the cost of a denial-of-existence proof is the number
     * of names hashed multiplied by the iterations for each. That product is
     * <a href="https://www.cve.org/CVERecord?id=CVE-2023-50868">CVE-2023-50868</a>, and the "HashTrap" variant makes
     * it quadratic by pairing many {@code NSEC3} records with a deep query name so the closest-encloser search walks
     * every combination.</p>
     */
    public int maxNsec3HashComputations() {
        return maxNsec3HashComputations;
    }

    /**
     * The greatest {@code NSEC3} salt length accepted, in octets. Defaults to {@code 32}.
     *
     * <p>The wire format allows up to 255, but
     * <a href="https://www.rfc-editor.org/rfc/rfc9276.html#section-3.1">RFC 9276, Section 3.1</a> says an
     * additional salt "provides no additional protection" and asks zones to use none at all, so any salt at all is
     * already unusual and a long one is a sign of a zone optimising the validator's hashing cost.</p>
     */
    public int maxNsec3SaltLength() {
        return maxNsec3SaltLength;
    }

    /**
     * The greatest number of {@code NSEC} records considered in one denial-of-existence proof. Defaults to
     * {@code 16}.
     *
     * <p>A complete {@code NSEC} proof needs at most three records; the headroom is for responses that repeat
     * records across the answer and authority sections.</p>
     */
    public int maxNsecRecordsPerProof() {
        return maxNsecRecordsPerProof;
    }

    /**
     * The greatest number of {@code NSEC3} records considered in one denial-of-existence proof. Defaults to
     * {@code 16}. Together with {@link #maxNsec3HashComputations()} this bounds the closest-encloser search, whose
     * cost is the product of the two.
     */
    public int maxNsec3RecordsPerProof() {
        return maxNsec3RecordsPerProof;
    }

    /**
     * The greatest number of delegations a chain of trust may traverse from the trust anchor to the name being
     * validated. Defaults to {@code 32}.
     *
     * <p>A wire-form name holds at most 127 labels, so a chain cannot legitimately be deeper than that; 32 is well
     * beyond any real delegation hierarchy and keeps the recursion shallow.</p>
     */
    public int maxDelegationDepth() {
        return maxDelegationDepth;
    }

    /**
     * The greatest number of lookups one validation may issue for the records it needs, such as {@code DS} and
     * {@code DNSKEY} RRsets. Defaults to {@code 24}.
     *
     * <p>This is the limit that most directly implements the requirement of
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.4">RFC 4035, Section 5.4</a> that a validator
     * bound its work: without it a crafted chain turns one client query into unbounded traffic aimed at whichever
     * servers the attacker names.</p>
     */
    public int maxFetches() {
        return maxFetches;
    }

    /**
     * The greatest number of {@code CNAME} or {@code DNAME} links followed in one answer. Defaults to {@code 16}.
     *
     * <p><a href="https://www.rfc-editor.org/rfc/rfc1034.html#section-3.6.2">RFC 1034, Section 3.6.2</a> notes that
     * alias chains may loop and leaves the cut-off to the implementation.</p>
     */
    public int maxCnameChainLength() {
        return maxCnameChainLength;
    }

    /**
     * The greatest number of records accepted in one section of a message before validation is abandoned. Defaults
     * to {@code 256}.
     *
     * <p>Validation begins by grouping records into RRsets by owner name, class and type, and several later steps
     * pair records against one another. Both are quadratic in the size of the section in the worst case, so this
     * bound is what keeps every one of them bounded, whatever the message claims its counts are.</p>
     */
    public int maxRecordsPerSection() {
        return maxRecordsPerSection;
    }

    /**
     * The smallest RSA modulus, in bits, whose signatures are accepted. Defaults to {@code 1024}.
     *
     * <p><a href="https://www.rfc-editor.org/rfc/rfc5702.html#section-4.1">RFC 5702, Section 4.1</a> requires
     * implementations to accept keys of 1024 bits and up and leaves smaller keys to local policy; keys below that
     * are not worth the verification they cost.</p>
     */
    public int minimumRsaKeySizeBits() {
        return minimumRsaKeySizeBits;
    }

    /**
     * The wall-clock budget for one validation, in milliseconds. Defaults to {@code 5000}.
     *
     * <p>Exceeding it is {@link DnssecFailureReason#LIMIT_EXCEEDED}, not
     * {@link DnssecFailureReason#TIMEOUT}: a validation that runs out of time has been made expensive by the records
     * it was given, so it fails the same way as any other limit breach. A network lookup that does not answer is a
     * different thing and is {@link DnssecFailureReason#TIMEOUT}.</p>
     */
    public long validationTimeoutMillis() {
        return validationTimeoutMillis;
    }

    /**
     * The tolerance, in seconds, applied on both sides of an {@code RRSIG} validity window. Defaults to {@code 0}.
     *
     * <p>Explicitly zero, so that a deployment which needs a grace period has to ask for one. Every second of skew
     * is a second during which an expired signature is still accepted, and a silent default would hide a broken
     * clock until it became a much larger problem.</p>
     */
    public long clockSkewSeconds() {
        return clockSkewSeconds;
    }

    /**
     * Whether signatures made with the SHA-1 algorithms, {@code RSASHA1} (5) and {@code RSASHA1-NSEC3-SHA1} (7), are
     * accepted. Defaults to {@code true}.
     *
     * <p>Both remain {@code MUST} implement <em>for validation</em> under
     * <a href="https://www.rfc-editor.org/rfc/rfc9904.html">RFC 9904</a>, even though they are no longer to be used
     * for signing. Turning this off does not make anything more secure: an alg-7 zone simply stops validating and
     * becomes {@link DnssecStatus#INSECURE}, which is a self-inflicted downgrade of every zone that has not yet
     * rolled.</p>
     */
    public boolean allowSha1Signatures() {
        return allowSha1Signatures;
    }

    /**
     * Whether {@code DS} records using digest type 1, SHA-1, are accepted. Defaults to {@code true}.
     *
     * <p>Digest type 1 is {@code MUST} implement for validation under
     * <a href="https://www.rfc-editor.org/rfc/rfc9904.html">RFC 9904</a>. As with
     * {@link #allowSha1Signatures()}, refusing it turns working delegations
     * {@link DnssecStatus#INSECURE} rather than making anything safer.</p>
     */
    public boolean allowSha1DsDigest() {
        return allowSha1DsDigest;
    }

    @Override
    public String toString() {
        return "DnssecLimits(maxSignatureVerificationsPerRrset: " + maxSignatureVerificationsPerRrset
                + ", maxSignatureVerificationsPerValidation: " + maxSignatureVerificationsPerValidation
                + ", maxDsMatchFailures: " + maxDsMatchFailures
                + ", maxDnskeysPerKeyTag: " + maxDnskeysPerKeyTag
                + ", maxDnskeysPerRrset: " + maxDnskeysPerRrset
                + ", maxDsRecordsPerRrset: " + maxDsRecordsPerRrset
                + ", maxNsec3Iterations: " + maxNsec3Iterations
                + ", maxNsec3IterationsHardFail: " + maxNsec3IterationsHardFail
                + ", maxNsec3HashComputations: " + maxNsec3HashComputations
                + ", maxNsec3SaltLength: " + maxNsec3SaltLength
                + ", maxNsecRecordsPerProof: " + maxNsecRecordsPerProof
                + ", maxNsec3RecordsPerProof: " + maxNsec3RecordsPerProof
                + ", maxDelegationDepth: " + maxDelegationDepth
                + ", maxFetches: " + maxFetches
                + ", maxCnameChainLength: " + maxCnameChainLength
                + ", maxRecordsPerSection: " + maxRecordsPerSection
                + ", minimumRsaKeySizeBits: " + minimumRsaKeySizeBits
                + ", validationTimeoutMillis: " + validationTimeoutMillis
                + ", clockSkewSeconds: " + clockSkewSeconds
                + ", allowSha1Signatures: " + allowSha1Signatures
                + ", allowSha1DsDigest: " + allowSha1DsDigest + ')';
    }

    /**
     * Builds a {@link DnssecLimits}. Every setter validates its argument immediately, and {@link #build()} checks
     * the two constraints that involve more than one knob.
     *
     * <p>Not thread-safe; build the instance on one thread and share the result, which is immutable.</p>
     */
    public static final class Builder {

        private int maxSignatureVerificationsPerRrset = 8;
        private int maxSignatureVerificationsPerValidation = 32;
        private int maxDsMatchFailures = 4;
        private int maxDnskeysPerKeyTag = 2;
        private int maxDnskeysPerRrset = 16;
        private int maxDsRecordsPerRrset = 16;
        private int maxNsec3Iterations = 100;
        private int maxNsec3IterationsHardFail = 500;
        private int maxNsec3HashComputations = 64;
        private int maxNsec3SaltLength = 32;
        private int maxNsecRecordsPerProof = 16;
        private int maxNsec3RecordsPerProof = 16;
        private int maxDelegationDepth = 32;
        private int maxFetches = 24;
        private int maxCnameChainLength = 16;
        private int maxRecordsPerSection = 256;
        private int minimumRsaKeySizeBits = 1024;
        private long validationTimeoutMillis = 5000;
        private long clockSkewSeconds;
        private boolean allowSha1Signatures = true;
        private boolean allowSha1DsDigest = true;

        Builder() {
        }

        Builder(DnssecLimits limits) {
            maxSignatureVerificationsPerRrset = limits.maxSignatureVerificationsPerRrset;
            maxSignatureVerificationsPerValidation = limits.maxSignatureVerificationsPerValidation;
            maxDsMatchFailures = limits.maxDsMatchFailures;
            maxDnskeysPerKeyTag = limits.maxDnskeysPerKeyTag;
            maxDnskeysPerRrset = limits.maxDnskeysPerRrset;
            maxDsRecordsPerRrset = limits.maxDsRecordsPerRrset;
            maxNsec3Iterations = limits.maxNsec3Iterations;
            maxNsec3IterationsHardFail = limits.maxNsec3IterationsHardFail;
            maxNsec3HashComputations = limits.maxNsec3HashComputations;
            maxNsec3SaltLength = limits.maxNsec3SaltLength;
            maxNsecRecordsPerProof = limits.maxNsecRecordsPerProof;
            maxNsec3RecordsPerProof = limits.maxNsec3RecordsPerProof;
            maxDelegationDepth = limits.maxDelegationDepth;
            maxFetches = limits.maxFetches;
            maxCnameChainLength = limits.maxCnameChainLength;
            maxRecordsPerSection = limits.maxRecordsPerSection;
            minimumRsaKeySizeBits = limits.minimumRsaKeySizeBits;
            validationTimeoutMillis = limits.validationTimeoutMillis;
            clockSkewSeconds = limits.clockSkewSeconds;
            allowSha1Signatures = limits.allowSha1Signatures;
            allowSha1DsDigest = limits.allowSha1DsDigest;
        }

        /**
         * See {@link DnssecLimits#maxSignatureVerificationsPerRrset()}.
         *
         * @param value between {@code 1} and {@code 1024}.
         */
        public Builder maxSignatureVerificationsPerRrset(int value) {
            maxSignatureVerificationsPerRrset =
                    ObjectUtil.checkInRange(value, 1, 1024, "maxSignatureVerificationsPerRrset");
            return this;
        }

        /**
         * See {@link DnssecLimits#maxSignatureVerificationsPerValidation()}.
         *
         * @param value between {@code 1} and {@code 65536}.
         */
        public Builder maxSignatureVerificationsPerValidation(int value) {
            maxSignatureVerificationsPerValidation =
                    ObjectUtil.checkInRange(value, 1, 65536, "maxSignatureVerificationsPerValidation");
            return this;
        }

        /**
         * See {@link DnssecLimits#maxDsMatchFailures()}.
         *
         * @param value between {@code 1} and {@code 1024}.
         */
        public Builder maxDsMatchFailures(int value) {
            maxDsMatchFailures = ObjectUtil.checkInRange(value, 1, 1024, "maxDsMatchFailures");
            return this;
        }

        /**
         * See {@link DnssecLimits#maxDnskeysPerKeyTag()}.
         *
         * @param value between {@code 1} and {@code 1024}.
         */
        public Builder maxDnskeysPerKeyTag(int value) {
            maxDnskeysPerKeyTag = ObjectUtil.checkInRange(value, 1, 1024, "maxDnskeysPerKeyTag");
            return this;
        }

        /**
         * See {@link DnssecLimits#maxDnskeysPerRrset()}.
         *
         * @param value between {@code 1} and {@code 1024}.
         */
        public Builder maxDnskeysPerRrset(int value) {
            maxDnskeysPerRrset = ObjectUtil.checkInRange(value, 1, 1024, "maxDnskeysPerRrset");
            return this;
        }

        /**
         * See {@link DnssecLimits#maxDsRecordsPerRrset()}.
         *
         * @param value between {@code 1} and {@code 1024}.
         */
        public Builder maxDsRecordsPerRrset(int value) {
            maxDsRecordsPerRrset = ObjectUtil.checkInRange(value, 1, 1024, "maxDsRecordsPerRrset");
            return this;
        }

        /**
         * See {@link DnssecLimits#maxNsec3Iterations()}.
         *
         * @param value between {@code 0} and {@code 2500}, the largest count
         *              <a href="https://www.rfc-editor.org/rfc/rfc5155.html#section-10.3">RFC 5155,
         *              Section 10.3</a> ever permitted.
         */
        public Builder maxNsec3Iterations(int value) {
            maxNsec3Iterations = ObjectUtil.checkInRange(value, 0, 2500, "maxNsec3Iterations");
            return this;
        }

        /**
         * See {@link DnssecLimits#maxNsec3IterationsHardFail()}.
         *
         * @param value between {@code 0} and {@code 65535}, the width of the {@code NSEC3} Iterations field.
         */
        public Builder maxNsec3IterationsHardFail(int value) {
            maxNsec3IterationsHardFail = ObjectUtil.checkInRange(value, 0, 65535, "maxNsec3IterationsHardFail");
            return this;
        }

        /**
         * See {@link DnssecLimits#maxNsec3HashComputations()}.
         *
         * @param value between {@code 1} and {@code 1048576}.
         */
        public Builder maxNsec3HashComputations(int value) {
            maxNsec3HashComputations = ObjectUtil.checkInRange(value, 1, 1048576, "maxNsec3HashComputations");
            return this;
        }

        /**
         * See {@link DnssecLimits#maxNsec3SaltLength()}.
         *
         * @param value between {@code 0} and {@code 255}, the width of the {@code NSEC3} Salt Length field.
         */
        public Builder maxNsec3SaltLength(int value) {
            maxNsec3SaltLength = ObjectUtil.checkInRange(value, 0, 255, "maxNsec3SaltLength");
            return this;
        }

        /**
         * See {@link DnssecLimits#maxNsecRecordsPerProof()}.
         *
         * @param value between {@code 1} and {@code 1024}.
         */
        public Builder maxNsecRecordsPerProof(int value) {
            maxNsecRecordsPerProof = ObjectUtil.checkInRange(value, 1, 1024, "maxNsecRecordsPerProof");
            return this;
        }

        /**
         * See {@link DnssecLimits#maxNsec3RecordsPerProof()}.
         *
         * @param value between {@code 1} and {@code 1024}.
         */
        public Builder maxNsec3RecordsPerProof(int value) {
            maxNsec3RecordsPerProof = ObjectUtil.checkInRange(value, 1, 1024, "maxNsec3RecordsPerProof");
            return this;
        }

        /**
         * See {@link DnssecLimits#maxDelegationDepth()}.
         *
         * @param value between {@code 1} and {@code 128}, one more than the greatest number of labels a name can
         *              have.
         */
        public Builder maxDelegationDepth(int value) {
            maxDelegationDepth = ObjectUtil.checkInRange(value, 1, 128, "maxDelegationDepth");
            return this;
        }

        /**
         * See {@link DnssecLimits#maxFetches()}.
         *
         * @param value between {@code 1} and {@code 1024}.
         */
        public Builder maxFetches(int value) {
            maxFetches = ObjectUtil.checkInRange(value, 1, 1024, "maxFetches");
            return this;
        }

        /**
         * See {@link DnssecLimits#maxCnameChainLength()}.
         *
         * @param value between {@code 1} and {@code 1024}.
         */
        public Builder maxCnameChainLength(int value) {
            maxCnameChainLength = ObjectUtil.checkInRange(value, 1, 1024, "maxCnameChainLength");
            return this;
        }

        /**
         * See {@link DnssecLimits#maxRecordsPerSection()}.
         *
         * @param value between {@code 1} and {@code 65535}, the width of a message section count field.
         */
        public Builder maxRecordsPerSection(int value) {
            maxRecordsPerSection = ObjectUtil.checkInRange(value, 1, 65535, "maxRecordsPerSection");
            return this;
        }

        /**
         * See {@link DnssecLimits#minimumRsaKeySizeBits()}.
         *
         * @param value between {@code 512} and {@code 16384}.
         */
        public Builder minimumRsaKeySizeBits(int value) {
            minimumRsaKeySizeBits = ObjectUtil.checkInRange(value, 512, 16384, "minimumRsaKeySizeBits");
            return this;
        }

        /**
         * See {@link DnssecLimits#validationTimeoutMillis()}.
         *
         * @param value between {@code 1} and {@code 3600000}.
         */
        public Builder validationTimeoutMillis(long value) {
            validationTimeoutMillis = ObjectUtil.checkInRange(value, 1L, 3600000L, "validationTimeoutMillis");
            return this;
        }

        /**
         * See {@link DnssecLimits#clockSkewSeconds()}.
         *
         * @param value between {@code 0} and {@code 86400}.
         */
        public Builder clockSkewSeconds(long value) {
            clockSkewSeconds = ObjectUtil.checkInRange(value, 0L, 86400L, "clockSkewSeconds");
            return this;
        }

        /**
         * See {@link DnssecLimits#allowSha1Signatures()}.
         */
        public Builder allowSha1Signatures(boolean value) {
            allowSha1Signatures = value;
            return this;
        }

        /**
         * See {@link DnssecLimits#allowSha1DsDigest()}.
         */
        public Builder allowSha1DsDigest(boolean value) {
            allowSha1DsDigest = value;
            return this;
        }

        /**
         * Builds the {@link DnssecLimits}.
         *
         * @throws IllegalArgumentException if {@code maxSignatureVerificationsPerValidation} is smaller than
         *                                  {@code maxSignatureVerificationsPerRrset}, or if
         *                                  {@code maxNsec3IterationsHardFail} is smaller than
         *                                  {@code maxNsec3Iterations}; either way one of the two limits could never
         *                                  be reached, which is a configuration mistake rather than a policy.
         */
        public DnssecLimits build() {
            if (maxSignatureVerificationsPerValidation < maxSignatureVerificationsPerRrset) {
                throw new IllegalArgumentException("maxSignatureVerificationsPerValidation: "
                        + maxSignatureVerificationsPerValidation + " (expected: >= maxSignatureVerificationsPerRrset ("
                        + maxSignatureVerificationsPerRrset + "))");
            }
            if (maxNsec3IterationsHardFail < maxNsec3Iterations) {
                throw new IllegalArgumentException("maxNsec3IterationsHardFail: " + maxNsec3IterationsHardFail
                        + " (expected: >= maxNsec3Iterations (" + maxNsec3Iterations + "))");
            }
            return new DnssecLimits(this);
        }
    }
}
