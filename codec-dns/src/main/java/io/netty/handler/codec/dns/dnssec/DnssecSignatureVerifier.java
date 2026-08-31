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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.codec.dns.DnsName;
import io.netty.util.internal.ObjectUtil;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * Checks an RRset against the {@code RRSIG}s that claim to cover it, using a set of candidate {@code DNSKEY}s.
 *
 * <p>This is the whole of <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.3">RFC 4035,
 * Section 5.3</a>: the validity checks of Section 5.3.1, the signed-data reconstruction of Section 5.3.2, which is
 * {@link DnssecCanonicalizer}'s work, and the signature check of Section 5.3.3. It is <em>not</em> a chain of
 * trust. It answers "is this RRset signed by one of these keys", and says nothing about where the keys came from,
 * whether the records are in bailiwick, or whether a wildcard answer came with the proof it needs. A caller that
 * treats a {@link DnssecStatus#SECURE} result here as an authenticated answer has built a bypass.
 *
 * <p>The order is deliberate and is most of the defence against
 * <a href="https://www.cve.org/CVERecord?id=CVE-2023-50387">KeyTrap</a>. Each check below is free compared with a
 * signature verification, so an attacker who wants to make this class do expensive work has to get an
 * {@code RRSIG} past all of them first:
 * <ol>
 *   <li>the {@code RRSIG} and the RRset have the same class (RFC 4035, Section 5.3.1);</li>
 *   <li>and the same owner name;</li>
 *   <li>the Type Covered field equals the RRset's type;</li>
 *   <li>every record in the RRset really does share that owner, class and type
 *   (<a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-3.1.8.1">RFC 4034, Section 3.1.8.1</a>);</li>
 *   <li>the Labels field is not greater than the owner's label count, counting neither the root label nor a
 *   leading {@code *} (RFC 4035, Section 5.3.1);</li>
 *   <li>the Labels field is not <em>smaller</em> than the Signer's Name label count. This bound is not in RFC 4035;
 *   it is Unbound's <a href="https://www.cve.org/CVERecord?id=CVE-2026-44690">CVE-2026-44690</a>. Without it
 *   {@code evil.example.} can sign {@code x.evil.example.} with {@code labels = 1} and mint the signed owner
 *   {@code *.example.}, a wildcard in a zone it has no authority over;</li>
 *   <li>the Signer's Name is the RRset owner or an ancestor of it;</li>
 *   <li>the signature is inside its validity period, compared with the serial arithmetic of
 *   <a href="https://www.rfc-editor.org/rfc/rfc1982.html">RFC 1982</a> as
 *   <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-3.1.5">RFC 4034, Section 3.1.5</a> requires — the
 *   fields are 32-bit and wrap in 2106, so a plain {@code long} comparison is wrong;</li>
 *   <li>a candidate {@code DNSKEY} exists with the same owner, algorithm and key tag;</li>
 *   <li>its Protocol field is 3
 *   (<a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-2.1.2">RFC 4034, Section 2.1.2</a>);</li>
 *   <li>its Zone Key flag is set (RFC 4034, Section 2.1.1);</li>
 *   <li>its REVOKE flag is clear
 *   (<a href="https://www.rfc-editor.org/rfc/rfc5011.html#section-2.1">RFC 5011, Section 2.1</a>);</li>
 *   <li>the signature has a length the algorithm can have produced.</li>
 * </ol>
 *
 * <p>The Secure Entry Point flag is deliberately <strong>not</strong> a criterion. RFC 4034, Section 2.1.1 says a
 * validator "MUST NOT" alter the validation process because of it, and
 * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-6.2">RFC 6840, Section 6.2</a> points out that a
 * {@code DS} may perfectly well match a key with the bit clear. Filtering on it breaks working zones and secures
 * nothing.
 *
 * <p>Two further rules come from <a href="https://www.rfc-editor.org/rfc/rfc6840.html">RFC 6840</a>. Section 5.12
 * requires an {@code RRSIG} with no corresponding {@code DNSKEY}, or with an algorithm that does not appear in the
 * {@code DNSKEY} RRset, to be disregarded, and doing that first costs nothing while removing the cheapest way to
 * force key lookups. Section 5.4 says any single valid {@code RRSIG} is sufficient and the RRset is Bogus only if
 * they all fail, so this class stops at the first success: BIND's
 * <a href="https://www.cve.org/CVERecord?id=CVE-2026-11605">CVE-2026-11605</a> was the cost of carrying on.
 *
 * <p>RFC 4035, Section 5.3.1 says a validator "MUST try each matching DNSKEY RR until either the signature is
 * validated or the validator has run out of matching public keys to try". That loop is what KeyTrap exploits, and
 * this class does not obey it: {@link DnssecLimits#maxSignatureVerificationsPerRrset()} caps the verifications one
 * RRset may cost, {@link DnssecLimits#maxDnskeysPerKeyTag()} caps how many keys may share one tag — key tags are
 * not unique, by RFC 4034, Appendix B's own admission — and the {@link DnssecBudget} caps the whole validation.
 * Exceeding any of them is {@link DnssecStatus#BOGUS}, never {@link DnssecStatus#INSECURE}: the records that drive
 * the work come from the other side of the wire, so a limit that downgraded a zone would be a downgrade oracle.
 * <a href="https://www.rfc-editor.org/errata/eid8037">RFC 4035 erratum 8037</a> proposes softening that MUST to a
 * SHOULD, citing CVE-2023-50387, so this is the direction the specification is moving rather than a departure
 * from it.
 *
 * <p>An algorithm this JVM does not offer, or a well-formed key its provider refuses to build, yields
 * {@link DnssecStatus#INSECURE} with {@link DnssecFailureReason#UNSUPPORTED_DNSKEY_ALGORITHM} or
 * {@link DnssecFailureReason#LOCAL_CRYPTO_UNAVAILABLE}. {@code Ed25519} and {@code Ed448} are simply absent before
 * Java 15, and that is a fact about the runtime, not evidence about the zone. Only data that is provably wrong is
 * Bogus.
 *
 * <p>That judgement is made about the <em>zone</em>, from the whole key set it was given, and not one
 * {@code RRSIG} at a time. RFC 6840, Section 5.2's "treat as unsigned" is for a zone this build can evaluate
 * nothing of; a zone that also publishes an algorithm this build does implement is validatable, so an RRset
 * carrying only {@code RRSIG}s of the other algorithm is Bogus. The distinction is the difference between an
 * honest downgrade and an attacker's: a zone in the middle of an algorithm rollover publishes both, and deciding
 * per {@code RRSIG} would let anyone who can discard the signatures made with the supported algorithm strip
 * DNSSEC from it.
 *
 * <p>Instances are immutable and safe to share between threads. A {@link DnssecBudget} is not: it belongs to one
 * validation.
 */
public final class DnssecSignatureVerifier {

    /** RFC 4034, Section 2.1.2: the Protocol field "MUST have value 3". */
    private static final int DNSKEY_PROTOCOL = 3;

    /** RFC 6605, Section 4: {@code r} and {@code s} are 32 octets each for P-256 and 48 each for P-384. */
    private static final int P256_HALF_SIGNATURE_LENGTH = 32;
    private static final int P384_HALF_SIGNATURE_LENGTH = 48;

    /** RFC 8080, Section 3: an Ed25519 signature is 64 octets and an Ed448 signature is 114. */
    private static final int ED25519_SIGNATURE_LENGTH = 64;
    private static final int ED448_SIGNATURE_LENGTH = 114;

    private final DnssecClock clock;
    private final DnssecLimits limits;

    /**
     * Creates a verifier that judges signature validity against the system clock and enforces
     * {@link DnssecLimits#defaults()}.
     */
    public DnssecSignatureVerifier() {
        this(DnssecClock.SYSTEM, DnssecLimits.defaults());
    }

    /**
     * Creates a verifier.
     *
     * @param clock  the clock the Signature Inception and Signature Expiration fields are judged against. Pinning
     *               it is what makes the published RFC vectors testable at all: RFC 6605's example signatures
     *               expired in 2010.
     * @param limits the hardening limits to enforce.
     */
    public DnssecSignatureVerifier(DnssecClock clock, DnssecLimits limits) {
        this.clock = ObjectUtil.checkNotNull(clock, "clock");
        this.limits = ObjectUtil.checkNotNull(limits, "limits");
    }

    /**
     * Returns the clock signature validity is judged against.
     */
    public DnssecClock clock() {
        return clock;
    }

    /**
     * Returns the limits this verifier enforces.
     */
    public DnssecLimits limits() {
        return limits;
    }

    /**
     * Verifies one RRset against a fresh {@link DnssecBudget}.
     *
     * <p>Only for a caller that is checking a single RRset. A chain of trust must create one budget and pass it to
     * every call, because a quota that each step refills is not a quota; that is Unbound's
     * <a href="https://www.cve.org/CVERecord?id=CVE-2026-50045">CVE-2026-50045</a>.
     */
    public DnssecVerificationResult verify(DnsRRset rrset, Collection<DnsDnskeyRecord> keys) {
        return verify(rrset, keys, new DnssecBudget(limits, clock));
    }

    /**
     * Verifies one RRset.
     *
     * @param rrset  the records to authenticate, together with the {@code RRSIG}s that claim to cover them.
     * @param keys   the candidate {@code DNSKEY}s, normally the validated apex {@code DNSKEY} RRset of the signing
     *               zone. Keys that do not match an {@code RRSIG}'s owner, algorithm and key tag are ignored.
     * @param budget the work quota for the validation this call is part of. Charged one unit per signature
     *               verification actually performed.
     * @return what could be concluded, never {@code null}.
     */
    public DnssecVerificationResult verify(DnsRRset rrset, Collection<DnsDnskeyRecord> keys, DnssecBudget budget) {
        ObjectUtil.checkNotNull(rrset, "rrset");
        ObjectUtil.checkNotNull(keys, "keys");
        ObjectUtil.checkNotNull(budget, "budget");
        try {
            return doVerify(rrset, keys, budget);
        } catch (DnssecLimitExceededException e) {
            // Bogus, not Insecure: see the class documentation.
            return DnssecVerificationResult.failed(DnssecFailureReason.LIMIT_EXCEEDED, e.getMessage());
        }
    }

    private DnssecVerificationResult doVerify(DnsRRset rrset, Collection<DnsDnskeyRecord> keys, DnssecBudget budget) {
        if (rrset.records().isEmpty()) {
            return DnssecVerificationResult.failed(DnssecFailureReason.DNSSEC_BOGUS,
                    "the RRset " + rrset.owner() + ' ' + rrset.type() + " has no records to authenticate");
        }
        List<DnsRrsigRecord> rrsigs = rrset.signatures();
        if (rrsigs.isEmpty()) {
            return DnssecVerificationResult.failed(DnssecFailureReason.RRSIGS_MISSING,
                    "no RRSIG covers " + rrset.owner() + ' ' + rrset.type());
        }
        // RFC 6840, Section 5.2 treats a zone none of whose algorithms this build can evaluate as unsigned, and
        // this is where that is decided: at the zone, from its whole key set, and not one RRSIG at a time. A zone
        // that also offers an algorithm this build implements is validatable, so an RRSIG naming another one
        // leaves the RRset failing to validate rather than unsigned. Deciding it per RRSIG would mean anyone who
        // can discard the signatures made with the supported algorithm can strip DNSSEC from the zone.
        Failure failure = new Failure(hasUsableAlgorithm(keys));
        if (!checkHomogeneous(rrset, failure)) {
            return failure.toResult();
        }

        int ownerLabels = DnssecCanonicalizer.ownerLabelCount(rrset.owner());
        int verificationsForThisRrset = 0;

        for (int i = 0; i < rrsigs.size(); i++) {
            budget.checkDeadline();
            DnsRrsigRecord rrsig = rrsigs.get(i);
            DnssecAlgorithm algorithm = rrsig.algorithm();

            // RFC 6840, Section 5.12, first because it is the cheapest test there is.
            if (!containsAlgorithm(keys, algorithm)) {
                failure.record(DnssecFailureReason.DNSKEY_MISSING, "the RRSIG on " + rrset.owner() + ' '
                        + rrset.type() + " uses " + algorithm + ", which no offered DNSKEY has");
                continue;
            }
            if (!checkRrsig(rrsig, rrset, ownerLabels, failure)) {
                continue;
            }
            if (!isUsable(algorithm)) {
                failure.record(DnssecFailureReason.UNSUPPORTED_DNSKEY_ALGORITHM,
                        "this build cannot verify " + algorithm + " signatures");
                continue;
            }
            List<DnsDnskeyRecord> candidates = candidateKeys(rrsig, keys);
            if (candidates.isEmpty()) {
                failure.record(DnssecFailureReason.KEY_TAG_NO_MATCH, "no offered DNSKEY of " + rrsig.signerName()
                        + " has algorithm " + algorithm + " and key tag " + rrsig.keyTag());
                continue;
            }

            ByteBuf signedData = null;
            try {
                for (int j = 0; j < candidates.size(); j++) {
                    DnsDnskeyRecord key = candidates.get(j);
                    if (!checkKey(key, failure)) {
                        continue;
                    }
                    // Everything past here costs real work whether or not a signature is ever checked: decoding a
                    // key runs the RFC 3110 length and the curve-membership checks, and canonicalising the RRset
                    // sorts and copies all of it. The quota is therefore taken now rather than at the verify()
                    // call, which also means a verification that throws has been paid for.
                    verificationsForThisRrset = spendVerification(budget, verificationsForThisRrset);
                    PublicKey publicKey = decode(key, failure);
                    if (publicKey == null) {
                        continue;
                    }
                    if (signedData == null) {
                        try {
                            signedData = DnssecCanonicalizer.signedData(ByteBufAllocator.DEFAULT, rrsig, rrset);
                        } catch (DnssecCanonicalizationException e) {
                            // The RRset has no canonical form at all, so another key would not help.
                            failure.record(e.reason(), e.getMessage());
                            break;
                        }
                    }
                    if (verifySignature(rrsig, key, publicKey, signedData, failure)) {
                        // RFC 6840, Section 5.4: one valid RRSIG is enough, and looking at the rest is what
                        // CVE-2026-11605 was.
                        DnsName signedOwner = DnssecCanonicalizer.signedOwner(rrsig, rrset.owner());
                        return DnssecVerificationResult.secure(rrsig, key, signedOwner,
                                rrsig.labels() < ownerLabels);
                    }
                }
            } finally {
                if (signedData != null) {
                    signedData.release();
                }
            }
        }
        return failure.toResult();
    }

    /**
     * Charges one signature verification to both quotas and returns the new count for this RRset.
     */
    private int spendVerification(DnssecBudget budget, int verificationsForThisRrset) {
        if (verificationsForThisRrset >= limits.maxSignatureVerificationsPerRrset()) {
            throw new DnssecLimitExceededException("maxSignatureVerificationsPerRrset",
                    limits.maxSignatureVerificationsPerRrset());
        }
        budget.spendSignatureVerification();
        return verificationsForThisRrset + 1;
    }

    /**
     * RFC 4034, Section 3.1.8.1: the signature is computed over records that share an owner name, class and type,
     * so an RRset that does not is not a thing any signature can cover.
     */
    private static boolean checkHomogeneous(DnsRRset rrset, Failure failure) {
        List<DnssecRecord> records = rrset.records();
        for (int i = 0; i < records.size(); i++) {
            DnssecRecord record = records.get(i);
            if (record.type().intValue() != rrset.type().intValue() || record.dnsClass() != rrset.dnsClass()
                    || !record.owner().equals(rrset.owner())) {
                failure.record(DnssecFailureReason.DNSSEC_BOGUS, "record " + i + " of the RRset is "
                        + record.owner() + ' ' + record.type() + " class " + record.dnsClass() + ", but the RRset is "
                        + rrset.owner() + ' ' + rrset.type() + " class " + rrset.dnsClass());
                return false;
            }
        }
        return true;
    }

    private boolean checkRrsig(DnsRrsigRecord rrsig, DnsRRset rrset, int ownerLabels, Failure failure) {
        if (rrsig.dnsClass() != rrset.dnsClass()) {
            failure.record(DnssecFailureReason.DNSSEC_BOGUS, "the RRSIG is class " + rrsig.dnsClass()
                    + " but the RRset it covers is class " + rrset.dnsClass());
            return false;
        }
        if (!rrsig.owner().equals(rrset.owner())) {
            failure.record(DnssecFailureReason.DNSSEC_BOGUS, "the RRSIG is owned by " + rrsig.owner()
                    + " but the RRset it covers is owned by " + rrset.owner());
            return false;
        }
        if (rrsig.typeCovered().intValue() != rrset.type().intValue()) {
            failure.record(DnssecFailureReason.DNSSEC_BOGUS, "the RRSIG covers " + rrsig.typeCovered()
                    + " but the RRset is " + rrset.type());
            return false;
        }
        int labels = rrsig.labels();
        if (labels > ownerLabels) {
            failure.record(DnssecFailureReason.RRSIG_LABELS_INVALID, "the RRSIG has labels " + labels
                    + " but " + rrset.owner() + " has only " + ownerLabels
                    + ", so it cannot be used to authenticate this RRset (RFC 4035, Section 5.3.2)");
            return false;
        }
        DnsName signerName = rrsig.signerName();
        int signerLabels = signerName.labelCount();
        if (labels < signerLabels) {
            failure.record(DnssecFailureReason.RRSIG_LABELS_INVALID, "the RRSIG has labels " + labels
                    + " but its signer " + signerName + " has " + signerLabels
                    + ", so the owner it signs lies outside that zone (CVE-2026-44690)");
            return false;
        }
        if (!rrset.owner().equalsOrIsSubDomainOf(signerName)) {
            failure.record(DnssecFailureReason.SIGNER_NOT_ZONE, "the RRSIG names " + signerName
                    + " as its signer, which is not " + rrset.owner() + " nor an ancestor of it");
            return false;
        }
        return checkValidityPeriod(rrsig, failure);
    }

    /**
     * Compares the current time with the Signature Inception and Signature Expiration fields.
     *
     * <p>Both are unsigned 32-bit seconds since the epoch compared with RFC 1982 serial arithmetic, so the test is
     * the sign of a 32-bit difference and not a comparison of two widened {@code long}s. The difference is
     * unobservable today and total in 2106, when the fields wrap.
     *
     * <p>{@link DnssecLimits#clockSkewSeconds()} is applied to the validator's own notion of "now" and never to the
     * record's fields: adding it to an expiration that is close to the wrap point would move the expiration into
     * the past.
     */
    private boolean checkValidityPeriod(DnsRrsigRecord rrsig, Failure failure) {
        long nowSeconds = clock.currentTimeMillis() / 1000L;
        long skew = limits.clockSkewSeconds();
        int expiration = (int) rrsig.expiration();
        int inception = (int) rrsig.inception();
        if ((int) (nowSeconds - skew) - expiration > 0) {
            failure.record(DnssecFailureReason.SIGNATURE_EXPIRED, "the RRSIG expired at " + rrsig.expiration()
                    + " and it is now " + nowSeconds + " (skew " + skew + "s)");
            return false;
        }
        if ((int) (nowSeconds + skew) - inception < 0) {
            failure.record(DnssecFailureReason.SIGNATURE_NOT_YET_VALID, "the RRSIG is not valid before "
                    + rrsig.inception() + " and it is now " + nowSeconds + " (skew " + skew + "s)");
            return false;
        }
        return true;
    }

    private static boolean checkKey(DnsDnskeyRecord key, Failure failure) {
        if (key.protocol() != DNSKEY_PROTOCOL) {
            failure.record(DnssecFailureReason.DNSSEC_BOGUS, "DNSKEY " + key.owner() + " has protocol "
                    + key.protocol() + ", but RFC 4034, Section 2.1.2 requires 3");
            return false;
        }
        if (!key.isZoneKey()) {
            failure.record(DnssecFailureReason.NO_ZONE_KEY_BIT_SET, "DNSKEY " + key.owner()
                    + " does not have the Zone Key flag set, so it does not sign this zone's RRsets");
            return false;
        }
        if (key.isRevoked()) {
            failure.record(DnssecFailureReason.DNSKEY_REVOKED, "DNSKEY " + key.owner()
                    + " has the REVOKE flag set (RFC 5011, Section 2.1)");
            return false;
        }
        // The Secure Entry Point flag is not consulted here, and must not be: RFC 4034, Section 2.1.1.
        return true;
    }

    /**
     * Returns {@code true} if any offered key uses {@code algorithm}, which is the RFC 6840, Section 5.12 test.
     */
    private static boolean containsAlgorithm(Collection<DnsDnskeyRecord> keys, DnssecAlgorithm algorithm) {
        for (Iterator<DnsDnskeyRecord> i = keys.iterator(); i.hasNext();) {
            DnsDnskeyRecord key = i.next();
            if (key != null && key.algorithm().intValue() == algorithm.intValue()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Collects the keys an {@code RRSIG} could have been made with: same owner as its Signer's Name, same algorithm
     * and same key tag.
     *
     * <p>More than {@link DnssecLimits#maxDnskeysPerKeyTag()} of them is a hard failure rather than a truncation.
     * A key tag is a 16-bit checksum and RFC 4034, Appendix B says outright that it does not identify a key, so an
     * attacker can manufacture as many colliding keys as they please and make every one of them a verification the
     * validator must perform.
     */
    private List<DnsDnskeyRecord> candidateKeys(DnsRrsigRecord rrsig, Collection<DnsDnskeyRecord> keys) {
        List<DnsDnskeyRecord> candidates = new ArrayList<DnsDnskeyRecord>(2);
        int keyTag = rrsig.keyTag();
        DnsName signerName = rrsig.signerName();
        int algorithm = rrsig.algorithm().intValue();
        for (Iterator<DnsDnskeyRecord> i = keys.iterator(); i.hasNext();) {
            DnsDnskeyRecord key = i.next();
            if (key == null || key.algorithm().intValue() != algorithm || !key.owner().equals(signerName)) {
                continue;
            }
            int tag;
            try {
                tag = key.keyTag();
            } catch (DnssecException ignored) {
                // A key whose tag cannot be computed, which today means only RSAMD5, can never be the key an
                // RRSIG names. Skipping it is not a downgrade: the RRSIG still has to find some other key.
                continue;
            }
            if (tag != keyTag) {
                continue;
            }
            if (candidates.size() >= limits.maxDnskeysPerKeyTag()) {
                throw new DnssecLimitExceededException("maxDnskeysPerKeyTag", limits.maxDnskeysPerKeyTag());
            }
            candidates.add(key);
        }
        return candidates;
    }

    /**
     * Returns {@code true} if any offered key names an algorithm {@link #isUsable(DnssecAlgorithm)} accepts, which
     * is the whole of the RFC 6840, Section 5.2 question: is there anything about this zone this build could have
     * validated?
     */
    private boolean hasUsableAlgorithm(Collection<DnsDnskeyRecord> keys) {
        for (Iterator<DnsDnskeyRecord> i = keys.iterator(); i.hasNext();) {
            DnsDnskeyRecord key = i.next();
            if (key != null && isUsable(key.algorithm())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns {@code true} if this build and this JVM can verify {@code algorithm}.
     */
    private boolean isUsable(DnssecAlgorithm algorithm) {
        if (!algorithm.isSupported()) {
            return false;
        }
        if (!limits.allowSha1Signatures()) {
            int value = algorithm.intValue();
            return value != DnssecAlgorithm.RSASHA1.intValue()
                    && value != DnssecAlgorithm.RSASHA1_NSEC3_SHA1.intValue();
        }
        return true;
    }

    private PublicKey decode(DnsDnskeyRecord key, Failure failure) {
        try {
            return DnssecPublicKeys.decode(key.algorithm(), key.publicKey(), limits.minimumRsaKeySizeBits());
        } catch (DnssecUnsupportedAlgorithmException e) {
            // The key is fine; this runtime will not load it. That is not evidence about the zone.
            failure.record(DnssecFailureReason.LOCAL_CRYPTO_UNAVAILABLE, e.getMessage());
        } catch (DnssecMalformedDataException e) {
            failure.record(DnssecFailureReason.DNSSEC_BOGUS, e.getMessage());
        }
        return null;
    }

    private static boolean verifySignature(DnsRrsigRecord rrsig, DnsDnskeyRecord key, PublicKey publicKey,
                                           ByteBuf signedData, Failure failure) {
        DnssecAlgorithm algorithm = rrsig.algorithm();
        byte[] encoded;
        try {
            encoded = encodeSignature(algorithm, publicKey, rrsig.signature());
        } catch (DnssecUnsupportedAlgorithmException e) {
            failure.record(DnssecFailureReason.LOCAL_CRYPTO_UNAVAILABLE, e.getMessage());
            return false;
        } catch (DnssecMalformedDataException e) {
            failure.record(DnssecFailureReason.DNSSEC_BOGUS, e.getMessage());
            return false;
        }
        try {
            Signature verifier = Signature.getInstance(algorithm.signatureAlgorithm());
            verifier.initVerify(publicKey);
            verifier.update(signedData.nioBuffer());
            if (verifier.verify(encoded)) {
                return true;
            }
            failure.record(DnssecFailureReason.DNSSEC_BOGUS, "the " + algorithm + " signature of the RRSIG with key "
                    + "tag " + rrsig.keyTag() + " does not verify against DNSKEY " + key.owner());
        } catch (NoSuchAlgorithmException e) {
            failure.record(DnssecFailureReason.LOCAL_CRYPTO_UNAVAILABLE,
                    "no provider offers " + algorithm.signatureAlgorithm() + ": " + e.getMessage());
        } catch (InvalidKeyException e) {
            failure.record(DnssecFailureReason.LOCAL_CRYPTO_UNAVAILABLE,
                    "the provider will not use this " + algorithm + " key: " + e.getMessage());
        } catch (SignatureException e) {
            // A provider that refuses the encoding is making a statement about the signature, not about itself.
            failure.record(DnssecFailureReason.DNSSEC_BOGUS,
                    "the " + algorithm + " signature could not be processed: " + e.getMessage());
        }
        return false;
    }

    /**
     * Converts an {@code RRSIG} Signature field into the encoding the JCA expects, and rejects any length the
     * algorithm cannot have produced before a single cryptographic operation is performed.
     *
     * <p>Two conversions are mandatory rather than tidy, and both were measured rather than assumed:
     * <ul>
     *   <li>DNSSEC carries an ECDSA signature as the fixed-width {@code r || s} of RFC 6605, Section 4, and SunEC
     *   rejects that outright; it wants ASN.1 DER.</li>
     *   <li>SunRsaSign rejects any RSA signature whose length differs from the modulus length in either direction,
     *   while <a href="https://www.rfc-editor.org/rfc/rfc3110.html#section-3">RFC 3110, Section 3</a> permits
     *   leading zero octets, so a perfectly valid signature fails unless it is normalised first.</li>
     * </ul>
     */
    private static byte[] encodeSignature(DnssecAlgorithm algorithm, PublicKey publicKey, byte[] signature) {
        if (algorithm.isRsa()) {
            if (!(publicKey instanceof RSAPublicKey)) {
                throw new DnssecUnsupportedAlgorithmException("the provider returned a "
                        + publicKey.getClass().getName() + " for " + algorithm + ", whose modulus length is unknown");
            }
            int modulusLength = (((RSAPublicKey) publicKey).getModulus().bitLength() + 7) / 8;
            return DnssecSignatures.normalizeRsaSignature(signature, modulusLength);
        }
        if (algorithm.isEcdsa()) {
            return DnssecSignatures.toDer(signature,
                    algorithm.intValue() == DnssecAlgorithm.ECDSAP256SHA256.intValue()
                            ? P256_HALF_SIGNATURE_LENGTH : P384_HALF_SIGNATURE_LENGTH);
        }
        if (algorithm.isEdDsa()) {
            int expected = algorithm.intValue() == DnssecAlgorithm.ED25519.intValue()
                    ? ED25519_SIGNATURE_LENGTH : ED448_SIGNATURE_LENGTH;
            if (signature.length != expected) {
                throw new DnssecMalformedDataException(algorithm + " signature is " + signature.length
                        + " octets, expected " + expected);
            }
            return signature;
        }
        throw new DnssecUnsupportedAlgorithmException("no signature encoding is defined here for " + algorithm);
    }

    /**
     * Keeps the most informative failure seen while trying the {@code RRSIG}s of one RRset.
     *
     * <p>The ranking matters for one reason beyond diagnostics: every reason that means "cannot evaluate" ranks
     * below every reason that means "provably wrong", so a set of {@code RRSIG}s that could none of them be
     * evaluated yields {@link DnssecStatus#INSECURE} while a set containing even one demonstrable inconsistency
     * yields {@link DnssecStatus#BOGUS}.
     *
     * <p>"Could not evaluate" survives into the verdict only when the zone offers nothing this build can evaluate.
     * Otherwise the zone is validatable and an RRset that did not validate against it is Bogus, whatever the
     * reason the individual {@code RRSIG}s failed for.
     */
    private static final class Failure {

        private final boolean zoneIsEvaluatable;
        private DnssecFailureReason reason = DnssecFailureReason.DNSSEC_BOGUS;
        private String message = "no RRSIG could be verified";
        private int rank = Integer.MIN_VALUE;

        Failure(boolean zoneIsEvaluatable) {
            this.zoneIsEvaluatable = zoneIsEvaluatable;
        }

        void record(DnssecFailureReason reason, String message) {
            int rank = rank(reason);
            if (rank >= this.rank) {
                this.rank = rank;
                this.reason = reason;
                this.message = message;
            }
        }

        DnssecVerificationResult toResult() {
            if (zoneIsEvaluatable && reason.impliedStatus() == DnssecStatus.INSECURE) {
                return DnssecVerificationResult.failed(DnssecFailureReason.DNSSEC_BOGUS, message
                        + ", and the zone offers an algorithm this build does implement, so this is a failure to "
                        + "validate rather than a zone to treat as unsigned");
            }
            return DnssecVerificationResult.failed(reason, message);
        }

        private static int rank(DnssecFailureReason reason) {
            switch (reason) {
                case UNSUPPORTED_DNSKEY_ALGORITHM:
                    return 10;
                case LOCAL_CRYPTO_UNAVAILABLE:
                    return 11;
                case DNSKEY_MISSING:
                    return 20;
                case KEY_TAG_NO_MATCH:
                    return 30;
                case NO_ZONE_KEY_BIT_SET:
                    return 40;
                case DNSKEY_REVOKED:
                    return 41;
                case SIGNER_NOT_ZONE:
                    return 50;
                case RRSIG_LABELS_INVALID:
                    return 51;
                case COMPRESSED_RDATA:
                case NAME_NOT_REPRESENTABLE:
                    return 55;
                case DNSSEC_BOGUS:
                    return 60;
                case SIGNATURE_NOT_YET_VALID:
                    return 70;
                case SIGNATURE_EXPIRED:
                    return 71;
                default:
                    return 15;
            }
        }
    }
}
