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
 * A machine-readable explanation of why a validation reached the {@link DnssecStatus} it did, and {@link #NONE} when
 * it succeeded.
 *
 * <p>Where the IANA
 * <a href="https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes">Extended
 * DNS Error Codes</a> registry of <a href="https://www.rfc-editor.org/rfc/rfc8914.html">RFC 8914</a> already names
 * the condition, {@link #extendedDnsErrorCode()} returns that registry code so a resolver can copy it straight into
 * an {@code EDE} option of its own response. The finer-grained reasons this package distinguishes internally have no
 * registry equivalent and return {@link #NO_EXTENDED_DNS_ERROR}.
 *
 * <p>Every reason carries the security state it implies through {@link #impliedStatus()}. Two of those mappings are
 * load-bearing and are not a matter of taste:
 * <ul>
 *   <li>{@link #UNSUPPORTED_DNSKEY_ALGORITHM} and {@link #UNSUPPORTED_DS_DIGEST_TYPE} imply
 *   {@link DnssecStatus#INSECURE}, never {@link DnssecStatus#BOGUS}, because
 *   <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.2">RFC 6840, Section 5.2</a> says a delegation
 *   whose {@code DS} records all use unknown algorithms must be treated as unsigned. Failing them closed would
 *   break every zone that has already rolled to an algorithm this build does not implement.</li>
 *   <li>{@link #LIMIT_EXCEEDED} implies {@link DnssecStatus#BOGUS}, never {@link DnssecStatus#INSECURE}. Whether a
 *   limit is reached is under the control of whoever supplies the records, so an attacker who can force a breach
 *   would otherwise hold a downgrade oracle: send enough keys or signatures and the zone stops being validated.</li>
 * </ul>
 */
public enum DnssecFailureReason {

    /**
     * No failure. The response validated, so the status is {@link DnssecStatus#SECURE}.
     */
    NONE(-1, DnssecStatus.SECURE),

    /**
     * Every {@code DNSKEY} offered for the zone uses an algorithm this validator cannot evaluate, so the zone is
     * treated as unsigned, per <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.2">RFC 6840,
     * Section 5.2</a>. Registry code {@code 1}, "Unsupported DNSKEY Algorithm".
     *
     * <p>Note that this is only reached when <em>all</em> of them are unsupported: a zone signed with several
     * algorithms is validated with whichever one this build understands.
     */
    UNSUPPORTED_DNSKEY_ALGORITHM(1, DnssecStatus.INSECURE),

    /**
     * Every {@code DS} record of the delegation uses a digest type this validator cannot evaluate, so the delegation
     * is treated as unsigned, per <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.2">RFC 6840,
     * Section 5.2</a>. Registry code {@code 2}, "Unsupported DS Digest Type".
     */
    UNSUPPORTED_DS_DIGEST_TYPE(2, DnssecStatus.INSECURE),

    /**
     * The validator has no opinion, in the RFC 4033 sense of <em>Indeterminate</em>. Registry code {@code 5},
     * "DNSSEC Indeterminate".
     */
    DNSSEC_INDETERMINATE(5, DnssecStatus.INDETERMINATE),

    /**
     * The response is inconsistent with the chain of trust in a way none of the more specific reasons describes.
     * Registry code {@code 6}, "DNSSEC Bogus".
     */
    DNSSEC_BOGUS(6, DnssecStatus.BOGUS),

    /**
     * An {@code RRSIG} that would otherwise have covered the RRset has an Signature Expiration earlier than the
     * validation time, see <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.3.1">RFC 4035,
     * Section 5.3.1</a>. Registry code {@code 7}, "Signature Expired".
     */
    SIGNATURE_EXPIRED(7, DnssecStatus.BOGUS),

    /**
     * An {@code RRSIG} that would otherwise have covered the RRset has a Signature Inception later than the
     * validation time, see <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.3.1">RFC 4035,
     * Section 5.3.1</a>. Registry code {@code 8}, "Signature Not Yet Valid".
     *
     * <p>Both this and {@link #SIGNATURE_EXPIRED} are decided by serial number arithmetic over the 32-bit fields,
     * per <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-3.1.5">RFC 4034, Section 3.1.5</a>, so they
     * depend on the validation clock rather than on a raw comparison.
     */
    SIGNATURE_NOT_YET_VALID(8, DnssecStatus.BOGUS),

    /**
     * The zone is provably signed, but no {@code DNSKEY} RRset could be obtained for it. Registry code {@code 9},
     * "DNSKEY Missing".
     */
    DNSKEY_MISSING(9, DnssecStatus.BOGUS),

    /**
     * The zone is provably signed, but the RRset arrived with no {@code RRSIG} covering it at all. Registry code
     * {@code 10}, "RRSIGs Missing".
     */
    RRSIGS_MISSING(10, DnssecStatus.BOGUS),

    /**
     * The only {@code DNSKEY} that could have made the signature does not have the Zone Key flag set, so
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-2.1.1">RFC 4034, Section 2.1.1</a> forbids using
     * it to verify zone data. Registry code {@code 11}, "No Zone Key Bit Set".
     */
    NO_ZONE_KEY_BIT_SET(11, DnssecStatus.BOGUS),

    /**
     * A negative or wildcard answer arrived without the {@code NSEC} or {@code NSEC3} records needed to
     * authenticate it, see <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.4">RFC 4035,
     * Section 5.4</a>. Registry code {@code 12}, "NSEC Missing".
     */
    NSEC_MISSING(12, DnssecStatus.BOGUS),

    /**
     * No configured trust anchor covers the name, so there is no chain of trust to follow. This is the original
     * <em>Indeterminate</em> case of <a href="https://www.rfc-editor.org/rfc/rfc4033.html#section-5">RFC 4033,
     * Section 5</a>.
     */
    NO_TRUST_ANCHOR(-1, DnssecStatus.INDETERMINATE),

    /**
     * A lookup the validation depended on, typically a {@code DS} or {@code DNSKEY} RRset, could not be completed.
     *
     * <p>Deliberately {@link DnssecStatus#INDETERMINATE} and not {@link DnssecStatus#INSECURE}: a failure to fetch
     * the {@code DS} RRset is exactly what an on-path attacker can arrange, and treating it as proof that the
     * delegation is unsigned would be a downgrade.
     */
    FETCH_FAILED(-1, DnssecStatus.INDETERMINATE),

    /**
     * A lookup the validation depended on did not answer in time. The distinction from
     * {@link #LIMIT_EXCEEDED} matters: this is the network failing to deliver data, which leaves the validator with
     * nothing to judge, whereas exceeding a limit means the data that did arrive was more work than the validator
     * agreed to do.
     */
    TIMEOUT(-1, DnssecStatus.INDETERMINATE),

    /**
     * One of the {@link DnssecLimits} was reached, so validation was abandoned. See
     * {@link DnssecLimitExceededException}.
     *
     * <p>This is {@link DnssecStatus#BOGUS} on purpose. Every limit bounds work that is driven by records supplied
     * by the other side, so an attacker chooses whether a limit is reached; if reaching one produced
     * {@link DnssecStatus#INSECURE} they would hold a downgrade oracle and could strip DNSSEC from any zone simply
     * by making validation expensive. The validation deadline of {@link DnssecBudget} is treated the same way, for
     * the same reason.
     */
    LIMIT_EXCEEDED(-1, DnssecStatus.BOGUS),

    /**
     * The Signer's Name of an {@code RRSIG} is not the zone that is supposed to have signed the RRset, which
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.3.1">RFC 4035, Section 5.3.1</a> requires it to
     * be. Accepting a signature from an unrelated signer is a cross-zone forgery.
     */
    SIGNER_NOT_ZONE(-1, DnssecStatus.BOGUS),

    /**
     * The Labels field of an {@code RRSIG} is greater than the number of labels in the owner name, or is otherwise
     * inconsistent with it, so the owner name used in the signed data cannot be reconstructed, see
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.3.2">RFC 4035, Section 5.3.2</a>.
     */
    RRSIG_LABELS_INVALID(-1, DnssecStatus.BOGUS),

    /**
     * No {@code DNSKEY} in the zone's key set has the key tag and algorithm named by the {@code RRSIG}, so nothing
     * could have produced that signature.
     *
     * <p>The key tag of <a href="https://www.rfc-editor.org/rfc/rfc4034.html#appendix-B">RFC 4034, Appendix B</a> is
     * a checksum, not an identifier: several keys may share one, and a match is a hint about which key to try
     * rather than a fact about which key signed. See {@link DnssecLimits#maxDnskeysPerKeyTag()}.
     */
    KEY_TAG_NO_MATCH(-1, DnssecStatus.BOGUS),

    /**
     * The only key that matches has the REVOKE bit set, and
     * <a href="https://www.rfc-editor.org/rfc/rfc5011.html#section-2.1">RFC 5011, Section 2.1</a> forbids using a
     * revoked key to validate anything.
     */
    DNSKEY_REVOKED(-1, DnssecStatus.BOGUS),

    /**
     * A {@code DS} record with a supported digest type exists, but no {@code DNSKEY} in the child zone hashes to it,
     * so the secure delegation is broken, see
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.2">RFC 4035, Section 5.2</a>.
     *
     * <p>Not to be confused with {@link #UNSUPPORTED_DS_DIGEST_TYPE}: here the validator could compute the digest
     * and it did not match, which is a proof of inconsistency.
     */
    DS_MISMATCH(-1, DnssecStatus.BOGUS),

    /**
     * The parent zone provably has no {@code DS} record for the delegation, so the child zone is unsigned and the
     * answer is legitimately {@link DnssecStatus#INSECURE}, per
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.2">RFC 4035, Section 5.2</a>.
     *
     * <p>This is the one route to {@link DnssecStatus#INSECURE} that rests on a signed proof of absence rather than
     * on the validator's own inability to evaluate something.
     */
    UNSIGNED_DELEGATION(-1, DnssecStatus.INSECURE),

    /**
     * The delegation falls in the span of an opt-out {@code NSEC3} record, so its existence is unauthenticated and
     * it is treated as unsigned, per
     * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#section-6">RFC 5155, Section 6</a>.
     */
    NSEC3_OPT_OUT(-1, DnssecStatus.INSECURE),

    /**
     * An {@code NSEC3} record asks for more hash iterations than {@link DnssecLimits#maxNsec3Iterations()}.
     * <a href="https://www.rfc-editor.org/rfc/rfc9276.html#section-3.2">RFC 9276, Section 3.2</a> says a validator
     * that declines to do that much work should return an insecure answer, which is what this reports.
     *
     * <p>Above the higher {@link DnssecLimits#maxNsec3IterationsHardFail()} threshold RFC 9276 instead calls for a
     * bogus answer; that case is reported as {@link #LIMIT_EXCEEDED}. The two thresholds exist so that the
     * "insecure" band stays narrow enough not to be a useful downgrade lever.
     */
    NSEC3_ITERATIONS_TOO_HIGH(-1, DnssecStatus.INSECURE),

    /**
     * An {@code NSEC3} record uses a hash algorithm this validator does not implement.
     * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#section-8.1">RFC 5155, Section 8.1</a> requires such
     * records to be ignored, which leaves the denial unproven and the zone treated as unsigned.
     */
    NSEC3_UNKNOWN_HASH(-1, DnssecStatus.INSECURE),

    /**
     * An answer was synthesised from a wildcard but the accompanying proof that no closer match exists is missing or
     * does not cover the queried name, see
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.3.4">RFC 4035, Section 5.3.4</a>. Without it a
     * wildcard answer can be replayed for a name the zone actually defines.
     */
    WILDCARD_PROOF_MISSING(-1, DnssecStatus.BOGUS),

    /**
     * A {@code CNAME} or {@code DNAME} chain in the answer does not link up: it loops, exceeds
     * {@link DnssecLimits#maxCnameChainLength()} links, or has a step whose owner name does not follow from the
     * previous target, see <a href="https://www.rfc-editor.org/rfc/rfc1034.html#section-3.6.2">RFC 1034,
     * Section 3.6.2</a>.
     */
    CNAME_CHAIN_INVALID(-1, DnssecStatus.BOGUS),

    /**
     * A record was offered for a name the responding zone has no authority over, so accepting it would let a zone
     * answer for the rest of the tree, see
     * <a href="https://www.rfc-editor.org/rfc/rfc2181.html#section-5.4.1">RFC 2181, Section 5.4.1</a>.
     */
    BAILIWICK_VIOLATION(-1, DnssecStatus.BOGUS),

    /**
     * The RDATA of a record that has to be canonicalised contains a compression pointer.
     * <a href="https://www.rfc-editor.org/rfc/rfc3597.html#section-4">RFC 3597, Section 4</a> forbids compressing
     * names in the RDATA of types defined after RFC 1035, and
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-6.2">RFC 4034, Section 6.2</a> requires the
     * uncompressed form when building the signed data, so a compressed name makes the canonical form ambiguous and
     * the signature uncheckable.
     */
    COMPRESSED_RDATA(-1, DnssecStatus.BOGUS),

    /**
     * A name that validation would have to construct cannot exist, for example a wildcard expansion longer than the
     * 255 octets a wire-form name is allowed, see
     * <a href="https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4">RFC 1035, Section 2.3.4</a>.
     */
    NAME_NOT_REPRESENTABLE(-1, DnssecStatus.BOGUS),

    /**
     * The running JDK offers no implementation of an algorithm that this package does implement, so the signature
     * could not be checked locally.
     *
     * <p>Indistinguishable from {@link #UNSUPPORTED_DNSKEY_ALGORITHM} as far as the other side is concerned, so it
     * shares registry code {@code 1} and, for the same RFC 6840 reason, resolves to {@link DnssecStatus#INSECURE}.
     * It is a separate constant because the remedy is different: install a security provider rather than wait for
     * the zone to roll its algorithm.
     */
    LOCAL_CRYPTO_UNAVAILABLE(1, DnssecStatus.INSECURE),

    /**
     * Validation could not be completed because of a defect in the validator itself.
     *
     * <p>Fails closed to {@link DnssecStatus#BOGUS} rather than to {@link DnssecStatus#INDETERMINATE}: an internal
     * error that some input can reproduce would otherwise be a downgrade oracle, on the same reasoning as
     * {@link #LIMIT_EXCEEDED}.
     */
    INTERNAL_ERROR(-1, DnssecStatus.BOGUS);

    /**
     * Returned by {@link #extendedDnsErrorCode()} for a reason that the RFC 8914 registry does not name. Negative,
     * so it can never be confused with a registry code, which is an unsigned 16-bit value.
     */
    public static final int NO_EXTENDED_DNS_ERROR = -1;

    // The constants above pass -1 rather than NO_EXTENDED_DNS_ERROR because an enum constant initialiser cannot
    // refer forward to a field of its own enum, and the field cannot be declared before the constants.

    private final int extendedDnsErrorCode;
    private final DnssecStatus impliedStatus;

    DnssecFailureReason(int extendedDnsErrorCode, DnssecStatus impliedStatus) {
        this.extendedDnsErrorCode = extendedDnsErrorCode;
        this.impliedStatus = impliedStatus;
    }

    /**
     * Returns the IANA Extended DNS Error code of
     * <a href="https://www.rfc-editor.org/rfc/rfc8914.html">RFC 8914</a> that names this condition, or
     * {@link #NO_EXTENDED_DNS_ERROR} if the registry has no entry for it.
     *
     * <p>The value is the INFO-CODE field of the {@code EDE} option, so a resolver relaying this verdict can emit it
     * unchanged. It is not unique across reasons: several of the internal reasons describe conditions the registry
     * lumps together.
     */
    public int extendedDnsErrorCode() {
        return extendedDnsErrorCode;
    }

    /**
     * Returns {@code true} if {@link #extendedDnsErrorCode()} is a real registry code rather than
     * {@link #NO_EXTENDED_DNS_ERROR}.
     */
    public boolean hasExtendedDnsErrorCode() {
        return extendedDnsErrorCode >= 0;
    }

    /**
     * Returns the {@link DnssecStatus} this reason implies. {@link #NONE} implies {@link DnssecStatus#SECURE}; every
     * other reason implies one of the three failure states.
     */
    public DnssecStatus impliedStatus() {
        return impliedStatus;
    }
}
