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

import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.util.internal.ObjectUtil;
import io.netty.util.internal.PlatformDependent;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates an authenticated denial of existence: the {@code NSEC} proof of
 * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.4">RFC 4035, section 5.4</a> as corrected by
 * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-4">RFC 6840, section 4</a>, and the {@code NSEC3}
 * proof of <a href="https://www.rfc-editor.org/rfc/rfc5155.html#section-8">RFC 5155, section 8</a> as amended by
 * <a href="https://www.rfc-editor.org/rfc/rfc9276.html#section-3.2">RFC 9276, section 3.2</a>.
 *
 * <h3>Precondition: the records must already be authenticated</h3>
 *
 * <p><strong>This class verifies no signature.</strong> It answers "do these records, taken as true, prove what the
 * response claims", and nothing else. Every {@code NSEC} or {@code NSEC3} record handed to it must already have had
 * its covering {@code RRSIG} verified against an authenticated {@code DNSKEY} of {@code zone}, with the Signer's
 * Name checked to be {@code zone}. Feeding it unauthenticated records is not a partial validation, it is no
 * validation at all: anyone able to write a UDP packet can then choose the answer, since the whole content of a
 * denial proof is "these names and types are absent".</p>
 *
 * <p>The precondition holds even where the verdict is {@link DnssecStatus#INSECURE}. RFC 9276, section 3.2 is
 * explicit that a validator which declines to do the work an {@code NSEC3} iteration count asks for "MUST still
 * validate the signature over the NSEC3 record to ensure the iteration count was not altered since record
 * publication", citing <a href="https://www.rfc-editor.org/rfc/rfc5155.html#section-10.3">RFC 5155,
 * section 10.3</a>: an unverified iteration count is a field the attacker fills in, and inflating it would be a
 * one-packet downgrade of any zone.</p>
 *
 * <h3>What it does check</h3>
 *
 * <p>Beyond the proof itself, the clarifications that exist because leaving them out is exploitable:</p>
 * <ul>
 *   <li>An NSEC or NSEC3 record from an <em>ancestor</em> zone may not deny anything below its zone cut except a
 *   {@code DS}, and one with the {@code DNAME} bit set may not deny any subdomain of its owner (RFC 6840,
 *   section 4.1).</li>
 *   <li>A NODATA proof must have the {@code CNAME} bit clear as well as the {@code QTYPE} bit (RFC 6840,
 *   section 4.3), or stripping a {@code CNAME} RRset from a positive answer turns it into a NODATA.</li>
 *   <li>An insecure delegation proof must have the {@code NS} bit <em>set</em> as well as {@code DS} and
 *   {@code SOA} clear (RFC 6840, section 4.4), or an NSEC matching an ordinary name can be replayed to strip
 *   DNSSEC from a signed subtree.</li>
 *   <li>Opt-out never proves that something does not exist, so a proof that leans on it is
 *   {@link DnssecStatus#INSECURE} rather than {@link DnssecStatus#SECURE} (RFC 5155, sections 6 and 9.2).</li>
 * </ul>
 *
 * <h3>Bounds</h3>
 *
 * <p>Every walk here is bounded by construction rather than by a termination condition: the closest-encloser search
 * counts down the labels of the query name, and the number of records, hash computations and the wall-clock
 * deadline all come from the one {@link DnssecBudget} passed to the constructor. Exceeding any of them is
 * {@link DnssecStatus#BOGUS} and never {@link DnssecStatus#INSECURE}, because the records that drive the work come
 * from the other side of the wire and a limit breach that downgraded a zone would be a downgrade oracle rather
 * than a defence.</p>
 *
 * <p>The shape of the bug this avoids is worth naming. hickory-dns
 * <a href="https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-3v94-mw7p-v465">GHSA-3v94-mw7p-v465</a>
 * looked for the closest encloser with a loop that stopped when the candidate equalled the {@code SOA} owner name;
 * given a response whose {@code SOA} owner is not an ancestor of the query name, the candidate walked past the root
 * and the loop never stopped. This class instead requires up front that the query name is at or below {@code zone}
 * and iterates a fixed number of times.</p>
 *
 * <p>One instance belongs to one validation and is not thread-safe, exactly like the {@link DnssecBudget} it holds.
 * Several proofs may be evaluated on one instance, which is worth doing: they share the {@code NSEC3} hash cache,
 * and the budget is spent once for a name however many proofs need it.</p>
 */
public final class DnssecDenialOfExistence {

    private final DnsName zone;
    private final DnssecBudget budget;
    private final DnsNsec3Hasher hasher;

    /**
     * Creates an evaluator for proofs made by {@code zone}.
     *
     * @param zone   the apex of the zone that signed the records, that is, the Signer's Name of the {@code RRSIG}
     *               the caller has already verified over them
     * @param budget the work this validation has left; shared with every other step of the same validation, so
     *               that a proof cannot be made cheap by splitting it across entry points
     */
    public DnssecDenialOfExistence(DnsName zone, DnssecBudget budget) {
        this.zone = ObjectUtil.checkNotNull(zone, "zone");
        this.budget = ObjectUtil.checkNotNull(budget, "budget");
        hasher = new DnsNsec3Hasher(budget);
    }

    /**
     * Returns the zone apex this evaluator judges records against.
     */
    public DnsName zone() {
        return zone;
    }

    /**
     * Returns the budget this evaluator spends.
     */
    public DnssecBudget budget() {
        return budget;
    }

    /**
     * Evaluates the proof that accompanies a name error, an {@code NXDOMAIN}: that {@code qname} does not exist and
     * that no wildcard could have been expanded to answer for it.
     *
     * <p>With {@code NSEC} that is an {@code NSEC} covering {@code qname} plus one covering the wildcard at the
     * closest encloser (RFC 4035, section 5.4). With {@code NSEC3} it is the closest encloser proof of RFC 5155,
     * section 8.3 plus an {@code NSEC3} covering the wildcard at the closest encloser (section 8.4).</p>
     *
     * <p>An {@code NSEC3} name error whose "next closer" name is covered by an opt-out record is
     * {@link DnssecStatus#INSECURE}: RFC 5155, section 9.2 forbids setting the {@code AD} bit on exactly this
     * response, because the covered name may still exist as an insecure delegation and the correct answer would
     * then have been a referral. The name error is still usable, it simply is not authenticated. Every proof in
     * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#appendix-B">RFC 5155, appendix B</a> that rests on
     * coverage falls in this case, because the example zone sets opt-out throughout.</p>
     *
     * @param qname   the name that does not exist
     * @param records the authenticated records of the response, from which the {@link DnsNsecRecord} and
     *                {@link DnsNsec3Record} instances are taken and everything else is ignored
     */
    public Result proveNameError(DnsName qname, List<? extends DnsRecord> records) {
        return evaluate(Proof.NAME_ERROR, qname, null, null, records);
    }

    /**
     * Evaluates the proof that accompanies a {@code NOERROR}/{@code NODATA} answer: that {@code qname} exists but
     * has no RRset of type {@code qtype}.
     *
     * <p>The straightforward form is an {@code NSEC} or {@code NSEC3} matching {@code qname} with the {@code QTYPE}
     * bit clear and, per RFC 6840, section 4.3, the {@code CNAME} bit clear too. Two variants are also accepted:</p>
     * <ul>
     *   <li>a wildcard NODATA, where {@code qname} itself does not exist but a wildcard at its closest encloser
     *   matches and has neither bit set (RFC 4035, appendix B.7 and RFC 5155, section 8.7);</li>
     *   <li>for {@code QTYPE} other than {@code DS} and with no matching record at all, a closest <em>provable</em>
     *   encloser proof whose "next closer" name is covered by an opt-out record, which is
     *   <a href="https://www.rfc-editor.org/errata/eid3441">RFC 5155 erratum 3441</a> against section 8.5: the case
     *   of an empty non-terminal derived from an insecure delegation. Section 8.5 as published has no such branch,
     *   and the answer there is {@link DnssecStatus#INSECURE}, since opt-out asserts nothing about the names it
     *   covers.</li>
     * </ul>
     *
     * <p>For {@code QTYPE=DS} the record must come from the parent side of the delegation, which means its
     * {@code SOA} bit must be clear;
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#appendix-B.8">RFC 4035, appendix B.8</a> and
     * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#appendix-B.6">RFC 5155, appendix B.6</a> are the
     * responses a child server gives to a {@code DS} query, and they are rejected here. That is not an accusation
     * of forgery: the remedy is to ask the parent. A {@link DnssecStatus#SECURE} verdict for {@code QTYPE=DS} says
     * only that the {@code DS} RRset provably does not exist; whether that makes a delegation insecure is
     * {@link #proveUnsignedDelegation(DnsName, List)}, which additionally requires the {@code NS} bit.</p>
     *
     * <p>The {@code NSEC} and {@code RRSIG} bits of an {@code NSEC} record are ignored, as RFC 4035, section 5.4
     * requires, so a NODATA proof for those two types is never accepted from one. No such rule applies to
     * {@code NSEC3}, whose bitmap describes the <em>original</em> owner name, at which no {@code NSEC3} record
     * lives; the type does exist at the hashed owner name, which is what
     * <a href="https://www.rfc-editor.org/errata/eid4622">RFC 5155 erratum 4622</a> corrects section 7.2.8 to
     * say.</p>
     *
     * @param qname   the name that exists
     * @param qtype   the RR type that does not exist at {@code qname}
     * @param records the authenticated records of the response
     */
    public Result proveNoData(DnsName qname, DnsRecordType qtype, List<? extends DnsRecord> records) {
        ObjectUtil.checkNotNull(qtype, "qtype");
        return evaluate(Proof.NO_DATA, qname, qtype, null, records);
    }

    /**
     * Evaluates the proof that must accompany an answer synthesised from a wildcard: that {@code qname} itself does
     * not exist, so that {@code wildcardOwner} really was the closest match.
     *
     * <p>Without it a wildcard answer can be replayed for a name the zone actually defines. With {@code NSEC} the
     * proof is an {@code NSEC} covering {@code qname} whose closest encloser is the parent of
     * {@code wildcardOwner}; with {@code NSEC3} it is an {@code NSEC3} covering the "next closer" name to
     * {@code qname} (RFC 5155, section 8.8). No record matching the closest encloser is required in the
     * {@code NSEC3} case, and none is looked for: the wildcard answer itself proves that name exists.</p>
     *
     * @param qname         the queried name, which the wildcard was expanded to answer for
     * @param wildcardOwner the owner name of the wildcard RRset, {@code *} followed by the closest encloser, as the
     *                      Labels field of the answer's {@code RRSIG} identifies it
     * @param records       the authenticated records of the response
     */
    public Result proveWildcardAnswer(DnsName qname, DnsName wildcardOwner, List<? extends DnsRecord> records) {
        ObjectUtil.checkNotNull(wildcardOwner, "wildcardOwner");
        return evaluate(Proof.WILDCARD_ANSWER, qname, null, wildcardOwner, records);
    }

    /**
     * Evaluates the proof that a referral leads to an unsigned zone: that {@code childZone} is a delegation and
     * that the parent publishes no {@code DS} for it, which makes {@code childZone} and everything under it
     * {@link DnssecStatus#INSECURE}.
     *
     * <p>Per RFC 6840, section 4.4 this needs the {@code NS} bit <em>set</em> and the {@code DS} and {@code SOA}
     * bits clear. The {@code NS} check is the one implementations forget, and without it an attacker replays an
     * NSEC or NSEC3 matching some ordinary name to claim a delegation exists where there is none, moving a signed
     * subtree out of DNSSEC's reach. The {@code SOA} check keeps the child's own apex record from being used to
     * answer a question only the parent can answer.</p>
     *
     * <p>With {@code NSEC3} the delegation name may instead have no matching record at all, provided a closest
     * provable encloser proof is present and the "next closer" name is covered by an opt-out record (RFC 5155,
     * section 8.9). That is opt-out's sanctioned use, and it is why an opt-out zone can carry insecure delegations
     * without an {@code NSEC3} at each one.</p>
     *
     * <p>A successful proof here is {@link DnssecStatus#INSECURE}, which is the answer, not a failure:
     * {@link DnssecFailureReason#UNSIGNED_DELEGATION} and {@link DnssecFailureReason#NSEC3_OPT_OUT} are the two
     * routes to it. {@link DnssecStatus#BOGUS} means the referral was not proven insecure and must not be
     * followed.</p>
     *
     * @param childZone the owner name of the {@code NS} RRset in the authority section of the referral
     * @param records   the authenticated records of the response
     */
    public Result proveUnsignedDelegation(DnsName childZone, List<? extends DnsRecord> records) {
        return evaluate(Proof.UNSIGNED_DELEGATION, childZone, null, null, records);
    }

    @Override
    public String toString() {
        return "DnssecDenialOfExistence(zone: " + zone + ", " + budget + ')';
    }

    // -----------------------------------------------------------------------------------------------------------
    // Dispatch
    // -----------------------------------------------------------------------------------------------------------

    private Result evaluate(Proof proof, DnsName subject, DnsRecordType qtype, DnsName wildcardOwner,
                            List<? extends DnsRecord> records) {
        ObjectUtil.checkNotNull(subject, "qname");
        ObjectUtil.checkNotNull(records, "records");
        try {
            budget.checkDeadline();
            // The guard that makes every walk below finite. A subject outside the zone has no closest encloser in
            // it, and a search for one has nowhere to stop.
            if (!subject.equalsOrIsSubDomainOf(zone)) {
                return bogus(DnssecFailureReason.BAILIWICK_VIOLATION);
            }
            List<DnsNsec3Record> rawNsec3 = collectNsec3(records);
            if (!rawNsec3.isEmpty()) {
                Nsec3Set set = nsec3Set(rawNsec3);
                if (set.failure != null) {
                    return set.failure;
                }
                switch (proof) {
                    case NAME_ERROR:
                        return nsec3NameError(subject, set);
                    case NO_DATA:
                        return nsec3NoData(subject, qtype, set);
                    case WILDCARD_ANSWER:
                        return nsec3WildcardAnswer(subject, wildcardOwner, set);
                    default:
                        return nsec3UnsignedDelegation(subject, set);
                }
            }
            List<DnsNsecRecord> nsec = collectNsec(records);
            if (nsec.isEmpty()) {
                return bogus(DnssecFailureReason.NSEC_MISSING);
            }
            switch (proof) {
                case NAME_ERROR:
                    return nsecNameError(subject, nsec);
                case NO_DATA:
                    return nsecNoData(subject, qtype, nsec);
                case WILDCARD_ANSWER:
                    return nsecWildcardAnswer(subject, wildcardOwner, nsec);
                default:
                    return nsecUnsignedDelegation(subject, nsec);
            }
        } catch (DnssecLimitExceededException e) {
            return bogus(DnssecFailureReason.LIMIT_EXCEEDED);
        }
    }

    private List<DnsNsecRecord> collectNsec(List<? extends DnsRecord> records) {
        List<DnsNsecRecord> collected = new ArrayList<DnsNsecRecord>(4);
        int limit = budget.limits().maxNsecRecordsPerProof();
        int seen = 0;
        for (DnsRecord record : records) {
            if (!(record instanceof DnsNsecRecord)) {
                continue;
            }
            if (++seen > limit) {
                throw new DnssecLimitExceededException("maxNsecRecordsPerProof", limit);
            }
            DnsNsecRecord nsec = (DnsNsecRecord) record;
            // An NSEC whose owner is outside the zone cannot say anything about it, and letting one take part
            // would hand whoever supplied it an interval of its own choosing in the canonical ordering.
            if (nsec.owner().equalsOrIsSubDomainOf(zone)) {
                collected.add(nsec);
            }
        }
        return collected;
    }

    private List<DnsNsec3Record> collectNsec3(List<? extends DnsRecord> records) {
        List<DnsNsec3Record> collected = new ArrayList<DnsNsec3Record>(4);
        int limit = budget.limits().maxNsec3RecordsPerProof();
        for (DnsRecord record : records) {
            if (!(record instanceof DnsNsec3Record)) {
                continue;
            }
            // Counted before any record is dropped, so that padding a response with records this class will go on
            // to ignore is not a way to buy room under the limit.
            if (collected.size() == limit) {
                throw new DnssecLimitExceededException("maxNsec3RecordsPerProof", limit);
            }
            collected.add((DnsNsec3Record) record);
        }
        return collected;
    }

    // -----------------------------------------------------------------------------------------------------------
    // NSEC, RFC 4035 section 5.4 and RFC 6840 section 4
    // -----------------------------------------------------------------------------------------------------------

    private Result nsecNameError(DnsName qname, List<DnsNsecRecord> nsec) {
        if (matchingNsec(nsec, qname) != null) {
            // The zone itself says the name exists, so the name error contradicts the proof offered for it.
            return bogus(DnssecFailureReason.DNSSEC_BOGUS);
        }
        DnsNsecRecord covering = coveringNsec(nsec, qname);
        if (covering == null) {
            return bogus(DnssecFailureReason.NSEC_MISSING);
        }
        DnsName closestEncloser = closestEncloserOf(qname, covering);
        if (closestEncloser == null || closestEncloser.labelCount() >= qname.labelCount()) {
            return bogus(DnssecFailureReason.DNSSEC_BOGUS);
        }
        DnsName wildcard = wildcardOf(closestEncloser);
        if (wildcard == null) {
            return bogus(DnssecFailureReason.NAME_NOT_REPRESENTABLE);
        }
        if (matchingNsec(nsec, wildcard) != null) {
            // The wildcard exists, so the answer should have been synthesised from it rather than denied.
            return bogus(DnssecFailureReason.DNSSEC_BOGUS);
        }
        if (coveringNsec(nsec, wildcard) == null) {
            return bogus(DnssecFailureReason.WILDCARD_PROOF_MISSING);
        }
        return secure(closestEncloser);
    }

    private Result nsecNoData(DnsName qname, DnsRecordType qtype, List<DnsNsecRecord> nsec) {
        boolean ds = isType(qtype, DnsRecordType.DS);
        DnsNsecRecord match = matchingNsec(nsec, qname);
        if (match != null) {
            if (!usableToDeny(match, qname, ds)) {
                return bogus(DnssecFailureReason.DNSSEC_BOGUS);
            }
            if (ds && match.types().contains(DnsRecordType.SOA)) {
                // The DS RRset lives in the parent zone, so an NSEC carrying the SOA bit is the child's own apex
                // record and has no authority over it. RFC 4035, appendix B.8.
                return bogus(DnssecFailureReason.BAILIWICK_VIOLATION);
            }
            return noDataAt(match.types(), qtype, true, null);
        }
        if (ds) {
            // A DS RRset is never produced by wildcard expansion, so with nothing matching QNAME there is no
            // second way to deny it.
            return bogus(DnssecFailureReason.NSEC_MISSING);
        }
        // RFC 4035, appendix B.7: QNAME does not exist, but a wildcard at its closest encloser matches it and has
        // no RRset of the queried type.
        DnsNsecRecord covering = coveringNsec(nsec, qname);
        if (covering == null) {
            return bogus(DnssecFailureReason.NSEC_MISSING);
        }
        DnsName closestEncloser = closestEncloserOf(qname, covering);
        if (closestEncloser == null || closestEncloser.labelCount() >= qname.labelCount()) {
            return bogus(DnssecFailureReason.DNSSEC_BOGUS);
        }
        DnsName wildcard = wildcardOf(closestEncloser);
        if (wildcard == null) {
            return bogus(DnssecFailureReason.NAME_NOT_REPRESENTABLE);
        }
        DnsNsecRecord wildcardMatch = matchingNsec(nsec, wildcard);
        if (wildcardMatch == null) {
            return bogus(DnssecFailureReason.WILDCARD_PROOF_MISSING);
        }
        if (!usableToDeny(wildcardMatch, wildcard, false)) {
            return bogus(DnssecFailureReason.DNSSEC_BOGUS);
        }
        return noDataAt(wildcardMatch.types(), qtype, true, closestEncloser);
    }

    private Result nsecWildcardAnswer(DnsName qname, DnsName wildcardOwner, List<DnsNsecRecord> nsec) {
        DnsName closestEncloser = closestEncloserOfWildcard(qname, wildcardOwner);
        if (closestEncloser == null) {
            return bogus(DnssecFailureReason.DNSSEC_BOGUS);
        }
        if (matchingNsec(nsec, qname) != null) {
            // QNAME exists, so no wildcard should have been expanded for it.
            return bogus(DnssecFailureReason.DNSSEC_BOGUS);
        }
        DnsNsecRecord covering = coveringNsec(nsec, qname);
        if (covering == null) {
            return bogus(DnssecFailureReason.WILDCARD_PROOF_MISSING);
        }
        // The closest encloser the chain proves must be the one the answer claims to have expanded a wildcard at.
        // A proof for some shorter ancestor would leave a nearer wildcard, or a nearer real name, unaccounted for.
        if (!closestEncloser.equals(closestEncloserOf(qname, covering))) {
            return bogus(DnssecFailureReason.WILDCARD_PROOF_MISSING);
        }
        return secure(closestEncloser);
    }

    private Result nsecUnsignedDelegation(DnsName childZone, List<DnsNsecRecord> nsec) {
        if (!childZone.isStrictSubDomainOf(zone)) {
            return bogus(DnssecFailureReason.BAILIWICK_VIOLATION);
        }
        DnsNsecRecord match = matchingNsec(nsec, childZone);
        if (match == null) {
            // NSEC has no opt-out, so a delegation with no NSEC of its own is simply unproven.
            return bogus(DnssecFailureReason.NSEC_MISSING);
        }
        return delegationFrom(match.types(), childZone);
    }

    /**
     * Returns the NSEC whose owner name is {@code name}, or {@code null}.
     */
    private DnsNsecRecord matchingNsec(List<DnsNsecRecord> nsec, DnsName name) {
        for (int i = 0; i < nsec.size(); i++) {
            DnsNsecRecord record = nsec.get(i);
            if (record.owner().equals(name)) {
                return record;
            }
        }
        return null;
    }

    /**
     * Returns an NSEC that both spans {@code name} and is allowed to deny it, or {@code null}.
     */
    private DnsNsecRecord coveringNsec(List<DnsNsecRecord> nsec, DnsName name) {
        for (int i = 0; i < nsec.size(); i++) {
            budget.checkDeadline();
            DnsNsecRecord record = nsec.get(i);
            if (covers(record, name) && usableToDeny(record, name, false)) {
                return record;
            }
        }
        return null;
    }

    /**
     * Returns {@code true} if {@code name} sorts strictly between the owner name and the Next Domain Name of
     * {@code nsec} in the canonical order of RFC 4034, section 6.1.
     */
    private static boolean covers(DnsNsecRecord nsec, DnsName name) {
        DnsName owner = nsec.owner();
        DnsName next = nsec.nextDomainName();
        int span = DnsName.CANONICAL_ORDER.compare(owner, next);
        int afterOwner = DnsName.CANONICAL_ORDER.compare(owner, name);
        int beforeNext = DnsName.CANONICAL_ORDER.compare(name, next);
        if (span < 0) {
            return afterOwner < 0 && beforeNext < 0;
        }
        // The last NSEC of a zone names the apex as its next domain name (RFC 4034, section 4.1.1), and the apex
        // sorts before every name below it, so this one interval wraps. A plain "owner < name < next" test is
        // false for every name in it, which is the whole tail of the zone: names after the last one that exists
        // would silently stop being deniable, and an NXDOMAIN for any of them would fail. The degenerate case
        // where owner equals next, a zone whose only name is its apex, lands here too and covers everything else.
        return afterOwner < 0 || beforeNext < 0;
    }

    /**
     * Applies the two restrictions of RFC 6840, section 4.1 on which NSEC may deny what.
     *
     * @param forDs {@code true} when the question is whether a {@code DS} RRset exists at {@code name}, the one
     *              thing an ancestor delegation NSEC is allowed to answer at its own owner name
     */
    private boolean usableToDeny(DnsNsecRecord nsec, DnsName name, boolean forDs) {
        DnsName owner = nsec.owner();
        DnsTypeBitmap types = nsec.types();
        // An "ancestor delegation" NSEC: NS set, SOA clear, and a signer shorter than the owner name, which for an
        // already-authenticated record means the zone that signed it. It sits at a zone cut in the parent, so
        // everything at or below that cut belongs to the child and it may deny none of it. Without this an NSEC
        // from a parent zone is a licence to deny anything in the child.
        if (types.contains(DnsRecordType.NS) && !types.contains(DnsRecordType.SOA)
                && zone.labelCount() < owner.labelCount()
                && name.equalsOrIsSubDomainOf(owner) && !(forDs && name.equals(owner))) {
            return false;
        }
        // A name below a DNAME is rewritten, not absent, so an NSEC at the DNAME's owner proves nothing about it.
        return !(types.contains(DnsRecordType.DNAME) && name.isStrictSubDomainOf(owner));
    }

    /**
     * Derives the closest encloser of {@code qname} from an NSEC that covers it.
     *
     * <p>Both names in the record exist in the zone, and no name between them does. The longest ancestor of
     * {@code qname} that exists is therefore the longest name that is a suffix of {@code qname} and of the owner
     * name: any longer ancestor of {@code qname} would have to sort inside the interval the record denies.</p>
     *
     * @return the closest encloser, or {@code null} if the record is inconsistent with {@code qname} not existing
     */
    private DnsName closestEncloserOf(DnsName qname, DnsNsecRecord covering) {
        DnsName fromOwner = commonSuffix(qname, covering.owner());
        DnsName fromNext = commonSuffix(qname, covering.nextDomainName());
        // The Next Domain Name shares exactly the same closest encloser. Sharing more of QNAME means it lies below
        // QNAME, so QNAME exists as an empty non-terminal and whatever was being denied is not deniable this way.
        if (fromNext.labelCount() > fromOwner.labelCount()) {
            return null;
        }
        return fromOwner.labelCount() < zone.labelCount() ? null : fromOwner;
    }

    // -----------------------------------------------------------------------------------------------------------
    // NSEC3, RFC 5155 section 8
    // -----------------------------------------------------------------------------------------------------------

    private Result nsec3NameError(DnsName qname, Nsec3Set set) {
        ClosestEncloser encloser = closestEncloser(qname, set);
        if (encloser.failure != null) {
            return encloser.failure;
        }
        DnsName wildcard = wildcardOf(encloser.name);
        if (wildcard == null) {
            return bogus(DnssecFailureReason.NAME_NOT_REPRESENTABLE);
        }
        if (matchingNsec3(set, wildcard) != null) {
            return bogus(DnssecFailureReason.DNSSEC_BOGUS);
        }
        if (coveringNsec3(set, wildcard) == null) {
            return bogus(DnssecFailureReason.WILDCARD_PROOF_MISSING);
        }
        return encloser.optOut() ? optOut(encloser.name) : secure(encloser.name);
    }

    private Result nsec3NoData(DnsName qname, DnsRecordType qtype, Nsec3Set set) {
        boolean ds = isType(qtype, DnsRecordType.DS);
        DnsNsec3Record match = matchingNsec3(set, qname);
        if (match != null) {
            DnsTypeBitmap types = match.types();
            if (ds) {
                if (types.contains(DnsRecordType.SOA)) {
                    // RFC 5155, appendix B.6: the child's apex record, which cannot deny the parent's DS.
                    return bogus(DnssecFailureReason.BAILIWICK_VIOLATION);
                }
            } else if (types.contains(DnsRecordType.NS) && !types.contains(DnsRecordType.SOA)
                    && zone.labelCount() < qname.labelCount()) {
                // RFC 6840, section 4.1: an ancestor delegation record answers for DS and for nothing else.
                return bogus(DnssecFailureReason.DNSSEC_BOGUS);
            }
            return noDataAt(types, qtype, false, null);
        }
        // With nothing matching QNAME the answer can still be a wildcard NODATA, RFC 5155, section 8.7.
        ClosestEncloser encloser = closestEncloser(qname, set);
        if (encloser.failure != null) {
            return encloser.failure;
        }
        if (!ds) {
            DnsName wildcard = wildcardOf(encloser.name);
            if (wildcard == null) {
                return bogus(DnssecFailureReason.NAME_NOT_REPRESENTABLE);
            }
            DnsNsec3Record wildcardMatch = matchingNsec3(set, wildcard);
            if (wildcardMatch != null) {
                DnsTypeBitmap types = wildcardMatch.types();
                if (types.contains(DnsRecordType.NS) && !types.contains(DnsRecordType.SOA)) {
                    return bogus(DnssecFailureReason.DNSSEC_BOGUS);
                }
                Result result = noDataAt(types, qtype, false, encloser.name);
                if (result.status() == DnssecStatus.SECURE && encloser.optOut()) {
                    // The wildcard denies the type, but the proof that QNAME itself does not exist rests on an
                    // opt-out span, so RFC 5155, section 9.2 forbids calling the answer authenticated.
                    return optOut(encloser.name);
                }
                return result;
            }
        }
        // RFC 5155 erratum 3441 against section 8.5, and section 8.6 for DS: with no record at QNAME and no
        // wildcard either, the only thing that can explain the absence is an opt-out span, and an opt-out span
        // asserts nothing, so the answer is insecure rather than proven.
        if (!encloser.optOut()) {
            return bogus(DnssecFailureReason.NSEC_MISSING);
        }
        return optOut(encloser.name);
    }

    private Result nsec3WildcardAnswer(DnsName qname, DnsName wildcardOwner, Nsec3Set set) {
        DnsName closestEncloser = closestEncloserOfWildcard(qname, wildcardOwner);
        if (closestEncloser == null) {
            return bogus(DnssecFailureReason.DNSSEC_BOGUS);
        }
        // RFC 5155, section 8.8: the answer itself proves the closest encloser exists, so only the "next closer"
        // name has to be shown absent.
        DnsName nextCloser = qname.stripLeftmostLabels(qname.labelCount() - closestEncloser.labelCount() - 1);
        DnsNsec3Record covering = coveringNsec3(set, nextCloser);
        if (covering == null) {
            return bogus(DnssecFailureReason.WILDCARD_PROOF_MISSING);
        }
        return covering.isOptOut() ? optOut(closestEncloser) : secure(closestEncloser);
    }

    private Result nsec3UnsignedDelegation(DnsName childZone, Nsec3Set set) {
        if (!childZone.isStrictSubDomainOf(zone)) {
            return bogus(DnssecFailureReason.BAILIWICK_VIOLATION);
        }
        DnsNsec3Record match = matchingNsec3(set, childZone);
        if (match != null) {
            return delegationFrom(match.types(), childZone);
        }
        // RFC 5155, section 8.9: an opt-out zone need not carry an NSEC3 at every insecure delegation.
        ClosestEncloser encloser = closestEncloser(childZone, set);
        if (encloser.failure != null) {
            return encloser.failure;
        }
        if (!encloser.optOut()) {
            return bogus(DnssecFailureReason.NSEC_MISSING);
        }
        return optOut(encloser.name);
    }

    /**
     * Runs the closest encloser proof of RFC 5155, section 8.3.
     *
     * <p>The walk is a counted {@code for} over the labels {@code qname} has below the zone apex, not a loop that
     * stops when it recognises the apex. That is the difference between this and hickory's GHSA-3v94-mw7p-v465,
     * where an apex that was not an ancestor of the query name meant the stopping condition was never met.</p>
     */
    private ClosestEncloser closestEncloser(DnsName qname, Nsec3Set set) {
        int depth = qname.labelCount() - zone.labelCount();
        for (int strip = 0; strip <= depth; strip++) {
            budget.checkDeadline();
            DnsName candidate = qname.stripLeftmostLabels(strip);
            DnsNsec3Record match = matchingNsec3(set, candidate);
            if (match == null) {
                continue;
            }
            if (strip == 0) {
                // Section 8.3 reaches a matching record with its flag still clear, which it calls bogus: nothing
                // was shown not to exist, because QNAME itself is there.
                return ClosestEncloser.failed(bogus(DnssecFailureReason.DNSSEC_BOGUS));
            }
            DnsTypeBitmap types = match.types();
            // The closing rule of section 8.3: the record at the closest encloser has to be from the zone that is
            // authoritative for it, or an attacker uses a record from elsewhere to deny names it has no say over.
            if (types.contains(DnsRecordType.DNAME)
                    || (types.contains(DnsRecordType.NS) && !types.contains(DnsRecordType.SOA))) {
                return ClosestEncloser.failed(bogus(DnssecFailureReason.DNSSEC_BOGUS));
            }
            DnsName nextCloser = qname.stripLeftmostLabels(strip - 1);
            DnsNsec3Record covering = coveringNsec3(set, nextCloser);
            if (covering == null) {
                return ClosestEncloser.failed(bogus(DnssecFailureReason.NSEC_MISSING));
            }
            return new ClosestEncloser(candidate, covering);
        }
        return ClosestEncloser.failed(bogus(DnssecFailureReason.NSEC_MISSING));
    }

    private DnsNsec3Record matchingNsec3(Nsec3Set set, DnsName name) {
        byte[] hash = hasher.hash(name, set.hashAlgorithm, set.iterations, set.salt);
        for (int i = 0; i < set.entries.size(); i++) {
            Nsec3Entry entry = set.entries.get(i);
            if (entry.ownerHash.length == hash.length
                    && PlatformDependent.equalsConstantTime(entry.ownerHash, 0, hash, 0, hash.length) != 0) {
                return entry.record;
            }
        }
        return null;
    }

    private DnsNsec3Record coveringNsec3(Nsec3Set set, DnsName name) {
        byte[] hash = hasher.hash(name, set.hashAlgorithm, set.iterations, set.salt);
        for (int i = 0; i < set.entries.size(); i++) {
            budget.checkDeadline();
            Nsec3Entry entry = set.entries.get(i);
            byte[] owner = entry.ownerHash;
            byte[] next = entry.record.nextHashedOwnerName();
            int span = compareHash(owner, next);
            int afterOwner = compareHash(owner, hash);
            int beforeNext = compareHash(hash, next);
            boolean covers = span < 0 ? afterOwner < 0 && beforeNext < 0 : afterOwner < 0 || beforeNext < 0;
            if (covers) {
                return entry.record;
            }
        }
        return null;
    }

    /**
     * Applies RFC 5155, sections 8.1 and 8.2 and the parameter policy of RFC 9276, section 3.2 to the records of
     * one response, and decodes the hash out of each owner name so that the proofs above compare octets.
     */
    private Nsec3Set nsec3Set(List<DnsNsec3Record> records) {
        int hashAlgorithm = -1;
        int iterations = -1;
        byte[] salt = null;
        List<Nsec3Entry> entries = new ArrayList<Nsec3Entry>(records.size());
        for (int i = 0; i < records.size(); i++) {
            DnsNsec3Record record = records.get(i);
            // Section 8.2: every flag other than Opt-Out is reserved, and a record that sets one must be ignored
            // rather than interpreted.
            if ((record.flags() & ~DnsNsec3Record.FLAG_OPT_OUT) != 0) {
                continue;
            }
            // Section 8.1: a hash type this validator does not know cannot be checked, so the record is ignored.
            // A zone rolling to a new hash algorithm publishes both chains and this is what picks ours out.
            if (!DnsNsec3Hasher.isSupportedAlgorithm(record.hashAlgorithm())) {
                continue;
            }
            if (hashAlgorithm < 0) {
                hashAlgorithm = record.hashAlgorithm();
                iterations = record.iterations();
                salt = record.salt();
            } else if (hashAlgorithm != record.hashAlgorithm() || iterations != record.iterations()
                    || !equalSalt(salt, record.salt())) {
                // Section 8.2 leaves this a MAY; it is a MUST here. Records that disagree on the parameters need
                // one hash chain each, and the query name has to be re-hashed against every chain at every step of
                // every closest-encloser walk. That product is the whole of the NSEC3 amplification, and no
                // legitimate zone needs it: RFC 5155, appendix C.1 requires one complete set of NSEC3 records per
                // salt value, so a proof is always assembled from records that agree.
                return Nsec3Set.failed(bogus(DnssecFailureReason.DNSSEC_BOGUS));
            }
            Nsec3Entry entry = entryOf(record, hashAlgorithm);
            if (entry != null) {
                entries.add(entry);
            }
        }
        if (entries.isEmpty()) {
            // Section 8.1: "responses containing only such NSEC3 RRs will generally be considered bogus".
            return Nsec3Set.failed(bogus(DnssecFailureReason.NSEC_MISSING));
        }
        DnssecLimits limits = budget.limits();
        if (salt.length > limits.maxNsec3SaltLength()) {
            throw new DnssecLimitExceededException("maxNsec3SaltLength", limits.maxNsec3SaltLength());
        }
        // RFC 9276, section 3.2 has two thresholds, and both matter. Above the higher one the answer is rejected;
        // between them it is returned unauthenticated. Keeping the insecure band narrow is what stops "make the
        // validator work harder" from being a general way to switch validation off for a zone.
        if (iterations > limits.maxNsec3IterationsHardFail()) {
            throw new DnssecLimitExceededException("maxNsec3IterationsHardFail", limits.maxNsec3IterationsHardFail());
        }
        if (iterations > limits.maxNsec3Iterations()) {
            return Nsec3Set.failed(new Result(DnssecStatus.INSECURE, DnssecFailureReason.NSEC3_ITERATIONS_TOO_HIGH,
                    null, false));
        }
        return new Nsec3Set(entries, hashAlgorithm, iterations, salt);
    }

    /**
     * Turns one record into an entry with its owner hash decoded, or returns {@code null} if the record cannot take
     * part: its owner name is not one label below the zone apex, that label is not base32hex, or the two hashes it
     * carries are not the length the algorithm produces.
     */
    private Nsec3Entry entryOf(DnsNsec3Record record, int hashAlgorithm) {
        DnsName owner = record.owner();
        if (owner.labelCount() != zone.labelCount() + 1 || !owner.parent().equals(zone)) {
            return null;
        }
        byte[] ownerHash;
        try {
            ownerHash = Base32Hex.decode(owner.label(0));
        } catch (CorruptedFrameException ignored) {
            return null;
        }
        // Equal lengths are what make the ordering comparison below a comparison of hashes rather than of strings
        // that happen to start alike.
        int length = DnsNsec3Hasher.hashLength(hashAlgorithm);
        if (ownerHash.length != length || record.nextHashedOwnerName().length != length) {
            return null;
        }
        return new Nsec3Entry(record, ownerHash);
    }

    // -----------------------------------------------------------------------------------------------------------
    // Shared
    // -----------------------------------------------------------------------------------------------------------

    /**
     * Applies the type bit tests a NODATA proof comes down to, once the record that makes it has been found.
     *
     * @param nsec {@code true} for an {@code NSEC} record, whose {@code NSEC} and {@code RRSIG} bits RFC 4035,
     *             section 5.4 requires to be ignored because the record's own existence sets them
     */
    private static Result noDataAt(DnsTypeBitmap types, DnsRecordType qtype, boolean nsec, DnsName closestEncloser) {
        if (nsec && (isType(qtype, DnsRecordType.NSEC) || isType(qtype, DnsRecordType.RRSIG))) {
            return bogus(DnssecFailureReason.DNSSEC_BOGUS);
        }
        if (types.contains(qtype)) {
            return bogus(DnssecFailureReason.DNSSEC_BOGUS);
        }
        // RFC 6840, section 4.3. Without it, stripping the CNAME RRset out of a positive CNAME answer leaves a
        // response that a validator reads as a proof the name has nothing at all of the queried type.
        if (types.contains(DnsRecordType.CNAME)) {
            return bogus(DnssecFailureReason.DNSSEC_BOGUS);
        }
        return secure(closestEncloser);
    }

    /**
     * Applies RFC 6840, section 4.4 to the record that matches a delegation name.
     */
    private static Result delegationFrom(DnsTypeBitmap types, DnsName childZone) {
        if (types.contains(DnsRecordType.SOA)) {
            // The record is the child's own apex, which has nothing to say about whether the parent published a DS.
            return bogus(DnssecFailureReason.BAILIWICK_VIOLATION);
        }
        if (!types.contains(DnsRecordType.NS)) {
            // The name exists but is not a delegation. Accepting this is how an attacker moves an ordinary signed
            // name, and the whole subtree under it, outside DNSSEC.
            return bogus(DnssecFailureReason.DNSSEC_BOGUS);
        }
        if (types.contains(DnsRecordType.DS)) {
            // A DS is published for this delegation, so it is signed and the referral is not insecure.
            return bogus(DnssecFailureReason.DNSSEC_BOGUS);
        }
        return new Result(DnssecStatus.INSECURE, DnssecFailureReason.UNSIGNED_DELEGATION, childZone, false);
    }

    /**
     * Returns the closest encloser a wildcard answer implies, after checking that {@code wildcardOwner} really is a
     * wildcard inside the zone and really could have matched {@code qname}.
     */
    private DnsName closestEncloserOfWildcard(DnsName qname, DnsName wildcardOwner) {
        if (wildcardOwner.labelCount() == 0 || !wildcardOwner.equalsOrIsSubDomainOf(zone)) {
            return null;
        }
        byte[] label = wildcardOwner.label(0);
        if (label.length != 1 || label[0] != '*') {
            return null;
        }
        DnsName closestEncloser = wildcardOwner.parent();
        // RFC 4592, section 2.2: a wildcard is the source of synthesis only for names strictly below its parent.
        return qname.isStrictSubDomainOf(closestEncloser) ? closestEncloser : null;
    }

    /**
     * Returns the longest name that is a suffix of both, which is the deepest node they share.
     */
    private static DnsName commonSuffix(DnsName left, DnsName right) {
        for (int strip = 0; strip <= left.labelCount(); strip++) {
            DnsName candidate = left.stripLeftmostLabels(strip);
            if (right.equalsOrIsSubDomainOf(candidate)) {
                return candidate;
            }
        }
        return DnsName.ROOT;
    }

    /**
     * Returns {@code *.name}, or {@code null} if that would be longer than a name may be.
     */
    private static DnsName wildcardOf(DnsName name) {
        try {
            return name.toWildcard();
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private static boolean isType(DnsRecordType type, DnsRecordType other) {
        return type.intValue() == other.intValue();
    }

    private static boolean equalSalt(byte[] left, byte[] right) {
        return left.length == right.length
                && (left.length == 0 || PlatformDependent.equalsConstantTime(left, 0, right, 0, left.length) != 0);
    }

    private static int compareHash(byte[] left, byte[] right) {
        for (int i = 0; i < left.length; i++) {
            int difference = (left[i] & 0xff) - (right[i] & 0xff);
            if (difference != 0) {
                return difference;
            }
        }
        return 0;
    }

    private static Result secure(DnsName closestEncloser) {
        return new Result(DnssecStatus.SECURE, DnssecFailureReason.NONE, closestEncloser, false);
    }

    private static Result optOut(DnsName closestEncloser) {
        return new Result(DnssecStatus.INSECURE, DnssecFailureReason.NSEC3_OPT_OUT, closestEncloser, true);
    }

    private static Result bogus(DnssecFailureReason reason) {
        return new Result(DnssecStatus.BOGUS, reason, null, false);
    }

    private enum Proof {
        NAME_ERROR,
        NO_DATA,
        WILDCARD_ANSWER,
        UNSIGNED_DELEGATION
    }

    /**
     * The verdict on one denial-of-existence proof.
     *
     * <p>{@link #status()} is what the caller acts on, and it is the authoritative field. It is decided by the
     * proof rather than read off {@link DnssecFailureReason#impliedStatus()}, so that a rule this class applies is
     * stated where the rule lives: exceeding a limit is {@link DnssecStatus#BOGUS} here because anything an
     * attacker can provoke on demand must not become a way to downgrade a zone, and that has to hold whatever a
     * shared reason code happens to say. The two agree for every reason this class produces today, which
     * {@code DnssecDenialOfExistenceTest} asserts, but a caller that switches on the reason rather than on the
     * status is reading the diagnostic and not the verdict.</p>
     */
    public static final class Result {

        private final DnssecStatus status;
        private final DnssecFailureReason reason;
        private final DnsName closestEncloser;
        private final boolean optOut;

        Result(DnssecStatus status, DnssecFailureReason reason, DnsName closestEncloser, boolean optOut) {
            this.status = status;
            this.reason = reason;
            this.closestEncloser = closestEncloser;
            this.optOut = optOut;
        }

        /**
         * Returns the security state this proof establishes.
         *
         * <p>{@link DnssecStatus#SECURE} means the proof holds. {@link DnssecStatus#INSECURE} means it does not
         * hold but the response may still be used unauthenticated, which is the outcome for a proof that rests on
         * opt-out, for an insecure delegation, and for an {@code NSEC3} iteration count above
         * {@link DnssecLimits#maxNsec3Iterations()}. {@link DnssecStatus#BOGUS} means the response must be
         * discarded.</p>
         */
        public DnssecStatus status() {
            return status;
        }

        /**
         * Returns why, {@link DnssecFailureReason#NONE} when the proof holds. Several reasons map to an
         * {@link DnssecStatus#INSECURE} that is a result rather than a failure, in particular
         * {@link DnssecFailureReason#UNSIGNED_DELEGATION} and {@link DnssecFailureReason#NSEC3_OPT_OUT}.
         */
        public DnssecFailureReason reason() {
            return reason;
        }

        /**
         * Returns the closest encloser the proof established, or {@code null} where the proof did not need one, as
         * a NODATA answer with a record matching the query name does not.
         */
        public DnsName closestEncloser() {
            return closestEncloser;
        }

        /**
         * Returns {@code true} if the proof relies on an opt-out {@code NSEC3} record, which is what keeps it from
         * being {@link DnssecStatus#SECURE}. See RFC 5155, section 9.2.
         */
        public boolean isOptOut() {
            return optOut;
        }

        /**
         * Returns {@code true} if {@link #status()} is {@link DnssecStatus#SECURE}.
         */
        public boolean isProven() {
            return status == DnssecStatus.SECURE;
        }

        @Override
        public String toString() {
            return "Result(status: " + status + ", reason: " + reason + ", closestEncloser: " + closestEncloser
                    + ", optOut: " + optOut + ')';
        }
    }

    /**
     * The result of the closest encloser proof: the encloser itself and the record that covers the "next closer"
     * name, whose Opt-Out flag decides whether the proof is authenticated.
     */
    private static final class ClosestEncloser {

        private final DnsName name;
        private final DnsNsec3Record covering;
        private final Result failure;

        ClosestEncloser(DnsName name, DnsNsec3Record covering) {
            this.name = name;
            this.covering = covering;
            failure = null;
        }

        private ClosestEncloser(Result failure) {
            name = null;
            covering = null;
            this.failure = failure;
        }

        static ClosestEncloser failed(Result failure) {
            return new ClosestEncloser(failure);
        }

        boolean optOut() {
            return covering.isOptOut();
        }
    }

    /**
     * One usable {@code NSEC3} record with the hash decoded out of its owner name.
     */
    private static final class Nsec3Entry {

        private final DnsNsec3Record record;
        private final byte[] ownerHash;

        Nsec3Entry(DnsNsec3Record record, byte[] ownerHash) {
            this.record = record;
            this.ownerHash = ownerHash;
        }
    }

    /**
     * The {@code NSEC3} records of one response that survived RFC 5155, sections 8.1 and 8.2, together with the one
     * set of parameters they all share.
     */
    private static final class Nsec3Set {

        private final List<Nsec3Entry> entries;
        private final int hashAlgorithm;
        private final int iterations;
        private final byte[] salt;
        private final Result failure;

        Nsec3Set(List<Nsec3Entry> entries, int hashAlgorithm, int iterations, byte[] salt) {
            this.entries = entries;
            this.hashAlgorithm = hashAlgorithm;
            this.iterations = iterations;
            this.salt = salt;
            failure = null;
        }

        private Nsec3Set(Result failure) {
            entries = null;
            hashAlgorithm = 0;
            iterations = 0;
            salt = null;
            this.failure = failure;
        }

        static Nsec3Set failed(Result failure) {
            return new Nsec3Set(failure);
        }
    }
}
