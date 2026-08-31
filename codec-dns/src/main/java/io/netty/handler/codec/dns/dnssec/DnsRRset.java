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

import io.netty.buffer.ByteBufUtil;
import io.netty.handler.codec.dns.DnsMessage;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.handler.codec.dns.DnsSection;
import io.netty.util.internal.ObjectUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The records of one RRset, that is every record in a message that shares an owner name, class and type, together
 * with the {@code RRSIG}s that claim to cover them.
 *
 * <p>The RRset, not the individual record, is the unit DNSSEC signs and therefore the unit a validator works with,
 * see <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.3">RFC 4035, Section 5.3</a>. Grouping a
 * section into RRsets is consequently the first thing a validator does, and it is not merely bookkeeping: a
 * signature is computed over <em>all</em> the members of the set, so a validator that silently loses one, or that
 * merges two sets that the zone signed separately, gets a different preimage and a wrong answer.
 *
 * <p><a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-6.3">RFC 4034, Section 6.3</a> requires duplicate
 * records to be removed before the canonical form of the RRset is computed, since a repeated record would be fed
 * into the signature twice. This class does that, comparing the {@code RDATA} octets with
 * {@link ByteBufUtil#equals(io.netty.buffer.ByteBuf, io.netty.buffer.ByteBuf)}.
 *
 * <p>It has to be done that way. {@code equals} and {@code hashCode} on these records come from
 * {@link io.netty.handler.codec.dns.AbstractDnsRecord}, which compares the name, type, class and TTL and
 * <strong>not</strong> the {@code RDATA} — so every member of an RRset is {@code equals} to every other member by
 * construction. Removing duplicates by putting the records in a {@link java.util.Set}, or with
 * {@code List.contains}, therefore collapses a five-key {@code DNSKEY} RRset to one key, and the RRset then fails
 * to validate against its own signature. Nothing about that failure points at the cause.
 *
 * <p>The constructor does not verify that every record really does share the owner name, class and type it is
 * filed under. {@link #group(DnsMessage, DnsSection, DnssecLimits)} cannot produce a mixed set, because those three
 * fields are its grouping key, but a hand-assembled one can be mixed, and
 * {@link DnssecSignatureVerifier} checks for that as a validation rule rather than an argument error: a mixed set
 * arriving from the network has to become {@link DnssecStatus#BOGUS}, which an {@link IllegalArgumentException}
 * thrown from a constructor is not.
 *
 * <p>Neither this class nor {@link #group(DnsMessage, DnsSection, DnssecLimits)} retains or releases any record.
 * The records belong to the message they were decoded from and stay valid for as long as it does.
 *
 * <p>Instances are immutable, in the sense that the lists cannot be changed after construction; the records they
 * hold are reference-counted objects owned by someone else.
 */
public final class DnsRRset {

    private final DnsName owner;
    private final DnsRecordType type;
    private final int dnsClass;
    private final List<DnssecRecord> records;
    private final List<DnsRrsigRecord> signatures;

    /**
     * Creates an RRset.
     *
     * @param owner      the owner name of every record, in wire form.
     * @param type       the type of every record. Must not be {@code RRSIG}; the {@code RRSIG}s that cover an
     *                   RRset go in {@code signatures}, not in {@code records}.
     * @param dnsClass   the class of every record, normally {@link DnsRecord#CLASS_IN}.
     * @param records    the members of the set. Duplicate {@code RDATA} is removed, per RFC 4034, Section 6.3.
     * @param signatures the {@code RRSIG}s that claim to cover the set. May be empty; whether any of them actually
     *                   does is {@link DnssecSignatureVerifier}'s decision, not this constructor's.
     * @throws IllegalArgumentException if {@code type} is {@code RRSIG}.
     */
    public DnsRRset(DnsName owner, DnsRecordType type, int dnsClass,
                    List<? extends DnssecRecord> records, List<? extends DnsRrsigRecord> signatures) {
        this.owner = ObjectUtil.checkNotNull(owner, "owner");
        this.type = ObjectUtil.checkNotNull(type, "type");
        ObjectUtil.checkNotNull(records, "records");
        ObjectUtil.checkNotNull(signatures, "signatures");
        if (type.intValue() == DnsRecordType.RRSIG.intValue()) {
            throw new IllegalArgumentException(
                    "type: RRSIG (an RRSIG covering an RRset belongs in signatures, not in records)");
        }
        this.dnsClass = dnsClass;
        this.records = Collections.unmodifiableList(deduplicate(records));
        List<DnsRrsigRecord> copy = new ArrayList<DnsRrsigRecord>(signatures.size());
        for (int i = 0; i < signatures.size(); i++) {
            copy.add(ObjectUtil.checkNotNull(signatures.get(i), "signatures[" + i + ']'));
        }
        this.signatures = Collections.unmodifiableList(copy);
    }

    /**
     * Splits one section of {@code message} into RRsets.
     *
     * <p>{@code RRSIG} records are not returned as RRsets of their own. Each is attached to the set it names in its
     * Type Covered field, matched on owner name, class and covered type; one that covers a type with no records in
     * the section is dropped, because there is nothing there for it to authenticate. {@code OPT} is skipped
     * entirely: <a href="https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1.1">RFC 6891, Section 6.1.1</a>
     * makes it a per-message pseudo-record that belongs to no zone and is never signed.
     *
     * <p>Only {@link DnsSection#ANSWER} and {@link DnsSection#AUTHORITY} should be fed to a validator.
     * {@link DnsSection#ADDITIONAL} is not authenticated data: treating it as though it were is the shape of
     * <a href="https://www.cve.org/CVERecord?id=CVE-2025-11411">CVE-2025-11411</a>, where records promiscuously
     * added to a response were allowed to influence the outcome.
     *
     * @param message the message to read. Not modified, not retained.
     * @param section the section to group.
     * @param limits  bounds the work: the section may hold at most {@link DnssecLimits#maxRecordsPerSection()}
     *                records, a {@code DNSKEY} RRset at most {@link DnssecLimits#maxDnskeysPerRrset()} and a
     *                {@code DS} RRset at most {@link DnssecLimits#maxDsRecordsPerRrset()}.
     * @return the RRsets, in the order their first member appears in the section.
     * @throws DnssecLimitExceededException      if a limit is exceeded.
     * @throws DnssecCanonicalizationException   if a record does not carry its owner name in wire form, that is if
     *                                           it is not a {@link DnssecRecord}, which normally means the pipeline
     *                                           is not using {@link DnssecDnsRecordDecoder}.
     */
    public static List<DnsRRset> group(DnsMessage message, DnsSection section, DnssecLimits limits) {
        ObjectUtil.checkNotNull(message, "message");
        ObjectUtil.checkNotNull(section, "section");
        ObjectUtil.checkNotNull(limits, "limits");

        int count = message.count(section);
        if (count > limits.maxRecordsPerSection()) {
            throw new DnssecLimitExceededException("maxRecordsPerSection", limits.maxRecordsPerSection());
        }

        List<Group> groups = new ArrayList<Group>();
        List<DnsRrsigRecord> signatures = new ArrayList<DnsRrsigRecord>();
        for (int i = 0; i < count; i++) {
            DnsRecord record = message.recordAt(section, i);
            if (record.type().intValue() == DnsRecordType.OPT.intValue()) {
                continue;
            }
            if (record.type().intValue() == DnsRecordType.RRSIG.intValue()) {
                if (!(record instanceof DnsRrsigRecord)) {
                    throw new DnssecCanonicalizationException(DnssecFailureReason.NAME_NOT_REPRESENTABLE,
                            "record " + i + " of the " + section + " section has type RRSIG but is a "
                                    + record.getClass().getName() + ", whose RDATA has not been parsed; decode "
                                    + "with DnssecDnsRecordDecoder");
                }
                signatures.add((DnsRrsigRecord) record);
                continue;
            }
            if (!(record instanceof DnssecRecord)) {
                throw new DnssecCanonicalizationException(DnssecFailureReason.NAME_NOT_REPRESENTABLE,
                        "record " + i + " of the " + section + " section is a " + record.getClass().getName()
                                + " and does not carry its owner name in wire form, so nothing signed over it can "
                                + "be reconstructed; decode with DnssecDnsRecordDecoder");
            }
            DnssecRecord dnssecRecord = (DnssecRecord) record;
            find(groups, dnssecRecord.owner(), record.type(), record.dnsClass(), true).records.add(dnssecRecord);
        }

        for (int i = 0; i < signatures.size(); i++) {
            DnsRrsigRecord rrsig = signatures.get(i);
            Group group = find(groups, rrsig.owner(), rrsig.typeCovered(), rrsig.dnsClass(), false);
            if (group != null) {
                group.signatures.add(rrsig);
            }
        }

        List<DnsRRset> rrsets = new ArrayList<DnsRRset>(groups.size());
        for (int i = 0; i < groups.size(); i++) {
            Group group = groups.get(i);
            checkTypeSpecificLimit(group, limits);
            rrsets.add(new DnsRRset(group.owner, group.type, group.dnsClass, group.records, group.signatures));
        }
        return rrsets;
    }

    /**
     * Returns the owner name every record in this set has, in wire form.
     *
     * <p>This is the name signature verification uses, downcased and, where the {@code RRSIG} says the answer came
     * from a wildcard, replaced by the wildcard name. It is never derived from {@link DnsRecord#name()}.
     */
    public DnsName owner() {
        return owner;
    }

    /**
     * Returns the type every record in this set has.
     */
    public DnsRecordType type() {
        return type;
    }

    /**
     * Returns the class every record in this set has, normally {@link DnsRecord#CLASS_IN}.
     */
    public int dnsClass() {
        return dnsClass;
    }

    /**
     * Returns the members of the set, with duplicate {@code RDATA} already removed, in the order they arrived.
     *
     * <p>This is <em>not</em> the order they are signed in: RFC 4034, Section 6.3 sorts an RRset by the
     * {@code RDATA} of its canonical form, which {@link DnssecCanonicalizer} does while it builds the signed data.
     * Sorting is left there rather than done here because canonicalising {@code RDATA} can fail, and grouping a
     * message must not: one unusable record would otherwise take the whole section with it.
     *
     * @return an unmodifiable list, never {@code null}.
     */
    public List<DnssecRecord> records() {
        return records;
    }

    /**
     * Returns the {@code RRSIG}s that name this set in their Type Covered field, in the order they arrived. Whether
     * any of them is valid is {@link DnssecSignatureVerifier}'s decision.
     *
     * @return an unmodifiable list, never {@code null}.
     */
    public List<DnsRrsigRecord> signatures() {
        return signatures;
    }

    /**
     * Returns how many records the set has after duplicate elimination.
     */
    public int size() {
        return records.size();
    }

    @Override
    public String toString() {
        return "DnsRRset(" + owner + ' ' + type + " class " + dnsClass + ", " + records.size() + " record(s), "
                + signatures.size() + " RRSIG(s))";
    }

    private static void checkTypeSpecificLimit(Group group, DnssecLimits limits) {
        int value = group.type.intValue();
        if (value == DnsRecordType.DNSKEY.intValue() || value == DnsRecordType.CDNSKEY.intValue()) {
            if (group.records.size() > limits.maxDnskeysPerRrset()) {
                throw new DnssecLimitExceededException("maxDnskeysPerRrset", limits.maxDnskeysPerRrset());
            }
        } else if (value == DnsRecordType.DS.intValue() || value == DnsRecordType.CDS.intValue()) {
            if (group.records.size() > limits.maxDsRecordsPerRrset()) {
                throw new DnssecLimitExceededException("maxDsRecordsPerRrset", limits.maxDsRecordsPerRrset());
            }
        }
    }

    private static Group find(List<Group> groups, DnsName owner, DnsRecordType type, int dnsClass, boolean create) {
        for (int i = 0; i < groups.size(); i++) {
            Group group = groups.get(i);
            // DnsName.equals is case-insensitive, which is what RFC 4034, Section 6.1 requires of name comparison,
            // so "A.EXAMPLE." and "a.example." land in one RRset rather than in two that each fail to validate.
            if (group.type.intValue() == type.intValue() && group.dnsClass == dnsClass
                    && group.owner.equals(owner)) {
                return group;
            }
        }
        if (!create) {
            return null;
        }
        Group group = new Group(owner, type, dnsClass);
        groups.add(group);
        return group;
    }

    /**
     * Removes records whose {@code RDATA} octets repeat one already seen, keeping the first.
     *
     * <p>Quadratic on purpose. The number of records is bounded by
     * {@link DnssecLimits#maxRecordsPerSection()} and the total {@code RDATA} of a message is bounded by the
     * message itself, so the octets compared are bounded by that product and there is nothing here for an attacker
     * to inflate. A hash-based index would trade that for a collision the same attacker chooses.
     */
    private static List<DnssecRecord> deduplicate(List<? extends DnssecRecord> records) {
        List<DnssecRecord> unique = new ArrayList<DnssecRecord>(records.size());
        for (int i = 0; i < records.size(); i++) {
            DnssecRecord record = ObjectUtil.checkNotNull(records.get(i), "records[" + i + ']');
            boolean duplicate = false;
            for (int j = 0; j < unique.size(); j++) {
                if (ByteBufUtil.equals(unique.get(j).content(), record.content())) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                unique.add(record);
            }
        }
        return unique;
    }

    private static final class Group {

        final DnsName owner;
        final DnsRecordType type;
        final int dnsClass;
        final List<DnssecRecord> records = new ArrayList<DnssecRecord>();
        final List<DnsRrsigRecord> signatures = new ArrayList<DnsRrsigRecord>();

        Group(DnsName owner, DnsRecordType type, int dnsClass) {
            this.owner = owner;
            this.type = type;
            this.dnsClass = dnsClass;
        }
    }
}
