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
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.util.internal.ObjectUtil;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/**
 * Builds the octets an {@code RRSIG} signature is computed over, the {@code signed_data} of
 * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.3.2">RFC 4035, Section 5.3.2</a>:
 *
 * <pre>
 * signed_data   = RRSIG_RDATA | RR(1) | RR(2) | ...
 * RRSIG_RDATA   = type_covered(2) | algorithm(1) | labels(1) | original_ttl(4)
 *               | sig_expiration(4) | sig_inception(4) | key_tag(2) | signer_name
 * RR(i)         = owner | type(2) | class(2) | original_ttl(4) | rdlength(2) | rdata
 * </pre>
 *
 * <p>with the Signature field of the {@code RRSIG} excluded, the Signer's Name downcased, the {@code RR(i)} sorted
 * into the canonical order of
 * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-6.3">RFC 4034, Section 6.3</a>, and every
 * {@code original_ttl} taken from the {@code RRSIG} rather than from the TTL the records arrived with, as
 * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-3.1.4">RFC 4034, Section 3.1.4</a> requires. A
 * received TTL has been decremented by every cache on the way and is not what the zone signed.
 *
 * <p>Item 2 of <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-6.2">RFC 4034, Section 6.2</a> downcases
 * the <em>owner</em> name of every record whatever its type. Item 3 downcases the domain names inside the
 * {@code RDATA} of a listed set of types, and that list has two published errors, both corrected by
 * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.1">RFC 6840, Section 5.1</a>:
 * <ul>
 *   <li><strong>{@code NSEC} is not downcased</strong>, although Section 6.2 lists it. {@code RRSIG} is. Getting
 *   this pair backwards is the classic canonicalisation bug and it is invisible to any test written in lower case,
 *   because both rules then produce identical octets. Its effect is signature malleability — a validator that
 *   downcases an {@code NSEC} Next Domain Name accepts a record whose octets are not the ones the zone signed, so
 *   the signature stops committing to the exact wire form — plus a spurious {@link DnssecStatus#BOGUS} on a zone
 *   that genuinely publishes mixed-case {@code NSEC} {@code RDATA}. It is not a denial-of-existence bypass: name
 *   comparison, and {@link DnsName#CANONICAL_ORDER} with it, is case-insensitive, so re-casing a Next Domain Name
 *   does not let an attacker prove a different range.</li>
 *   <li><strong>{@code HINFO} is not downcased</strong>, although Section 6.2 lists it twice. It contains no domain
 *   name at all; see <a href="https://www.rfc-editor.org/errata/eid1062">RFC 4034 erratum 1062</a>.</li>
 * </ul>
 *
 * <p>No type standardised after <a href="https://www.rfc-editor.org/rfc/rfc3597.html#section-7">RFC 3597,
 * Section 7</a> is ever downcased, so the {@code TargetName} of {@code SVCB} and {@code HTTPS}, and the contents of
 * {@code TLSA}, {@code SMIMEA} and {@code CAA}, are passed through untouched. The list is closed, not open.
 *
 * <p>Decompression is a separate question with a separate answer, and this class refuses rather than guesses:
 * {@code RDATA} holding a compression pointer is rejected with
 * {@link DnssecFailureReason#COMPRESSED_RDATA}. Expanding a pointer where compression is forbidden would let two
 * different wire encodings share one signed preimage, which is a signature-reuse primitive; and the message the
 * pointer refers to is not available here in any case. Three asymmetries are worth holding on to: {@code RRSIG} is
 * downcased but never compressed, {@code NSEC} is neither, and {@code KX}, {@code A6} and {@code DNAME} are
 * downcased but never compressed. Both sets, and the field positions they share, are held once in
 * {@link DnssecRdataLayout}, which {@link DnssecRdataDecompressor} reads as well.
 *
 * <p>{@link #signedData(ByteBufAllocator, DnsRrsigRecord, DnsRRset)} allocates one buffer per call, of exactly the
 * size the answer needs, and the caller releases it. There is deliberately no shared scratch buffer to grow or
 * shrink: Unbound's <a href="https://www.cve.org/CVERecord?id=CVE-2026-56416">CVE-2026-56416</a> was a heap
 * overflow reachable precisely because its canonicalisation walked one.
 *
 * <p>This class is stateless and thread-safe.
 */
public final class DnssecCanonicalizer {

    /**
     * The octets of an {@code RRSIG} {@code RDATA} before the Signer's Name: Type Covered, Algorithm, Labels,
     * Original TTL, Signature Expiration, Signature Inception and Key Tag. See
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-3.1">RFC 4034, Section 3.1</a>.
     */
    private static final int RRSIG_FIXED_LENGTH = 18;

    /**
     * {@code name(2) placeholder} — the fixed part of every {@code RR(i)} after the owner name: type, class,
     * original TTL and RDLENGTH.
     */
    private static final int RR_FIXED_LENGTH = 2 + 2 + 4 + 2;

    private static final int MAX_RDLENGTH = 0xffff;

    private static final Comparator<byte[]> CANONICAL_RDATA_ORDER = new CanonicalRdataOrder();

    private DnssecCanonicalizer() {
    }

    /**
     * Returns {@code true} if the domain names in the {@code RDATA} of {@code type} are downcased when the record
     * is put in canonical form, that is if {@code type} is in the RFC 4034, Section 6.2 item 3 list as corrected by
     * RFC 6840, Section 5.1.
     *
     * <p>Notably {@code false} for {@code NSEC} and {@code HINFO}, and for every type standardised after RFC 3597.
     * The owner name is downcased for every type and is not covered by this method.
     */
    static boolean downcasesRdataNames(DnsRecordType type) {
        return DnssecRdataLayout.downcasesNames(ObjectUtil.checkNotNull(type, "type"));
    }

    /**
     * Returns the number of labels an owner name has for the purpose of the {@code RRSIG} Labels field, which is
     * {@link DnsName#labelCount()} less a leading {@code *} if there is one.
     *
     * <p><a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-3.1.3">RFC 4034, Section 3.1.3</a>: the
     * Labels field "MUST NOT count either the null (root) label that terminates the owner name or the wildcard
     * label (if present)". {@link DnsName#labelCount()} already excludes the root.
     */
    public static int ownerLabelCount(DnsName owner) {
        int labels = ObjectUtil.checkNotNull(owner, "owner").labelCount();
        if (labels > 0 && isWildcardLabel(owner.label(0))) {
            labels--;
        }
        return labels;
    }

    /**
     * Returns {@code true} if {@code rrsig} says the records it covers were produced by expanding a wildcard, that
     * is if its Labels field is smaller than {@link #ownerLabelCount(DnsName)} of the owner.
     *
     * <p>A caller that gets {@code true} back has more work to do: RFC 4035, Section 5.3.4 requires it to also
     * obtain a denial-of-existence proof that the queried name itself does not exist, because otherwise a valid
     * wildcard signature could be replayed over a name the zone answers explicitly.
     */
    static boolean isWildcardExpansion(DnsRrsigRecord rrsig, DnsName owner) {
        ObjectUtil.checkNotNull(rrsig, "rrsig");
        return rrsig.labels() < ownerLabelCount(owner);
    }

    /**
     * Returns the owner name the signature was actually computed over, per the {@code name} calculation of RFC 4035,
     * Section 5.3.2: the owner itself when the {@code RRSIG} Labels field matches, and {@code *.} followed by the
     * rightmost {@code labels} labels of the owner when it is smaller, because the answer was synthesised from a
     * wildcard.
     *
     * <p>The returned name is not downcased; {@link #signedData(ByteBufAllocator, DnsRrsigRecord, DnsRRset)} does
     * that. Callers that only want to know which name was signed usually want it as it is.
     *
     * @throws IllegalArgumentException if the Labels field exceeds {@link #ownerLabelCount(DnsName)}, which RFC
     *                                  4035, Section 5.3.2 says means "the RRSIG RR did not pass the necessary
     *                                  validation checks and MUST NOT be used to authenticate this RRset".
     *                                  {@link DnssecSignatureVerifier} rejects that before reaching here.
     */
    public static DnsName signedOwner(DnsRrsigRecord rrsig, DnsName owner) {
        ObjectUtil.checkNotNull(rrsig, "rrsig");
        ObjectUtil.checkNotNull(owner, "owner");
        int labels = rrsig.labels();
        int ownerLabels = ownerLabelCount(owner);
        if (labels > ownerLabels) {
            throw new IllegalArgumentException("RRSIG labels: " + labels + " exceeds the " + ownerLabels
                    + " labels of " + owner);
        }
        if (labels == ownerLabels) {
            // RFC 4034, Section 6.2 item 4: a wildcard owner name stays in its original unexpanded form, "*" and
            // all, so there is nothing to rebuild here even when the owner is itself a wildcard.
            return owner;
        }
        return owner.stripLeftmostLabels(owner.labelCount() - labels).toWildcard();
    }

    /**
     * Writes the canonical {@code RDATA} of one record: the octets as received, with the domain names of the
     * RFC 4034, Section 6.2 item 3 types downcased and everything else left alone. Canonicalisation never changes
     * the length of {@code RDATA}.
     *
     * @param type  the type of the record the {@code RDATA} belongs to.
     * @param rdata the {@code RDATA}. Neither index is modified.
     * @param out   the buffer to append to.
     * @throws DnssecCanonicalizationException if the {@code RDATA} of a type whose names are downcased holds a
     *                                         compression pointer, a reserved label type, or a truncated name.
     */
    static void writeCanonicalRdata(DnsRecordType type, ByteBuf rdata, ByteBuf out) {
        ObjectUtil.checkNotNull(out, "out").writeBytes(canonicalRdata(type, rdata));
    }

    /**
     * Builds the {@code signed_data} of RFC 4035, Section 5.3.2 for {@code rrsig} over {@code rrset}.
     *
     * <p>This performs no validation: it does not check that the {@code RRSIG} covers the RRset, that it is in its
     * validity period or that a key exists for it. Those are {@link DnssecSignatureVerifier}'s job and it does them
     * all before calling this, so that no attacker-controlled record reaches the canonicaliser without having been
     * judged first.
     *
     * @param alloc the allocator for the returned buffer.
     * @param rrsig the signature whose preimage is wanted.
     * @param rrset the records it covers, which must not be empty.
     * @return a heap buffer holding exactly the signed octets. <strong>The caller must release it.</strong>
     * @throws IllegalArgumentException        if {@code rrset} has no records, or if the {@code RRSIG} Labels field
     *                                         exceeds the owner's label count.
     * @throws DnssecCanonicalizationException if a record's {@code RDATA} cannot be put in canonical form.
     */
    public static ByteBuf signedData(ByteBufAllocator alloc, DnsRrsigRecord rrsig, DnsRRset rrset) {
        ObjectUtil.checkNotNull(alloc, "alloc");
        ObjectUtil.checkNotNull(rrsig, "rrsig");
        ObjectUtil.checkNotNull(rrset, "rrset");

        List<DnssecRecord> records = rrset.records();
        if (records.isEmpty()) {
            throw new IllegalArgumentException("rrset: " + rrset + " (expected: at least one record)");
        }
        ByteBuf rrsigRdata = rrsig.content();
        if (rrsigRdata.readableBytes() < RRSIG_FIXED_LENGTH) {
            throw new DnssecCanonicalizationException(DnssecFailureReason.COMPRESSED_RDATA,
                    "RRSIG RDATA is " + rrsigRdata.readableBytes() + " octets, expected at least "
                            + RRSIG_FIXED_LENGTH);
        }

        // RFC 4034, Section 6.2 item 2: the owner name is downcased whatever the type. Section 5.3.2 replaces it
        // with the wildcard name when the answer was synthesised from one.
        byte[] owner = signedOwner(rrsig, rrset.owner()).toLowerCase().toWireBytes();
        // Section 5.3.2: "the Signer's Name in canonical form", so this one is downcased even though the RRSIG
        // RDATA that carries it is not otherwise rewritten here.
        byte[] signerName = rrsig.signerName().toLowerCase().toWireBytes();

        byte[][] rdata = canonicalRdata(rrset);
        int unique = sortAndDeduplicate(rdata);

        long size = (long) RRSIG_FIXED_LENGTH + signerName.length;
        for (int i = 0; i < unique; i++) {
            size += owner.length + RR_FIXED_LENGTH + rdata[i].length;
        }
        // Bounded by the RRset size, which DnsRRset.group bounds, times the 65535-octet ceiling on RDATA; a DNS
        // message cannot hold enough for this to overflow, and the cast is checked rather than assumed.
        if (size > Integer.MAX_VALUE) {
            throw new DnssecCanonicalizationException(DnssecFailureReason.COMPRESSED_RDATA,
                    "the signed data of " + rrset + " would be " + size + " octets");
        }

        int capacity = (int) size;
        // A fixed capacity: the buffer is sized from the records themselves and must not be able to grow, so a
        // miscounted field shows up here as an exception rather than as a silently reallocated buffer.
        ByteBuf out = alloc.heapBuffer(capacity, capacity);
        boolean success = false;
        try {
            rrsigRdata.getBytes(rrsigRdata.readerIndex(), out, RRSIG_FIXED_LENGTH);
            out.writeBytes(signerName);
            for (int i = 0; i < unique; i++) {
                out.writeBytes(owner);
                out.writeShort(rrset.type().intValue());
                out.writeShort(rrset.dnsClass());
                out.writeInt((int) rrsig.originalTtl());
                out.writeShort(rdata[i].length);
                out.writeBytes(rdata[i]);
            }
            success = true;
            return out;
        } finally {
            if (!success) {
                out.release();
            }
        }
    }

    private static byte[][] canonicalRdata(DnsRRset rrset) {
        List<DnssecRecord> records = rrset.records();
        byte[][] rdata = new byte[records.size()][];
        for (int i = 0; i < rdata.length; i++) {
            rdata[i] = canonicalRdata(rrset.type(), records.get(i).content());
        }
        return rdata;
    }

    /**
     * Sorts {@code rdata} into the canonical order of RFC 4034, Section 6.3 and moves the distinct values to the
     * front, returning how many there are. The section requires both: duplicates are a protocol error that an
     * implementation may handle "in the spirit of the robustness principle", in which case it "MUST remove all but
     * one".
     */
    private static int sortAndDeduplicate(byte[][] rdata) {
        Arrays.sort(rdata, CANONICAL_RDATA_ORDER);
        int unique = 0;
        for (int i = 0; i < rdata.length; i++) {
            if (unique == 0 || !Arrays.equals(rdata[unique - 1], rdata[i])) {
                rdata[unique++] = rdata[i];
            }
        }
        return unique;
    }

    private static byte[] canonicalRdata(DnsRecordType type, ByteBuf rdata) {
        ObjectUtil.checkNotNull(type, "type");
        ObjectUtil.checkNotNull(rdata, "rdata");
        int length = rdata.readableBytes();
        if (length > MAX_RDLENGTH) {
            throw new DnssecCanonicalizationException(DnssecFailureReason.COMPRESSED_RDATA,
                    type + " record has " + length + " octets of RDATA, which cannot be expressed in the "
                            + "16-bit RDLENGTH the signed data carries");
        }
        byte[] canonical = new byte[length];
        rdata.getBytes(rdata.readerIndex(), canonical);
        // Downcasing rewrites octets in place and never changes the length, which is what lets the buffer above be
        // sized from the received RDATA.
        downcaseRdataNames(type, canonical);
        return canonical;
    }

    private static void downcaseRdataNames(DnsRecordType type, byte[] rdata) {
        DnssecRdataLayout layout = DnssecRdataLayout.downcasedLayoutOf(type);
        if (layout == null) {
            return;
        }
        int pos;
        int names;
        if (layout == DnssecRdataLayout.A6_LAYOUT) {
            // RFC 2874, Section 3.1.1, in DnssecRdataLayout: a prefix length octet, the low (128 - prefixLength)
            // bits of the address rounded up to whole octets, and a prefix name only when the length is not 0.
            if (rdata.length < 1) {
                throw truncated(type, "prefix length");
            }
            int prefixLength = rdata[0] & 0xff;
            if (prefixLength > DnssecRdataLayout.A6_MAX_PREFIX_LENGTH) {
                throw new DnssecCanonicalizationException(DnssecFailureReason.COMPRESSED_RDATA,
                        type + " record has a prefix length of " + prefixLength + ", expected 0 to "
                                + DnssecRdataLayout.A6_MAX_PREFIX_LENGTH);
            }
            pos = DnssecRdataLayout.a6NamesStart(prefixLength);
            if (pos > rdata.length) {
                throw truncated(type, "address suffix");
            }
            names = DnssecRdataLayout.a6NameCount(prefixLength);
        } else {
            pos = layout.prefixLength;
            names = layout.nameCount;
            if (pos > rdata.length) {
                throw truncated(type, "fixed fields");
            }
            for (int i = 0; i < layout.characterStrings; i++) {
                if (pos >= rdata.length) {
                    throw truncated(type, "character string");
                }
                pos += 1 + (rdata[pos] & 0xff);
                if (pos > rdata.length) {
                    throw truncated(type, "character string");
                }
            }
        }
        for (int i = 0; i < names; i++) {
            pos = downcaseName(type, rdata, pos);
        }
    }

    /**
     * Downcases the {@code A} to {@code Z} octets of the labels of the name at {@code offset}, in place, and
     * returns the offset just past its terminating zero octet.
     */
    private static int downcaseName(DnsRecordType type, byte[] rdata, int offset) {
        int pos = offset;
        for (;;) {
            if (pos >= rdata.length) {
                throw truncated(type, "embedded domain name");
            }
            int labelLength = rdata[pos] & 0xff;
            int labelType = labelLength & 0xc0;
            if (labelType == 0xc0) {
                throw new DnssecCanonicalizationException(DnssecFailureReason.COMPRESSED_RDATA,
                        type + " record has a compressed domain name at offset " + pos + " of its RDATA; "
                                + "canonical form requires every name fully expanded, and expanding it here would "
                                + "let two wire encodings share one signed preimage");
            }
            if (labelType != 0) {
                throw new DnssecCanonicalizationException(DnssecFailureReason.COMPRESSED_RDATA,
                        type + " record has a reserved label type 0x" + Integer.toHexString(labelType)
                                + " at offset " + pos + " of its RDATA");
            }
            pos++;
            if (labelLength == 0) {
                return pos;
            }
            int end = pos + labelLength;
            if (end > rdata.length) {
                throw truncated(type, "embedded domain name");
            }
            for (; pos < end; pos++) {
                byte octet = rdata[pos];
                // The fixed 26-letter mapping of RFC 4034, Section 6.2, not String.toLowerCase: signatures are
                // computed over these octets, so the mapping must not vary with the default locale.
                if (octet >= 'A' && octet <= 'Z') {
                    rdata[pos] = (byte) (octet + ('a' - 'A'));
                }
            }
        }
    }

    private static DnssecCanonicalizationException truncated(DnsRecordType type, String field) {
        return new DnssecCanonicalizationException(DnssecFailureReason.COMPRESSED_RDATA,
                type + " record is truncated in its " + field + ", so its canonical form is not defined");
    }

    private static boolean isWildcardLabel(byte[] label) {
        return label.length == 1 && label[0] == '*';
    }

    /**
     * Orders {@code RDATA} as RFC 4034, Section 6.3 does: "a left-justified unsigned octet sequence in which the
     * absence of an octet sorts before a zero octet", so a prefix sorts before what extends it.
     */
    private static final class CanonicalRdataOrder implements Comparator<byte[]> {

        @Override
        public int compare(byte[] left, byte[] right) {
            int shared = Math.min(left.length, right.length);
            for (int i = 0; i < shared; i++) {
                int difference = (left[i] & 0xff) - (right[i] & 0xff);
                if (difference != 0) {
                    return difference;
                }
            }
            return left.length - right.length;
        }
    }
}
