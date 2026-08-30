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

import io.netty.handler.codec.dns.DnsRecordType;

/**
 * Where the domain names sit inside the {@code RDATA} of one record type, and which of the two per-type sets that
 * type belongs to. The single source of truth for {@link DnssecRdataDecompressor}, which expands the compressed
 * names, and for {@link DnssecCanonicalizer}, which downcases them.
 *
 * <p>The two have to agree about every field position. If they ever disagreed, the octets a record decodes to and
 * the octets its canonical form is built from would drift apart, the signed preimage would be wrong, and the only
 * symptom would be a spurious {@link DnssecStatus#BOGUS} on a zone that is signed correctly: silent, and
 * reproducible only against a real zone. That is why the table is written down once, here, rather than once in
 * each of them.</p>
 *
 * <h3>Two sets, not one</h3>
 *
 * <p>Membership is two independent questions, answered separately by {@link #isCompressible(DnsRecordType)} and
 * {@link #downcasesNames(DnsRecordType)}:</p>
 * <ul>
 *   <li><strong>Compressible</strong> is <a href="https://www.rfc-editor.org/rfc/rfc3597.html#section-4">RFC 3597,
 *   section 4</a>: a receiver "MUST decompress domain names in RRs of well-known type", which the same section
 *   defines as the types of RFC 1035, "and SHOULD also decompress RRs of type RP, AFSDB, RT, SIG, PX, NXT, NAPTR,
 *   and SRV". {@code HINFO} is well-known but holds no domain name, so there is nothing there to expand. Every
 *   other type, known or not, is passed through untouched: RFC 3597 forbids compression in the {@code RDATA} of
 *   any other type, so an octet that looks like a compression pointer there is data, and expanding it would give
 *   two different wire encodings one canonical form, which is exactly the collision a signature must not have.</li>
 *   <li><strong>Downcased</strong> is item 3 of
 *   <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-6.2">RFC 4034, section 6.2</a>, which is the list
 *   of <a href="https://www.rfc-editor.org/rfc/rfc3597.html#section-7">RFC 3597, section 7</a> plus {@code RRSIG}
 *   and {@code NSEC}, as corrected by
 *   <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.1">RFC 6840, section 5.1</a>, which removes
 *   {@code NSEC}, and by <a href="https://www.rfc-editor.org/errata/eid1062">RFC 4034 erratum 1062</a>, which
 *   removes {@code HINFO}. The list is closed: RFC 3597, section 7 fixes the canonical form of every type
 *   published after it, so no later type is ever downcased however name-like its {@code RDATA} looks, not the
 *   {@code TargetName} of {@code SVCB} or {@code HTTPS} and not {@code TLSA}, {@code SMIMEA} or {@code CAA}.</li>
 * </ul>
 *
 * <p>The asymmetries between the two are what a future editor will get wrong, so they are spelled out:</p>
 * <ul>
 *   <li>{@code RRSIG} is downcased but never decompressed:
 *   <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-3.1.7">RFC 4034, section 3.1.7</a> forbids
 *   compressing the Signer's Name, and RFC 3597, section 4 does not list it.</li>
 *   <li>{@code NSEC} is neither: not downcased, per RFC 6840, section 5.1, and
 *   <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-4.1.1">RFC 4034, section 4.1.1</a> forbids
 *   compressing the Next Domain Name. It appears nowhere in this table.</li>
 *   <li>{@code KX}, {@code A6} and {@code DNAME} are downcased but never decompressed: they postdate RFC 1035 and
 *   RFC 3597, section 4 does not name them.</li>
 *   <li>{@code SIG} and {@code NXT}, the RFC 2535 forerunners of {@code RRSIG} and {@code NSEC}, are in both sets.
 *   RFC 3597, section 4 stops a sender compressing them but still has a receiver expand what earlier senders
 *   compressed.</li>
 *   <li>{@code HINFO} is in neither set: it holds no domain name at all, only character-strings.</li>
 * </ul>
 *
 * <p>A layout is shared by every type of the same shape, so membership cannot live on the shape alone: {@code MX},
 * {@code AFSDB} and {@code RT} are compressible while {@code KX}, laid out identically, is not. Each constant below
 * therefore carries its own membership, and {@link #downcasedOnly()} derives the non-compressible twin of a shape
 * from the compressible one so that the offsets themselves are still written down once.</p>
 */
final class DnssecRdataLayout {

    // Types whose RDATA holds a domain name in at least one of the two senses. DnsRecordType has no constants for
    // several of these, and constants are needed here anyway so that they can be used as switch labels.
    private static final int NS = 2;
    private static final int MD = 3;
    private static final int MF = 4;
    private static final int CNAME = 5;
    private static final int SOA = 6;
    private static final int MB = 7;
    private static final int MG = 8;
    private static final int MR = 9;
    private static final int PTR = 12;
    private static final int MINFO = 14;
    private static final int MX = 15;
    private static final int RP = 17;
    private static final int AFSDB = 18;
    private static final int RT = 21;
    private static final int SIG = 24;
    private static final int PX = 26;
    private static final int NXT = 30;
    private static final int SRV = 33;
    private static final int NAPTR = 35;
    private static final int KX = 36;
    private static final int A6 = 38;
    private static final int DNAME = 39;
    private static final int RRSIG = 46;

    /**
     * A tail of this length means "whatever is left, including nothing".
     */
    static final int TAIL_REST = -1;

    /**
     * A field that is not fixed but computed from the {@code RDATA} itself; only {@link #A6_LAYOUT} has any. A
     * layout holding this must never be given {@link #COMPRESSIBLE}, because the fixed walk of
     * {@link DnssecRdataDecompressor} reads {@link #prefixLength} and {@link #nameCount} as they stand.
     */
    private static final int COMPUTED = -1;

    /** A sender was allowed to compress the domain names in the {@code RDATA} of this type. */
    private static final int COMPRESSIBLE = 1;

    /** The domain names in the {@code RDATA} of this type are downcased by the canonical form. */
    private static final int DOWNCASED = 2;

    private static final int COMPRESSIBLE_AND_DOWNCASED = COMPRESSIBLE | DOWNCASED;

    /**
     * The octets of a {@code SIG} or {@code RRSIG} {@code RDATA} before the signer's name: Type Covered, Algorithm,
     * Labels, Original TTL, Signature Expiration, Signature Inception and Key Tag. See
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-3.1">RFC 4034, section 3.1</a>.
     */
    private static final int SIGNER_NAME_OFFSET = 18;

    /** A prefix length above this many bits cannot be expressed by an {@code A6} record. */
    static final int A6_MAX_PREFIX_LENGTH = 128;

    /** A bare domain name: {@code NS}, {@code CNAME}, {@code PTR} and their RFC 1035 siblings. */
    private static final DnssecRdataLayout ONE_NAME =
            new DnssecRdataLayout(0, 0, 1, 0, COMPRESSIBLE_AND_DOWNCASED);
    /** {@code MINFO} and {@code RP}: two names and nothing else. */
    private static final DnssecRdataLayout TWO_NAMES =
            new DnssecRdataLayout(0, 0, 2, 0, COMPRESSIBLE_AND_DOWNCASED);
    /** {@code MX}, {@code AFSDB} and {@code RT}: a 16-bit preference or subtype, then one name. */
    private static final DnssecRdataLayout SHORT_AND_NAME =
            new DnssecRdataLayout(2, 0, 1, 0, COMPRESSIBLE_AND_DOWNCASED);
    /** {@code SOA}, RFC 1035, section 3.3.13: two names then five 32-bit numbers. */
    private static final DnssecRdataLayout SOA_LAYOUT =
            new DnssecRdataLayout(0, 0, 2, 20, COMPRESSIBLE_AND_DOWNCASED);
    /** {@code SIG}, RFC 2535, section 4.1: the RRSIG fixed fields, the signer's name, then the signature. */
    private static final DnssecRdataLayout SIG_LAYOUT =
            new DnssecRdataLayout(SIGNER_NAME_OFFSET, 0, 1, TAIL_REST, COMPRESSIBLE_AND_DOWNCASED);
    /** {@code PX}, RFC 2163, section 4: a 16-bit preference then two names. */
    private static final DnssecRdataLayout PX_LAYOUT =
            new DnssecRdataLayout(2, 0, 2, 0, COMPRESSIBLE_AND_DOWNCASED);
    /** {@code NXT}, RFC 2535, section 5.2: the next name then a type bit map. */
    private static final DnssecRdataLayout NXT_LAYOUT =
            new DnssecRdataLayout(0, 0, 1, TAIL_REST, COMPRESSIBLE_AND_DOWNCASED);
    /** {@code SRV}, RFC 2782: priority, weight and port, then the target. */
    private static final DnssecRdataLayout SRV_LAYOUT =
            new DnssecRdataLayout(6, 0, 1, 0, COMPRESSIBLE_AND_DOWNCASED);
    /** {@code NAPTR}, RFC 2915, section 2: order and preference, three character-strings, then the replacement. */
    private static final DnssecRdataLayout NAPTR_LAYOUT =
            new DnssecRdataLayout(4, 3, 1, 0, COMPRESSIBLE_AND_DOWNCASED);

    /** {@code DNAME}, RFC 6672, section 2.1: one name, shaped like a {@code CNAME} but never compressed. */
    private static final DnssecRdataLayout DNAME_LAYOUT = ONE_NAME.downcasedOnly();
    /** {@code KX}, RFC 2230, section 3.1: shaped like an {@code MX} but never compressed. */
    private static final DnssecRdataLayout KX_LAYOUT = SHORT_AND_NAME.downcasedOnly();
    /** {@code RRSIG}, RFC 4034, section 3.1: shaped like a {@code SIG} but never compressed. */
    private static final DnssecRdataLayout RRSIG_LAYOUT = SIG_LAYOUT.downcasedOnly();
    /**
     * {@code A6}, RFC 2874, section 3.1.1: a prefix length octet, an address suffix whose width follows from it,
     * and a prefix name that is there only when the prefix length is not zero. Its fields are
     * {@link #COMPUTED}, so it is never {@link #COMPRESSIBLE}; use {@link #a6NamesStart(int)} and
     * {@link #a6NameCount(int)} to resolve it against a record.
     */
    static final DnssecRdataLayout A6_LAYOUT =
            new DnssecRdataLayout(COMPUTED, 0, COMPUTED, TAIL_REST, DOWNCASED);

    /** The fixed octets before the character-strings and names, or {@link #COMPUTED}. */
    final int prefixLength;

    /** How many character-strings sit between the fixed prefix and the names. */
    final int characterStrings;

    /** How many domain names follow the character-strings, or {@link #COMPUTED}. */
    final int nameCount;

    /** The octets after the last name, or {@link #TAIL_REST} when the type ends with whatever is left. */
    final int tailLength;

    private final int sets;

    private DnssecRdataLayout(int prefixLength, int characterStrings, int nameCount, int tailLength, int sets) {
        this.prefixLength = prefixLength;
        this.characterStrings = characterStrings;
        this.nameCount = nameCount;
        this.tailLength = tailLength;
        this.sets = sets;
    }

    /**
     * The same shape for a type that is downcased but never decompressed, so that a shape shared by both kinds of
     * type still has its offsets written down once. See the asymmetries in the class documentation.
     */
    private DnssecRdataLayout downcasedOnly() {
        return new DnssecRdataLayout(prefixLength, characterStrings, nameCount, tailLength, DOWNCASED);
    }

    /**
     * Returns {@code true} if a sender was allowed to compress the domain names in the {@code RDATA} of
     * {@code type}, so that a receiver has to expand them before the record can be put in canonical form.
     */
    static boolean isCompressible(DnsRecordType type) {
        return compressibleLayoutOf(type) != null;
    }

    /**
     * Returns {@code true} if the domain names in the {@code RDATA} of {@code type} are downcased by the canonical
     * form of RFC 4034, section 6.2 as amended. The owner name is downcased whatever the type and is not covered
     * by this.
     */
    static boolean downcasesNames(DnsRecordType type) {
        return downcasedLayoutOf(type) != null;
    }

    /**
     * The layout of {@code type} if its {@code RDATA} may hold a compressed name, {@code null} otherwise.
     */
    static DnssecRdataLayout compressibleLayoutOf(DnsRecordType type) {
        return layoutIn(type, COMPRESSIBLE);
    }

    /**
     * The layout of {@code type} if the names in its {@code RDATA} are downcased, {@code null} otherwise.
     */
    static DnssecRdataLayout downcasedLayoutOf(DnsRecordType type) {
        return layoutIn(type, DOWNCASED);
    }

    /**
     * Where the prefix name of an {@code A6} record with this prefix length starts: past the prefix length octet
     * and past the low {@code 128 - prefixLength} bits of the address, rounded up to whole octets. RFC 2874,
     * section 3.1.1.
     */
    static int a6NamesStart(int prefixLength) {
        return 1 + ((A6_MAX_PREFIX_LENGTH - prefixLength + 7) >> 3);
    }

    /**
     * How many names an {@code A6} record with this prefix length carries: one, unless the whole address is
     * present and there is nothing left to prefix it with. RFC 2874, section 3.1.1.
     */
    static int a6NameCount(int prefixLength) {
        return prefixLength > 0 ? 1 : 0;
    }

    private static DnssecRdataLayout layoutIn(DnsRecordType type, int set) {
        DnssecRdataLayout layout = layoutOf(type.intValue());
        return layout != null && (layout.sets & set) != 0 ? layout : null;
    }

    private static DnssecRdataLayout layoutOf(int type) {
        switch (type) {
        case NS:
        case MD:
        case MF:
        case CNAME:
        case MB:
        case MG:
        case MR:
        case PTR:
            return ONE_NAME;
        case SOA:
            return SOA_LAYOUT;
        case MINFO:
        case RP:
            return TWO_NAMES;
        case MX:
        case AFSDB:
        case RT:
            return SHORT_AND_NAME;
        case SIG:
            return SIG_LAYOUT;
        case PX:
            return PX_LAYOUT;
        case NXT:
            return NXT_LAYOUT;
        case SRV:
            return SRV_LAYOUT;
        case NAPTR:
            return NAPTR_LAYOUT;
        case KX:
            return KX_LAYOUT;
        case A6:
            return A6_LAYOUT;
        case DNAME:
            return DNAME_LAYOUT;
        case RRSIG:
            return RRSIG_LAYOUT;
        default:
            return null;
        }
    }
}
