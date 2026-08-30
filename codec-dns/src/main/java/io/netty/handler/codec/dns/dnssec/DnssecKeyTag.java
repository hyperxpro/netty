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
 * Computes the key tag of a {@code DNSKEY} record, as defined by
 * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#appendix-B">RFC 4034, Appendix B</a>.
 *
 * <h3>The key tag is only a hint</h3>
 *
 * <p>RFC 4034, Appendix B is explicit: <em>"Implementations MUST NOT assume that the key tag uniquely identifies a
 * DNSKEY RR."</em> It is a 16-bit checksum, and two distinct keys with the same owner name and algorithm can share
 * one. It exists to narrow a candidate set, never to select a key.</p>
 *
 * <p>This is not a theoretical caveat. It is the root cause of
 * <a href="https://nvd.nist.gov/vuln/detail/CVE-2023-50387">CVE-2023-50387</a> ("KeyTrap"), in which an attacker
 * publishes many colliding {@code DNSKEY} records, or many {@code RRSIG} records bearing the same key tag, so that a
 * resolver which tries every candidate performs a quadratic number of signature verifications and stalls. A caller
 * must therefore treat the value returned here as a filter, cap the number of candidate keys and candidate
 * signatures it is willing to try, and give up rather than iterate.</p>
 *
 * <h3>Errata</h3>
 *
 * <p>The prose of Appendix B says the two-octet groups are added "ignoring any carry bits", which contradicts the
 * reference C implementation printed immediately below it and is wrong. Verified
 * <a href="https://www.rfc-editor.org/errata/eid4552">Errata 4552</a> corrects it: the groups are added with at
 * least 32-bit precision <em>retaining</em> the carries, the carries are then folded back in once, and only the low
 * 16 bits of that result are the key tag. This class implements the corrected algorithm, which is also what the
 * reference code does.</p>
 *
 * <p>The algorithm-1 special case of RFC 4034, Appendix B.1 is deliberately <strong>not</strong> implemented.
 * Algorithm 1 (RSAMD5) is {@code MUST NOT} implement for validation, so a key tag for it would have no use; and the
 * text defining it is itself wrong, naming the fourth-to-last and third-to-last octets of the modulus where
 * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.5">RFC 6840, Section 5.5</a> and verified
 * <a href="https://www.rfc-editor.org/errata/eid193">Errata 193</a> say it is the third-to-last and second-to-last.
 * Rather than implement a retired algorithm from corrected text, algorithm 1 is rejected.</p>
 */
public final class DnssecKeyTag {

    /**
     * The fixed part of a {@code DNSKEY} RDATA: {@code flags} (2 octets), {@code protocol} (1) and
     * {@code algorithm} (1). See <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-2.1">RFC 4034,
     * Section 2.1</a>.
     */
    private static final int RDATA_HEADER_LENGTH = 4;

    private static final int ALGORITHM_OFFSET = 3;

    private DnssecKeyTag() {
    }

    /**
     * Computes the key tag over a complete {@code DNSKEY} RDATA.
     *
     * <p>The input is the whole RDATA, {@code flags || protocol || algorithm || publicKey}, exactly as it appeared on
     * the wire. Only the length and the algorithm octet are inspected; the public key is folded in as opaque octets,
     * because the key tag is defined over the encoding rather than over the key, and validating the key is
     * {@link DnssecPublicKeys}' job.</p>
     *
     * @param rdata the {@code DNSKEY} RDATA. Never modified.
     * @return the key tag, in the range {@code 0} to {@code 65535}.
     * @throws DnssecMalformedDataException        if {@code rdata} is shorter than the four-octet fixed header.
     * @throws DnssecUnsupportedAlgorithmException if the algorithm is 1 (RSAMD5), whose key tag is defined
     *                                             differently and is not implemented.
     */
    public static int compute(byte[] rdata) {
        ObjectUtil.checkNotNull(rdata, "rdata");
        if (rdata.length < RDATA_HEADER_LENGTH) {
            throw new DnssecMalformedDataException(
                    "DNSKEY RDATA is " + rdata.length + " octets, expected at least " + RDATA_HEADER_LENGTH);
        }
        checkAlgorithm(rdata[ALGORITHM_OFFSET] & 0xff);

        long ac = 0;
        for (int i = 0; i < rdata.length; i++) {
            ac += (i & 1) == 0 ? (long) (rdata[i] & 0xff) << 8 : rdata[i] & 0xff;
        }
        return fold(ac);
    }

    /**
     * Computes the key tag from the individual {@code DNSKEY} RDATA fields, without assembling the RDATA first.
     *
     * <p>Equivalent to {@link #compute(byte[])} over
     * {@code flags || protocol || algorithm || publicKey}, and provided because hand-assembling that concatenation
     * at every call site is both wasteful and a place to get the field widths wrong.</p>
     *
     * @param flags     the 16-bit {@code DNSKEY} Flags field.
     * @param protocol  the 8-bit {@code DNSKEY} Protocol field, which RFC 4034, Section 2.1.2 requires to be 3.
     * @param algorithm the {@code DNSKEY} Algorithm field.
     * @param publicKey the {@code DNSKEY} Public Key field. Never modified.
     * @return the key tag, in the range {@code 0} to {@code 65535}.
     * @throws IllegalArgumentException            if {@code flags} or {@code protocol} does not fit its field.
     * @throws DnssecUnsupportedAlgorithmException if the algorithm is 1 (RSAMD5).
     */
    public static int compute(int flags, int protocol, DnssecAlgorithm algorithm, byte[] publicKey) {
        if ((flags & 0xffff) != flags) {
            throw new IllegalArgumentException("flags: " + flags + " (expected: 0 ~ 65535)");
        }
        if ((protocol & 0xff) != protocol) {
            throw new IllegalArgumentException("protocol: " + protocol + " (expected: 0 ~ 255)");
        }
        ObjectUtil.checkNotNull(algorithm, "algorithm");
        ObjectUtil.checkNotNull(publicKey, "publicKey");
        checkAlgorithm(algorithm.intValue());

        // flags occupies RDATA octets 0 and 1, so it contributes its value unchanged; protocol is at octet 2, which
        // is even and therefore shifted; algorithm is at octet 3, which is odd. The public key starts at octet 4,
        // so its own indices have the same parity as the RDATA offsets they occupy.
        long ac = flags + ((long) protocol << 8) + algorithm.intValue();
        for (int i = 0; i < publicKey.length; i++) {
            ac += (i & 1) == 0 ? (long) (publicKey[i] & 0xff) << 8 : publicKey[i] & 0xff;
        }
        return fold(ac);
    }

    private static void checkAlgorithm(int algorithm) {
        if (algorithm == DnssecAlgorithm.RSAMD5.intValue()) {
            throw new DnssecUnsupportedAlgorithmException(
                    "key tag for " + DnssecAlgorithm.RSAMD5 + " is not implemented, see RFC 6840 section 5.5");
        }
    }

    /**
     * Applies Errata 4552: the carries accumulated above 16 bits are added back in once, and only the low 16 bits of
     * that are the key tag. Any carry produced by that final addition is discarded, which is why this is not simply
     * a reduction modulo 65535.
     */
    private static int fold(long ac) {
        ac += (ac >>> 16) & 0xffff;
        return (int) (ac & 0xffff);
    }
}
