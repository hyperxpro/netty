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

import io.netty.util.collection.IntObjectHashMap;
import io.netty.util.internal.ObjectUtil;

import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

/**
 * An entry of the IANA
 * <a href="https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml">Delegation Signer (DS) Resource Record
 * (RR) Type Digest Algorithms</a> registry, as it appears in the Digest Type field of a {@code DS} or {@code CDS}
 * record.
 *
 * <p>Deliberately not an {@code enum}, for the same reason as {@link DnssecAlgorithm}: an unrecognised digest type
 * must be reportable rather than fatal. A {@code DS} RRset whose every digest type is unsupported makes the
 * delegation <em>Insecure</em>, per
 * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.2">RFC 6840, Section 5.2</a>.
 *
 * <table border="1">
 * <caption>Implement for DNSSEC Validation</caption>
 * <tr><th>Value</th><th>Description</th><th>RFC 9904</th><th>Implemented</th><th>Digest length</th></tr>
 * <tr><td>0</td><td>NULL (CDS only)</td><td>MUST NOT</td><td>no</td><td>-</td></tr>
 * <tr><td>1</td><td>SHA-1</td><td>MUST</td><td>yes</td><td>20</td></tr>
 * <tr><td>2</td><td>SHA-256</td><td>MUST</td><td>yes</td><td>32</td></tr>
 * <tr><td>3</td><td>GOST R 34.11-94</td><td>MUST NOT</td><td>no</td><td>-</td></tr>
 * <tr><td>4</td><td>SHA-384</td><td>RECOMMENDED</td><td>yes</td><td>48</td></tr>
 * <tr><td>5</td><td>GOST R 34.11-2012</td><td>MAY</td><td>no</td><td>-</td></tr>
 * <tr><td>6</td><td>SM3</td><td>MAY</td><td>no</td><td>-</td></tr>
 * </table>
 *
 * <p>Digest type 3 is listed as {@code MAY} by RFC 9904, Table 3, but
 * <a href="https://www.rfc-editor.org/rfc/rfc9906.html#section-2">RFC 9906, Section 2</a> subsequently retired it and
 * IANA now records it as {@code MUST NOT} in every column.
 *
 * <p>Digest type 1 (SHA-1) remains {@code MUST} to <em>implement for validation</em> even though it is
 * {@code MUST NOT} to <em>use for delegation</em>: existing delegations still carry SHA-1 {@code DS} records and
 * refusing them would break resolution rather than improve it.
 */
public final class DnssecDigestType implements Comparable<DnssecDigestType> {

    /**
     * Reserved, and usable only in a {@code CDS} record to signal "delete DS", see
     * <a href="https://www.rfc-editor.org/rfc/rfc8078.html#section-4">RFC 8078, Section 4</a>. Never a real digest.
     */
    public static final DnssecDigestType NULL = new DnssecDigestType(0, "NULL", null, 0);

    /**
     * SHA-1, defined by <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-5.1.4">RFC 4034,
     * Section 5.1.4</a>. {@code MUST} be implemented for validation.
     */
    public static final DnssecDigestType SHA1 = new DnssecDigestType(1, "SHA-1", "SHA-1", 20);

    /**
     * SHA-256, defined by <a href="https://www.rfc-editor.org/rfc/rfc4509.html">RFC 4509</a>. {@code MUST} be
     * implemented for validation.
     */
    public static final DnssecDigestType SHA256 = new DnssecDigestType(2, "SHA-256", "SHA-256", 32);

    /**
     * GOST R 34.11-94, defined by <a href="https://www.rfc-editor.org/rfc/rfc5933.html">RFC 5933</a> and retired by
     * <a href="https://www.rfc-editor.org/rfc/rfc9906.html#section-2">RFC 9906, Section 2</a>. {@code MUST NOT} be
     * implemented for validation.
     */
    public static final DnssecDigestType GOST_R_34_11_94 = new DnssecDigestType(3, "GOST R 34.11-94", null, 0);

    /**
     * SHA-384, defined by <a href="https://www.rfc-editor.org/rfc/rfc6605.html#section-5">RFC 6605, Section 5</a>.
     * {@code RECOMMENDED} to be implemented for validation.
     */
    public static final DnssecDigestType SHA384 = new DnssecDigestType(4, "SHA-384", "SHA-384", 48);

    /**
     * GOST R 34.11-2012, defined by <a href="https://www.rfc-editor.org/rfc/rfc9558.html">RFC 9558</a>. {@code MAY}
     * be implemented for validation. Not implemented.
     */
    public static final DnssecDigestType GOST_R_34_11_2012 = new DnssecDigestType(5, "GOST R 34.11-2012", null, 0);

    /**
     * SM3, defined by <a href="https://www.rfc-editor.org/rfc/rfc9563.html">RFC 9563</a>. {@code MAY} be implemented
     * for validation. Not implemented.
     */
    public static final DnssecDigestType SM3 = new DnssecDigestType(6, "SM3", null, 0);

    private static final Map<String, DnssecDigestType> BY_NAME = new HashMap<String, DnssecDigestType>();
    private static final IntObjectHashMap<DnssecDigestType> BY_VALUE = new IntObjectHashMap<DnssecDigestType>();
    private static final String EXPECTED;

    static {
        DnssecDigestType[] all = {NULL, SHA1, SHA256, GOST_R_34_11_94, SHA384, GOST_R_34_11_2012, SM3};

        StringBuilder expected = new StringBuilder(128);
        expected.append(" (expected: ");
        for (DnssecDigestType digestType: all) {
            BY_NAME.put(digestType.name(), digestType);
            BY_VALUE.put(digestType.intValue(), digestType);

            expected.append(digestType.name())
                    .append('(')
                    .append(digestType.intValue())
                    .append("), ");
        }
        expected.setLength(expected.length() - 2);
        expected.append(')');
        EXPECTED = expected.toString();
    }

    /**
     * Returns the {@link DnssecDigestType} for the given digest type number.
     *
     * <p>Never throws for an unassigned number: it yields an unregistered instance whose {@link #name()} is
     * {@code "UNKNOWN"} and whose {@link #isSupported()} is {@code false}.
     *
     * @param intValue the 8-bit digest type as it appears on the wire.
     * @return the matching instance, never {@code null}.
     * @throws IllegalArgumentException if {@code intValue} does not fit in an unsigned octet.
     */
    public static DnssecDigestType valueOf(int intValue) {
        DnssecDigestType result = BY_VALUE.get(intValue);
        if (result == null) {
            return new DnssecDigestType(intValue, "UNKNOWN", null, 0);
        }
        return result;
    }

    /**
     * Returns the {@link DnssecDigestType} with the given IANA description.
     *
     * @param name the description, for example {@code "SHA-256"}.
     * @return the matching instance, never {@code null}.
     * @throws IllegalArgumentException if no registered digest type has that description.
     */
    public static DnssecDigestType valueOf(String name) {
        DnssecDigestType result = BY_NAME.get(ObjectUtil.checkNotNull(name, "name"));
        if (result == null) {
            throw new IllegalArgumentException("name: " + name + EXPECTED);
        }
        return result;
    }

    private final int intValue;
    private final String name;
    private final String algorithm;
    private final int digestLength;
    private final boolean supported;
    private String text;

    private DnssecDigestType(int intValue, String name, String algorithm, int digestLength) {
        if ((intValue & 0xff) != intValue) {
            throw new IllegalArgumentException("intValue: " + intValue + " (expected: 0 ~ 255)");
        }
        this.intValue = intValue;
        this.name = name;
        this.algorithm = algorithm;
        this.digestLength = digestLength;
        supported = isAvailable(algorithm);
    }

    private static boolean isAvailable(String algorithm) {
        if (algorithm == null) {
            return false;
        }
        try {
            MessageDigest.getInstance(algorithm);
            return true;
        } catch (Throwable ignored) {
            // A missing or misbehaving security provider must not prevent this class from loading.
            return false;
        }
    }

    /**
     * Returns the digest type as it appears on the wire, in the range {@code 0} to {@code 255}.
     */
    public int intValue() {
        return intValue;
    }

    /**
     * Returns the IANA description of this digest type, or {@code "UNKNOWN"} if it is not registered here.
     */
    public String name() {
        return name;
    }

    /**
     * Returns {@code true} if this digest type is implemented by this package <em>and</em> offered by the running
     * JDK.
     */
    public boolean isSupported() {
        return supported;
    }

    /**
     * Returns the JCA {@link MessageDigest} algorithm name for this digest type, or {@code null} if this package does
     * not implement it.
     */
    public String algorithm() {
        return algorithm;
    }

    /**
     * Returns the exact length in octets that the Digest field of a {@code DS} record using this digest type must
     * have, or {@code 0} if this package does not implement it.
     *
     * <p>The length is fixed by the digest algorithm, so a {@code DS} record whose Digest field is a different length
     * is malformed and must be rejected before any comparison is attempted.
     */
    public int digestLength() {
        return digestLength;
    }

    @Override
    public int hashCode() {
        return intValue;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof DnssecDigestType && ((DnssecDigestType) o).intValue == intValue;
    }

    @Override
    public int compareTo(DnssecDigestType o) {
        return intValue - o.intValue;
    }

    @Override
    public String toString() {
        String text = this.text;
        if (text == null) {
            this.text = text = name + '(' + intValue + ')';
        }
        return text;
    }
}
