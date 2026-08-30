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

import java.security.KeyFactory;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

/**
 * An entry of the IANA
 * <a href="https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml">DNS Security Algorithm
 * Numbers</a> registry, as it appears in the Algorithm field of a {@code DNSKEY}, {@code RRSIG} or {@code DS} record.
 *
 * <p>Deliberately not an {@code enum}: an algorithm number this implementation has never heard of must still flow
 * through the stack so that a validator can report the zone as <em>Insecure</em> rather than fail. {@link
 * #valueOf(int)} therefore returns an unregistered, unsupported instance for such numbers instead of throwing.</p>
 *
 * <h3>Which algorithms are supported</h3>
 *
 * <p><a href="https://www.rfc-editor.org/rfc/rfc9904.html">RFC 9904</a> obsoleted RFC 8624 and moved the
 * requirement levels into the registry itself. The algorithms marked {@code MUST} or {@code RECOMMENDED} in the
 * "Implement for DNSSEC Validation" column of RFC 9904, Table 2 are implemented here:</p>
 *
 * <table border="1">
 * <caption>Implement for DNSSEC Validation</caption>
 * <tr><th>Number</th><th>Mnemonic</th><th>RFC 9904</th><th>Implemented</th></tr>
 * <tr><td>1</td><td>RSAMD5</td><td>MUST NOT</td><td>no</td></tr>
 * <tr><td>3</td><td>DSA</td><td>MUST NOT</td><td>no</td></tr>
 * <tr><td>5</td><td>RSASHA1</td><td>MUST</td><td>yes</td></tr>
 * <tr><td>6</td><td>DSA-NSEC3-SHA1</td><td>MUST NOT</td><td>no</td></tr>
 * <tr><td>7</td><td>RSASHA1-NSEC3-SHA1</td><td>MUST</td><td>yes</td></tr>
 * <tr><td>8</td><td>RSASHA256</td><td>MUST</td><td>yes</td></tr>
 * <tr><td>10</td><td>RSASHA512</td><td>MUST</td><td>yes</td></tr>
 * <tr><td>12</td><td>ECC-GOST</td><td>MUST NOT</td><td>no</td></tr>
 * <tr><td>13</td><td>ECDSAP256SHA256</td><td>MUST</td><td>yes</td></tr>
 * <tr><td>14</td><td>ECDSAP384SHA384</td><td>RECOMMENDED</td><td>yes</td></tr>
 * <tr><td>15</td><td>ED25519</td><td>RECOMMENDED</td><td>yes</td></tr>
 * <tr><td>16</td><td>ED448</td><td>RECOMMENDED</td><td>yes</td></tr>
 * <tr><td>17</td><td>SM2SM3</td><td>MAY</td><td>no</td></tr>
 * <tr><td>23</td><td>ECC-GOST12</td><td>MAY</td><td>no</td></tr>
 * <tr><td>253</td><td>PRIVATEDNS</td><td>MAY</td><td>no</td></tr>
 * <tr><td>254</td><td>PRIVATEOID</td><td>MAY</td><td>no</td></tr>
 * </table>
 *
 * <p>Algorithm 12 (ECC-GOST) is listed as {@code MAY} by RFC 9904, Table 2, but
 * <a href="https://www.rfc-editor.org/rfc/rfc9906.html#section-2">RFC 9906, Section 2</a> subsequently retired it and
 * IANA now records it as {@code MUST NOT} in every column.</p>
 *
 * <p>Algorithms 253 and 254 are private-use. They carry no interoperable meaning, and
 * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.3">RFC 6840, Section 5.3</a> explicitly permits a
 * validator that supports no private algorithm to treat such a zone as unsigned, so they are reported as
 * unsupported.</p>
 *
 * <p>{@link #isSupported()} is stricter than "listed above": it also requires the running JDK to offer the algorithm.
 * {@code Ed25519} and {@code Ed448} were only added to the JDK in Java 15, so on an older runtime
 * {@link #ED25519} and {@link #ED448} report {@code false}.</p>
 */
public final class DnssecAlgorithm implements Comparable<DnssecAlgorithm> {

    private static final int FAMILY_OTHER = 0;
    private static final int FAMILY_RSA = 1;
    private static final int FAMILY_ECDSA = 2;
    private static final int FAMILY_EDDSA = 3;

    /**
     * RSA/MD5. Defined by <a href="https://www.rfc-editor.org/rfc/rfc2537.html">RFC 2537</a>, {@code MUST NOT} be
     * implemented for validation. MD5 is not collision resistant, and this is also the only algorithm with a
     * special-cased key tag ({@code RFC 4034}, Appendix B.1), which is not implemented either.
     */
    public static final DnssecAlgorithm RSAMD5 = new DnssecAlgorithm(1, "RSAMD5", null, null, FAMILY_RSA);

    /**
     * DSA/SHA-1. Defined by <a href="https://www.rfc-editor.org/rfc/rfc2536.html">RFC 2536</a>, {@code MUST NOT} be
     * implemented for validation.
     */
    public static final DnssecAlgorithm DSA = new DnssecAlgorithm(3, "DSA", null, null, FAMILY_OTHER);

    /**
     * RSA/SHA-1. Defined by <a href="https://www.rfc-editor.org/rfc/rfc3110.html">RFC 3110</a>, {@code MUST} be
     * implemented for validation.
     */
    public static final DnssecAlgorithm RSASHA1 =
            new DnssecAlgorithm(5, "RSASHA1", "SHA1withRSA", "RSA", FAMILY_RSA);

    /**
     * DSA/SHA-1 with NSEC3 support. Defined by <a href="https://www.rfc-editor.org/rfc/rfc5155.html">RFC 5155</a>,
     * {@code MUST NOT} be implemented for validation.
     */
    public static final DnssecAlgorithm DSA_NSEC3_SHA1 =
            new DnssecAlgorithm(6, "DSA-NSEC3-SHA1", null, null, FAMILY_OTHER);

    /**
     * RSA/SHA-1 with NSEC3 support. Defined by <a href="https://www.rfc-editor.org/rfc/rfc5155.html">RFC 5155</a>,
     * {@code MUST} be implemented for validation. The key and signature encodings are identical to
     * {@link #RSASHA1}; only the NSEC3 opt-in differs.
     */
    public static final DnssecAlgorithm RSASHA1_NSEC3_SHA1 =
            new DnssecAlgorithm(7, "RSASHA1-NSEC3-SHA1", "SHA1withRSA", "RSA", FAMILY_RSA);

    /**
     * RSA/SHA-256. Defined by <a href="https://www.rfc-editor.org/rfc/rfc5702.html">RFC 5702</a>, {@code MUST} be
     * implemented for validation.
     */
    public static final DnssecAlgorithm RSASHA256 =
            new DnssecAlgorithm(8, "RSASHA256", "SHA256withRSA", "RSA", FAMILY_RSA);

    /**
     * RSA/SHA-512. Defined by <a href="https://www.rfc-editor.org/rfc/rfc5702.html">RFC 5702</a>, {@code MUST} be
     * implemented for validation.
     */
    public static final DnssecAlgorithm RSASHA512 =
            new DnssecAlgorithm(10, "RSASHA512", "SHA512withRSA", "RSA", FAMILY_RSA);

    /**
     * GOST R 34.10-2001. Defined by <a href="https://www.rfc-editor.org/rfc/rfc5933.html">RFC 5933</a> and retired by
     * <a href="https://www.rfc-editor.org/rfc/rfc9906.html#section-2">RFC 9906, Section 2</a>, {@code MUST NOT} be
     * implemented for validation.
     */
    public static final DnssecAlgorithm ECC_GOST = new DnssecAlgorithm(12, "ECC-GOST", null, null, FAMILY_OTHER);

    /**
     * ECDSA over NIST P-256 with SHA-256. Defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc6605.html">RFC 6605</a>, {@code MUST} be implemented for validation.
     */
    public static final DnssecAlgorithm ECDSAP256SHA256 =
            new DnssecAlgorithm(13, "ECDSAP256SHA256", "SHA256withECDSA", "EC", FAMILY_ECDSA);

    /**
     * ECDSA over NIST P-384 with SHA-384. Defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc6605.html">RFC 6605</a>, {@code RECOMMENDED} to be implemented for
     * validation.
     */
    public static final DnssecAlgorithm ECDSAP384SHA384 =
            new DnssecAlgorithm(14, "ECDSAP384SHA384", "SHA384withECDSA", "EC", FAMILY_ECDSA);

    /**
     * Ed25519. Defined by <a href="https://www.rfc-editor.org/rfc/rfc8080.html">RFC 8080</a>, {@code RECOMMENDED} to
     * be implemented for validation. Requires Java 15 or newer.
     */
    public static final DnssecAlgorithm ED25519 =
            new DnssecAlgorithm(15, "ED25519", "Ed25519", "Ed25519", FAMILY_EDDSA);

    /**
     * Ed448. Defined by <a href="https://www.rfc-editor.org/rfc/rfc8080.html">RFC 8080</a>, {@code RECOMMENDED} to be
     * implemented for validation. Requires Java 15 or newer.
     */
    public static final DnssecAlgorithm ED448 = new DnssecAlgorithm(16, "ED448", "Ed448", "Ed448", FAMILY_EDDSA);

    /**
     * SM2 with SM3. Defined by <a href="https://www.rfc-editor.org/rfc/rfc9563.html">RFC 9563</a>, {@code MAY} be
     * implemented for validation. Not implemented.
     */
    public static final DnssecAlgorithm SM2SM3 = new DnssecAlgorithm(17, "SM2SM3", null, null, FAMILY_OTHER);

    /**
     * GOST R 34.10-2012. Defined by <a href="https://www.rfc-editor.org/rfc/rfc9558.html">RFC 9558</a>, {@code MAY}
     * be implemented for validation. Not implemented.
     */
    public static final DnssecAlgorithm ECC_GOST12 = new DnssecAlgorithm(23, "ECC-GOST12", null, null, FAMILY_OTHER);

    /**
     * Private algorithm identified by a domain name, see
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#appendix-A.1.1">RFC 4034, Appendix A.1.1</a>. Reported as
     * unsupported, which <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.3">RFC 6840, Section 5.3</a>
     * permits.
     */
    public static final DnssecAlgorithm PRIVATEDNS = new DnssecAlgorithm(253, "PRIVATEDNS", null, null, FAMILY_OTHER);

    /**
     * Private algorithm identified by an ISO OID, see
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#appendix-A.1.1">RFC 4034, Appendix A.1.1</a>. Reported as
     * unsupported, which <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.3">RFC 6840, Section 5.3</a>
     * permits.
     */
    public static final DnssecAlgorithm PRIVATEOID = new DnssecAlgorithm(254, "PRIVATEOID", null, null, FAMILY_OTHER);

    private static final Map<String, DnssecAlgorithm> BY_NAME = new HashMap<String, DnssecAlgorithm>();
    private static final IntObjectHashMap<DnssecAlgorithm> BY_VALUE = new IntObjectHashMap<DnssecAlgorithm>();
    private static final String EXPECTED;

    static {
        DnssecAlgorithm[] all = {
                RSAMD5, DSA, RSASHA1, DSA_NSEC3_SHA1, RSASHA1_NSEC3_SHA1, RSASHA256, RSASHA512, ECC_GOST,
                ECDSAP256SHA256, ECDSAP384SHA384, ED25519, ED448, SM2SM3, ECC_GOST12, PRIVATEDNS, PRIVATEOID
        };

        StringBuilder expected = new StringBuilder(256);
        expected.append(" (expected: ");
        for (DnssecAlgorithm algorithm: all) {
            BY_NAME.put(algorithm.name(), algorithm);
            BY_VALUE.put(algorithm.intValue(), algorithm);

            expected.append(algorithm.name())
                    .append('(')
                    .append(algorithm.intValue())
                    .append("), ");
        }
        expected.setLength(expected.length() - 2);
        expected.append(')');
        EXPECTED = expected.toString();
    }

    /**
     * Returns the {@link DnssecAlgorithm} for the given algorithm number.
     *
     * <p>Unlike {@link #valueOf(String)} this never throws: an unassigned or unrecognised number yields an
     * unregistered instance whose {@link #name()} is {@code "UNKNOWN"} and whose {@link #isSupported()} is
     * {@code false}, so that an unknown algorithm can be reported rather than aborting the parse.</p>
     *
     * @param intValue the 8-bit algorithm number as it appears on the wire.
     * @return the matching instance, never {@code null}.
     * @throws IllegalArgumentException if {@code intValue} does not fit in an unsigned octet.
     */
    public static DnssecAlgorithm valueOf(int intValue) {
        DnssecAlgorithm result = BY_VALUE.get(intValue);
        if (result == null) {
            return new DnssecAlgorithm(intValue, "UNKNOWN", null, null, FAMILY_OTHER);
        }
        return result;
    }

    /**
     * Returns the {@link DnssecAlgorithm} with the given IANA mnemonic.
     *
     * @param name the mnemonic, for example {@code "ECDSAP256SHA256"}.
     * @return the matching instance, never {@code null}.
     * @throws IllegalArgumentException if no registered algorithm has that mnemonic.
     */
    public static DnssecAlgorithm valueOf(String name) {
        DnssecAlgorithm result = BY_NAME.get(ObjectUtil.checkNotNull(name, "name"));
        if (result == null) {
            throw new IllegalArgumentException("name: " + name + EXPECTED);
        }
        return result;
    }

    private final int intValue;
    private final String name;
    private final String signatureAlgorithm;
    private final String keyFactoryAlgorithm;
    private final int family;
    private final boolean supported;
    private String text;

    private DnssecAlgorithm(int intValue, String name, String signatureAlgorithm, String keyFactoryAlgorithm,
                            int family) {
        if ((intValue & 0xff) != intValue) {
            throw new IllegalArgumentException("intValue: " + intValue + " (expected: 0 ~ 255)");
        }
        this.intValue = intValue;
        this.name = name;
        this.signatureAlgorithm = signatureAlgorithm;
        this.keyFactoryAlgorithm = keyFactoryAlgorithm;
        this.family = family;
        supported = isAvailable(signatureAlgorithm, keyFactoryAlgorithm);
    }

    /**
     * Probes the running JDK once, at class-initialisation time, for the algorithms this class claims to implement.
     * A missing algorithm is a fact about the runtime, not an error: {@code Ed25519} and {@code Ed448} are simply
     * absent before Java 15.
     */
    private static boolean isAvailable(String signatureAlgorithm, String keyFactoryAlgorithm) {
        if (signatureAlgorithm == null) {
            return false;
        }
        try {
            Signature.getInstance(signatureAlgorithm);
            KeyFactory.getInstance(keyFactoryAlgorithm);
            return true;
        } catch (Throwable ignored) {
            // A missing or misbehaving security provider must not prevent this class from loading.
            return false;
        }
    }

    /**
     * Returns the algorithm number as it appears on the wire, in the range {@code 0} to {@code 255}.
     */
    public int intValue() {
        return intValue;
    }

    /**
     * Returns the IANA mnemonic of this algorithm, or {@code "UNKNOWN"} if it is not registered here.
     */
    public String name() {
        return name;
    }

    /**
     * Returns {@code true} if this algorithm is implemented by this package <em>and</em> offered by the running JDK.
     *
     * <p>Both halves matter. An algorithm can be {@code RECOMMENDED} by RFC 9904 and still be unavailable, most
     * commonly {@link #ED25519} and {@link #ED448} on a JDK older than 15. A validator that finds every algorithm of
     * a zone unsupported must treat that zone as <em>Insecure</em>, not <em>Bogus</em>.</p>
     */
    public boolean isSupported() {
        return supported;
    }

    /**
     * Returns {@code true} if this algorithm uses an RSA key encoded as described by
     * <a href="https://www.rfc-editor.org/rfc/rfc3110.html#section-2">RFC 3110, Section 2</a>.
     *
     * <p>The family is a statement about the key encoding only and is independent of {@link #isSupported()}:
     * {@link #RSAMD5} is in the RSA family yet must never be used.</p>
     */
    public boolean isRsa() {
        return family == FAMILY_RSA;
    }

    /**
     * Returns {@code true} if this algorithm uses an ECDSA key encoded as described by
     * <a href="https://www.rfc-editor.org/rfc/rfc6605.html#section-4">RFC 6605, Section 4</a>.
     */
    public boolean isEcdsa() {
        return family == FAMILY_ECDSA;
    }

    /**
     * Returns {@code true} if this algorithm uses an EdDSA key encoded as described by
     * <a href="https://www.rfc-editor.org/rfc/rfc8080.html#section-3">RFC 8080, Section 3</a>.
     */
    public boolean isEdDsa() {
        return family == FAMILY_EDDSA;
    }

    /**
     * Returns the JCA {@link Signature} algorithm name for this algorithm, or {@code null} if this package does not
     * implement it.
     *
     * <p>A non-{@code null} result does not imply the running JDK offers it; check {@link #isSupported()} for that.
     * For {@link #ECDSAP256SHA256} and {@link #ECDSAP384SHA384} the returned name expects an ASN.1 DER signature, so
     * the wire format must first be converted with
     * {@link DnssecSignatures#toDer(byte[], int)}.</p>
     */
    public String signatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * Returns the JCA {@link KeyFactory} algorithm name for this algorithm, or {@code null} if this package does not
     * implement it.
     */
    public String keyFactoryAlgorithm() {
        return keyFactoryAlgorithm;
    }

    @Override
    public int hashCode() {
        return intValue;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof DnssecAlgorithm && ((DnssecAlgorithm) o).intValue == intValue;
    }

    @Override
    public int compareTo(DnssecAlgorithm o) {
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
