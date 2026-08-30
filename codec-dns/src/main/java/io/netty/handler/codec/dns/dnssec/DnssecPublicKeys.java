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

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Decodes the Public Key field of a {@code DNSKEY} record into a {@link PublicKey} the JDK can verify with.
 *
 * <p>The Public Key field is the trailing, variable-length part of the {@code DNSKEY} RDATA described by
 * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-2.1">RFC 4034, Section 2.1</a>; its interpretation is
 * entirely determined by the Algorithm field, and each algorithm family has its own encoding RFC. Only the key field
 * itself is passed here, not the four-octet {@code flags || protocol || algorithm} header.</p>
 *
 * <h3>Why this class validates keys itself</h3>
 *
 * <p>A {@code DNSKEY} arrives from the network and is attacker-controlled, so every structural rule its RFC states is
 * enforced here rather than left to a JCA provider. That is not belt-and-braces: {@code KeyFactory}'s {@code EC}
 * implementation in the JDK accepts an {@link ECPublicKeySpec} whose point is <em>not on the curve</em>, so an
 * on-curve check performed here is the only one that happens.</p>
 *
 * <h3>Canonicality is a security property, not tidiness</h3>
 *
 * <p>Several rules enforced here reject keys that are arithmetically fine but encoded in more than one way. They
 * exist because <strong>a key with two wire encodings has two key tags and two {@code DS} digests</strong>, and key
 * tag collisions are the amplification primitive behind
 * <a href="https://nvd.nist.gov/vuln/detail/CVE-2023-50387">CVE-2023-50387</a> ("KeyTrap") - see
 * {@link DnssecKeyTag}. Letting an attacker mint them at will is the thing to prevent.</p>
 *
 * <p>The elliptic-curve range check is the least obvious of these, and it is not merely a bounds test. On both
 * curves used by DNSSEC, {@code b} is a quadratic residue modulo {@code p}, so {@code x == 0} is a real curve
 * point. Because the curve equation is evaluated modulo {@code p}, encoding that same point with {@code x == p}
 * satisfies it identically: without the requirement that each coordinate be strictly less than {@code p}, one key
 * would have two valid encodings. The JDK does not help here either, as {@code KeyFactory} accepts {@code x == p}.
 * The RSA rules of <a href="https://www.rfc-editor.org/rfc/rfc3110.html#section-2">RFC 3110, Section 2</a> - no
 * leading zero octets, and the 3-octet exponent length reserved for lengths above 255 - are the same defence.</p>
 *
 * <h3>Malformed versus unusable</h3>
 *
 * <p>The two failures this class raises are not interchangeable, because they lead to opposite verdicts:</p>
 * <ul>
 *   <li>{@link DnssecMalformedDataException} means the key breaks a rule its encoding RFC states. That is proof
 *   the data is wrong, and a validator may treat it as <em>Bogus</em>.</li>
 *   <li>{@link DnssecUnsupportedAlgorithmException} means the key is well formed but cannot be evaluated by this
 *   build or this JVM. That is not evidence of an attack, so the zone degrades to <em>Insecure</em>, exactly as
 *   <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.2">RFC 4035, Section 5.2</a> and
 *   <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.2">RFC 6840, Section 5.2</a> already require for
 *   an algorithm the validator does not implement.</li>
 * </ul>
 */
public final class DnssecPublicKeys {

    /**
     * The default lower bound on RSA modulus size, in bits.
     *
     * <p>This is a hardening policy, not a protocol rule.
     * <a href="https://www.rfc-editor.org/rfc/rfc5702.html#section-2.1">RFC 5702, Section 2.1</a> permits
     * {@code RSASHA256} keys as small as 512 bits, and the example key in
     * <a href="https://www.rfc-editor.org/rfc/rfc5702.html#section-6.1">RFC 5702, Section 6.1</a> is exactly that
     * size, but 512-bit RSA has been factorable on commodity hardware for many years. Callers that must accept such
     * keys can pass a lower bound explicitly to {@link #decode(DnssecAlgorithm, byte[], int)}.</p>
     */
    public static final int DEFAULT_MINIMUM_RSA_MODULUS_BITS = 1024;

    /**
     * The upper bound on RSA modulus size, in bits, fixed by
     * <a href="https://www.rfc-editor.org/rfc/rfc3110.html#section-2">RFC 3110, Section 2</a> and restated by
     * <a href="https://www.rfc-editor.org/rfc/rfc5702.html#section-2.1">RFC 5702, Sections 2.1 and 2.2</a>. It also
     * bounds the work a hostile {@code DNSKEY} can force on a verifier.
     */
    public static final int MAXIMUM_RSA_MODULUS_BITS = 4096;

    /**
     * RFC 3110, Section 2 limits the exponent to 4096 bits as well.
     */
    private static final int MAXIMUM_RSA_EXPONENT_BYTES = MAXIMUM_RSA_MODULUS_BITS / Byte.SIZE;

    /**
     * RFC 3110, Section 3 and RFC 5702, Section 2.1: RSASHA1, RSASHA1-NSEC3-SHA1 and RSASHA256 keys MUST NOT be
     * smaller than 512 bits.
     */
    private static final int RFC3110_MINIMUM_RSA_MODULUS_BITS = 512;

    /**
     * RFC 5702, Section 2.2: RSASHA512 keys MUST NOT be smaller than 1024 bits.
     */
    private static final int RFC5702_MINIMUM_RSASHA512_MODULUS_BITS = 1024;

    /** RFC 6605, Section 4: for P-256 each of x and y MUST be encoded as 32 octets. */
    private static final int P256_COORDINATE_LENGTH = 32;

    /** RFC 6605, Section 4: for P-384 each of x and y MUST be encoded as 48 octets. */
    private static final int P384_COORDINATE_LENGTH = 48;

    /** RFC 8080, Section 3: an Ed25519 public key is a 32-octet value. */
    private static final int ED25519_KEY_LENGTH = 32;

    /** RFC 8080, Section 3: an Ed448 public key is a 57-octet value. */
    private static final int ED448_KEY_LENGTH = 57;

    /**
     * DER {@code SubjectPublicKeyInfo} prefix for an Ed25519 key: a 42-octet SEQUENCE holding an AlgorithmIdentifier
     * whose OID is 1.3.101.112 and a 33-octet BIT STRING with no unused bits. See
     * <a href="https://www.rfc-editor.org/rfc/rfc8410.html#section-4">RFC 8410, Section 4</a>. Built by hand because
     * {@code java.security.spec.EdECPublicKeySpec} does not exist before Java 15 and cannot even be referenced from
     * source compiled against Java 8.
     */
    private static final byte[] ED25519_SPKI_PREFIX = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    /**
     * DER {@code SubjectPublicKeyInfo} prefix for an Ed448 key: a 67-octet SEQUENCE holding an AlgorithmIdentifier
     * whose OID is 1.3.101.113 and a 58-octet BIT STRING with no unused bits. See
     * <a href="https://www.rfc-editor.org/rfc/rfc8410.html#section-4">RFC 8410, Section 4</a>.
     */
    private static final byte[] ED448_SPKI_PREFIX = {
            0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x3a, 0x00
    };

    /**
     * Deriving an {@link ECParameterSpec} from a curve name goes through {@link AlgorithmParameters}, which is far
     * too expensive to repeat per record, so both curves are resolved once. {@code null} means the running JDK does
     * not offer the curve, which is reported as an unsupported algorithm rather than a decoding failure.
     */
    private static final ECParameterSpec P256 = ecParameterSpec("secp256r1");
    private static final ECParameterSpec P384 = ecParameterSpec("secp384r1");

    private DnssecPublicKeys() {
    }

    private static ECParameterSpec ecParameterSpec(String curveName) {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(curveName));
            ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
            // Both DNSSEC curves are over a prime field; anything else would break the on-curve check below.
            return spec.getCurve().getField() instanceof ECFieldFp ? spec : null;
        } catch (Throwable ignored) {
            // A missing or misbehaving security provider must not prevent this class from loading.
            return null;
        }
    }

    /**
     * Decodes the Public Key field of a {@code DNSKEY} record, rejecting RSA keys whose modulus is smaller than
     * {@link #DEFAULT_MINIMUM_RSA_MODULUS_BITS}.
     *
     * @param algorithm the value of the {@code DNSKEY} Algorithm field.
     * @param publicKey the value of the {@code DNSKEY} Public Key field. Never modified, never retained.
     * @return the decoded key, ready to be passed to {@code Signature.initVerify}.
     * @throws DnssecUnsupportedAlgorithmException if {@code algorithm} is not supported, or if the key is well
     *                                             formed but this JVM's provider will not build it, in which case
     *                                             the zone is <em>Insecure</em> rather than <em>Bogus</em>.
     * @throws DnssecMalformedDataException        if {@code publicKey} does not obey the encoding its algorithm
     *                                             mandates, which is proof the data is wrong.
     */
    public static PublicKey decode(DnssecAlgorithm algorithm, byte[] publicKey) {
        return decode(algorithm, publicKey, DEFAULT_MINIMUM_RSA_MODULUS_BITS);
    }

    /**
     * Decodes the Public Key field of a {@code DNSKEY} record.
     *
     * @param algorithm             the value of the {@code DNSKEY} Algorithm field.
     * @param publicKey             the value of the {@code DNSKEY} Public Key field. Never modified, never retained.
     * @param minimumRsaModulusBits the smallest RSA modulus to accept, in bits. Ignored for non-RSA algorithms. This
     *                              can only tighten the floor: the minimum mandated for the algorithm by RFC 3110,
     *                              Section 3 and RFC 5702, Sections 2.1 and 2.2 is always enforced as well, as is
     *                              the {@link #MAXIMUM_RSA_MODULUS_BITS} ceiling.
     * @return the decoded key, ready to be passed to {@code Signature.initVerify}.
     * @throws DnssecUnsupportedAlgorithmException if {@code algorithm} is not supported, or if the key is well
     *                                             formed but this JVM's provider will not build it, in which case
     *                                             the zone is <em>Insecure</em> rather than <em>Bogus</em>.
     * @throws DnssecMalformedDataException        if {@code publicKey} does not obey the encoding its algorithm
     *                                             mandates, which is proof the data is wrong.
     */
    public static PublicKey decode(DnssecAlgorithm algorithm, byte[] publicKey, int minimumRsaModulusBits) {
        ObjectUtil.checkNotNull(algorithm, "algorithm");
        ObjectUtil.checkNotNull(publicKey, "publicKey");
        ObjectUtil.checkPositive(minimumRsaModulusBits, "minimumRsaModulusBits");

        if (!algorithm.isSupported()) {
            throw new DnssecUnsupportedAlgorithmException("unsupported DNSSEC algorithm: " + algorithm);
        }
        if (algorithm.isRsa()) {
            return decodeRsa(algorithm, publicKey, minimumRsaModulusBits);
        }
        if (algorithm.isEcdsa()) {
            return decodeEcdsa(algorithm, publicKey);
        }
        if (algorithm.isEdDsa()) {
            return decodeEdDsa(algorithm, publicKey);
        }
        // Unreachable while every supported algorithm belongs to a known family, but a future registry addition
        // must fail closed rather than silently produce no key.
        throw new DnssecUnsupportedAlgorithmException("no key encoding known for DNSSEC algorithm: " + algorithm);
    }

    /**
     * RFC 3110, Section 2: {@code exponent length || exponent || modulus}, where the length is one octet if the
     * exponent is 1 to 255 octets long, or a zero octet followed by a two-octet big-endian length if it is longer.
     */
    private static PublicKey decodeRsa(DnssecAlgorithm algorithm, byte[] publicKey, int minimumRsaModulusBits) {
        if (publicKey.length == 0) {
            throw new DnssecMalformedDataException("RSA public key is empty");
        }

        int exponentOffset;
        int exponentLength = publicKey[0] & 0xff;
        if (exponentLength == 0) {
            if (publicKey.length < 3) {
                throw new DnssecMalformedDataException(
                        "truncated 3-octet RSA exponent length: " + publicKey.length + " octet(s) available");
            }
            exponentLength = (publicKey[1] & 0xff) << 8 | publicKey[2] & 0xff;
            // RFC 3110, Section 2 reserves the 3-octet form for exponents "longer than 255 bytes". Accepting the
            // short encoding here would give a single key two wire representations, hence two key tags and two DS
            // digests, which is exactly the ambiguity a validator must not tolerate. A zero exponent length, which
            // is meaningless, is rejected by the same test.
            if (exponentLength <= 255) {
                throw new DnssecMalformedDataException(
                        "non-canonical 3-octet RSA exponent length: " + exponentLength + " (expected: > 255)");
            }
            exponentOffset = 3;
        } else {
            exponentOffset = 1;
        }

        if (exponentLength > MAXIMUM_RSA_EXPONENT_BYTES) {
            throw new DnssecMalformedDataException("RSA exponent is longer than " + MAXIMUM_RSA_EXPONENT_BYTES
                    + " octets: " + exponentLength);
        }
        if (exponentLength > publicKey.length - exponentOffset) {
            throw new DnssecMalformedDataException("truncated RSA exponent: " + exponentLength
                    + " octet(s) declared but only " + (publicKey.length - exponentOffset) + " available");
        }

        int modulusOffset = exponentOffset + exponentLength;
        if (modulusOffset == publicKey.length) {
            throw new DnssecMalformedDataException("RSA public key has no modulus");
        }
        // RFC 3110, Section 2: "Leading zero octets are prohibited in the exponent and modulus."
        if (publicKey[exponentOffset] == 0) {
            throw new DnssecMalformedDataException("RSA exponent has a leading zero octet");
        }
        if (publicKey[modulusOffset] == 0) {
            throw new DnssecMalformedDataException("RSA modulus has a leading zero octet");
        }

        // BigInteger(int, byte[], int, int) is Java 9+, so the range has to be copied out first.
        BigInteger exponent = new BigInteger(1, Arrays.copyOfRange(publicKey, exponentOffset, modulusOffset));
        BigInteger modulus = new BigInteger(1, Arrays.copyOfRange(publicKey, modulusOffset, publicKey.length));

        // An exponent below 3 is not a usable RSA exponent, and e == 1 would make every signature verify against
        // itself. Checked here rather than relying on the provider, whose behaviour is not specified.
        if (exponent.compareTo(BigInteger.valueOf(3)) < 0) {
            throw new DnssecMalformedDataException("RSA exponent is smaller than 3: " + exponent);
        }

        int modulusBits = modulus.bitLength();
        int minimumBits = Math.max(minimumRsaModulusBits, rfcMinimumRsaModulusBits(algorithm));
        if (modulusBits < minimumBits) {
            throw new DnssecMalformedDataException("RSA modulus is " + modulusBits + " bits, expected at least "
                    + minimumBits + " for " + algorithm);
        }
        if (modulusBits > MAXIMUM_RSA_MODULUS_BITS) {
            throw new DnssecMalformedDataException("RSA modulus is " + modulusBits + " bits, expected at most "
                    + MAXIMUM_RSA_MODULUS_BITS);
        }

        return generate(algorithm, new RSAPublicKeySpec(modulus, exponent));
    }

    private static int rfcMinimumRsaModulusBits(DnssecAlgorithm algorithm) {
        return algorithm == DnssecAlgorithm.RSASHA512
                ? RFC5702_MINIMUM_RSASHA512_MODULUS_BITS : RFC3110_MINIMUM_RSA_MODULUS_BITS;
    }

    /**
     * RFC 6605, Section 4: the key is the uncompressed curve point {@code x || y}, with neither the {@code 0x04}
     * prefix that X9.62 would use nor any length field.
     */
    private static PublicKey decodeEcdsa(DnssecAlgorithm algorithm, byte[] publicKey) {
        ECParameterSpec spec;
        int coordinateLength;
        if (algorithm == DnssecAlgorithm.ECDSAP256SHA256) {
            spec = P256;
            coordinateLength = P256_COORDINATE_LENGTH;
        } else {
            spec = P384;
            coordinateLength = P384_COORDINATE_LENGTH;
        }
        if (spec == null) {
            throw new DnssecUnsupportedAlgorithmException("curve parameters unavailable for " + algorithm);
        }
        if (publicKey.length != coordinateLength * 2) {
            throw new DnssecMalformedDataException("ECDSA public key is " + publicKey.length
                    + " octets, expected " + coordinateLength * 2 + " for " + algorithm);
        }

        BigInteger x = new BigInteger(1, Arrays.copyOfRange(publicKey, 0, coordinateLength));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(publicKey, coordinateLength, publicKey.length));

        EllipticCurve curve = spec.getCurve();
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        // Both coordinates are non-negative by construction, so only the upper bound has to be checked. The JDK
        // does not do it: KeyFactory("EC") happily accepts x == p.
        if (x.compareTo(p) >= 0) {
            throw new DnssecMalformedDataException("ECDSA public key x coordinate is not less than the field prime");
        }
        if (y.compareTo(p) >= 0) {
            throw new DnssecMalformedDataException("ECDSA public key y coordinate is not less than the field prime");
        }
        // The point at infinity has no x || y representation, so an all-zero key is simply not a point.
        if (x.signum() == 0 && y.signum() == 0) {
            throw new DnssecMalformedDataException("ECDSA public key is the all-zero point");
        }
        // y^2 == x^3 + ax + b (mod p). P-256 and P-384 both have cofactor 1, so being on the curve is enough; there
        // is no small subgroup to check for.
        BigInteger left = y.multiply(y).mod(p);
        BigInteger right = x.multiply(x).multiply(x).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
        if (!left.equals(right)) {
            throw new DnssecMalformedDataException("ECDSA public key point is not on the curve of " + algorithm);
        }

        return generate(algorithm, new ECPublicKeySpec(new ECPoint(x, y), spec));
    }

    /**
     * RFC 8080, Section 3: the key is the raw 32-octet (Ed25519) or 57-octet (Ed448) value, with no framing at all.
     * It is wrapped in a {@code SubjectPublicKeyInfo} here because {@link X509EncodedKeySpec} is the only key spec
     * for EdDSA that exists in Java 8.
     */
    private static PublicKey decodeEdDsa(DnssecAlgorithm algorithm, byte[] publicKey) {
        byte[] prefix;
        int keyLength;
        if (algorithm == DnssecAlgorithm.ED25519) {
            prefix = ED25519_SPKI_PREFIX;
            keyLength = ED25519_KEY_LENGTH;
        } else {
            prefix = ED448_SPKI_PREFIX;
            keyLength = ED448_KEY_LENGTH;
        }
        if (publicKey.length != keyLength) {
            throw new DnssecMalformedDataException("EdDSA public key is " + publicKey.length + " octets, expected "
                    + keyLength + " for " + algorithm);
        }

        // The prefix encodes the total length, so it is only correct because the key length was just checked.
        byte[] encoded = new byte[prefix.length + keyLength];
        System.arraycopy(prefix, 0, encoded, 0, prefix.length);
        System.arraycopy(publicKey, 0, encoded, prefix.length, keyLength);

        return generate(algorithm, new X509EncodedKeySpec(encoded));
    }

    /**
     * Runs the {@link KeyFactory}. Everything reaching this point has already satisfied every structural rule its
     * encoding RFC states, because those are checked above and reported as
     * {@link DnssecMalformedDataException}. A failure here therefore means the key is well formed but <em>this
     * JVM's provider</em> declines to build it, which is a limitation of the runtime and not evidence that the zone
     * is wrong, so it is reported as {@link DnssecUnsupportedAlgorithmException} and the zone degrades to
     * <em>Insecure</em> rather than <em>Bogus</em>.
     *
     * <p>Both branches below are reachable in practice. {@code NoSuchAlgorithmException} is the pre-Java-15 EdDSA
     * case. {@code InvalidKeySpecException} is reachable with an RSA key that RFC 3110, Section 2 permits but
     * {@code SunRsaSign} refuses: an exponent that is not smaller than the modulus, or an exponent longer than 64
     * bits once the modulus exceeds 3072 bits. RFC 3110 allows exponents up to 4096 bits, so such a key is legal
     * and simply unusable here.</p>
     *
     * <p>The provider's own diagnostic is preserved as the cause, and the message names the algorithm, so a caller
     * can log this at warning level with enough detail for an operator to see which key was skipped and why. It is
     * deliberately not logged here: {@code decode} runs once per {@code DNSKEY} on attacker-supplied input, and a
     * log statement on that path is a flooding vector.</p>
     */
    private static PublicKey generate(DnssecAlgorithm algorithm, KeySpec keySpec) {
        try {
            return KeyFactory.getInstance(algorithm.keyFactoryAlgorithm()).generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new DnssecUnsupportedAlgorithmException(
                    "no KeyFactory for " + algorithm.keyFactoryAlgorithm() + " required by " + algorithm, e);
        } catch (InvalidKeySpecException e) {
            throw new DnssecUnsupportedAlgorithmException("this JVM's " + algorithm.keyFactoryAlgorithm()
                    + " provider cannot use an otherwise well-formed " + algorithm + " public key", e);
        }
    }
}
