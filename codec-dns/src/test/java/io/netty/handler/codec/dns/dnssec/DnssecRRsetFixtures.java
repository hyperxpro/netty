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
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.util.ReferenceCountUtil;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

/**
 * Records built from the worked examples of the DNSSEC RFCs, for the tests of {@link DnssecCanonicalizer},
 * {@link DnssecSignatureVerifier} and {@link DnssecDsMatcher}.
 *
 * <p>The signatures in <a href="https://www.rfc-editor.org/rfc/rfc4035.html#appendix-A">RFC 4035, appendix A</a>
 * and its worked responses in appendix B are real: they verify cryptographically against the appendix A zone
 * signing key. That is what makes them usable as an end-to-end fixture rather than as an illustration, and it is
 * why the tests here can assert that a tampered record stops verifying.</p>
 */
final class DnssecRRsetFixtures {

    /** {@code example.}, the apex of the RFC 4035, appendix A zone. */
    static final DnsName EXAMPLE = DnsName.fromString("example.");

    /** {@code a.z.w.example.}, the wildcard-expanded owner of RFC 4035, appendix B.6. */
    static final DnsName A_Z_W_EXAMPLE = DnsName.fromString("a.z.w.example.");

    /** {@code example.net.}, the owner of the RFC 6605 example keys. */
    static final DnsName EXAMPLE_NET = DnsName.fromString("example.net.");

    /** {@code 20040509183619}, the Signature Expiration of every RFC 4035 appendix A RRSIG. */
    static final long RFC4035_EXPIRATION = 1084127779L;

    /** {@code 20040409183619}, the Signature Inception of every RFC 4035 appendix A RRSIG. */
    static final long RFC4035_INCEPTION = 1081535779L;

    /** A moment one day after inception, so that every appendix A signature is inside its validity period. */
    static final long RFC4035_VALID_AT = RFC4035_INCEPTION + 86400L;

    /** The key tag of the appendix A zone signing key, which every appendix A RRSIG names. */
    static final int RFC4035_ZSK_KEY_TAG = 38519;

    private DnssecRRsetFixtures() {
    }

    /**
     * {@code example. 3600 IN DNSKEY 256 3 5 (AQOy1bZVvpPqhg4j...)}, the zone signing key of RFC 4035, appendix A.
     */
    static DnsDnskeyRecord zoneSigningKey() {
        return dnskey(EXAMPLE, 256, 3, DnssecAlgorithm.RSASHA1,
                "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBVrZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61e"
                        + "k8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFovBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZI"
                        + "ySFNsgEYvh0z2542lzMKR4Dh8uZffQ==");
    }

    /**
     * {@code example. 3600 IN NSEC a.example. NS SOA MX RRSIG NSEC DNSKEY} from RFC 4035, appendix A, with its
     * Next Domain Name written as {@code nextDomainName} so that a test can re-case it.
     */
    static DnsNsecRecord apexNsec(String nextDomainName) {
        // NS(2) SOA(6) MX(15) RRSIG(46) NSEC(47) DNSKEY(48), in the window block encoding of RFC 4034, section
        // 4.1.2. Copied from the appendix A record, whose type bit map is 00 07 22 01 00 00 00 03 80.
        byte[] bitmap = hex("00072201000000 0380");
        byte[] rdata = concat(wireName(nextDomainName), bitmap);
        return new DnsNsecRecord("example.", DnsRecordType.NSEC, DnsRecord.CLASS_IN, 3600, EXAMPLE,
                Unpooled.wrappedBuffer(rdata));
    }

    /**
     * {@code example. 3600 RRSIG NSEC 5 1 3600 20040509183619 20040409183619 38519 example. (O0k558jHhyrC...)} from
     * RFC 4035, appendix A, the signature over {@link #apexNsec(String)}.
     */
    static DnsRrsigRecord apexNsecRrsig() {
        return rrsig(EXAMPLE, DnsRecordType.NSEC, 1, 3600, RFC4035_EXPIRATION, RFC4035_INCEPTION, "example.",
                "O0k558jHhyrC97ISHnislm4kLMW48C7U7cBmFTfhke5iVqNRVTB1STLMpgpbDIC9hcryoO0V"
                        + "Z9ME5xPzUEhbvGnHd5sfzgFVeGxr5Nyyq4tWSDBgIBiLQUv1ivy29vhXy7WgR62dPrZ0PWvm"
                        + "jfFJ5arXf4nPxp/kEowGgBRzY/U=");
    }

    /**
     * {@code a.z.w.example. 3600 IN MX 1 ai.example.} from RFC 4035, appendix B.6, the answer that was synthesised
     * from the wildcard {@code *.w.example.}.
     */
    static DnssecRecord wildcardMx() {
        return rawRecord(A_Z_W_EXAMPLE, DnsRecordType.MX, 3600, concat(hex("0001"), wireName("ai.example.")));
    }

    /**
     * {@code a.z.w.example. 3600 RRSIG MX 5 2 3600 ... 38519 example.} from RFC 4035, appendix B.6. Its Labels
     * field of 2 against a four-label owner is what says the answer came from a wildcard.
     */
    static DnsRrsigRecord wildcardMxRrsig(int labels) {
        return rrsig(A_Z_W_EXAMPLE, DnsRecordType.MX, labels, 3600, RFC4035_EXPIRATION, RFC4035_INCEPTION,
                "example.",
                "OMK8rAZlepfzLWW75Dxd63jy2wswESzxDKG2f9AMN1CytCd10cYISAxfAdvXSZ7xujKAtPbc"
                        + "tvOQ2ofO7AZJ+d01EeeQTVBPq4/6KCWhqe2XTjnkVLNvvhnc0u28aoSsG0+4InvkkOHknKxw"
                        + "4kX18MMR34i8lC36SR5xBni8vHI=");
    }

    /** {@code example.net. 3600 IN DNSKEY 257 3 13 (...)} from RFC 6605, section 6.1. */
    static DnsDnskeyRecord rfc6605P256Key() {
        return dnskey(EXAMPLE_NET, 257, 3, DnssecAlgorithm.ECDSAP256SHA256,
                "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==");
    }

    /** {@code example.net. 3600 IN DNSKEY 257 3 14 (...)} from RFC 6605, section 6.2. */
    static DnsDnskeyRecord rfc6605P384Key() {
        return dnskey(EXAMPLE_NET, 257, 3, DnssecAlgorithm.ECDSAP384SHA384,
                "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8"
                        + "/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40");
    }

    /**
     * Builds a {@code DS} record with the given fields, so that a test can pair a published digest with the key it
     * is supposed to describe.
     */
    static DnsDsRecord ds(DnsName owner, int keyTag, DnssecAlgorithm algorithm, DnssecDigestType digestType,
                          String digest) {
        ByteArrayOutputStream rdata = new ByteArrayOutputStream();
        rdata.write(keyTag >> 8);
        rdata.write(keyTag);
        rdata.write(algorithm.intValue());
        rdata.write(digestType.intValue());
        byte[] bytes = hex(digest);
        rdata.write(bytes, 0, bytes.length);
        return new DnsDsRecord(owner.toString(), DnsRecordType.DS, DnsRecord.CLASS_IN, 3600, owner,
                Unpooled.wrappedBuffer(rdata.toByteArray()));
    }

    static DnsDnskeyRecord dnskey(DnsName owner, int flags, int protocol, DnssecAlgorithm algorithm,
                                  String publicKey) {
        ByteArrayOutputStream rdata = new ByteArrayOutputStream();
        rdata.write(flags >> 8);
        rdata.write(flags);
        rdata.write(protocol);
        rdata.write(algorithm.intValue());
        byte[] key = Base64.getMimeDecoder().decode(publicKey);
        rdata.write(key, 0, key.length);
        return new DnsDnskeyRecord(owner.toString(), DnsRecordType.DNSKEY, DnsRecord.CLASS_IN, 3600, owner,
                Unpooled.wrappedBuffer(rdata.toByteArray()));
    }

    static DnsRrsigRecord rrsig(DnsName owner, DnsRecordType typeCovered, int labels, long originalTtl,
                                long expiration, long inception, String signerName, String signature) {
        return rrsig(owner, typeCovered, DnssecAlgorithm.RSASHA1, labels, originalTtl, expiration, inception,
                RFC4035_ZSK_KEY_TAG, wireName(signerName), Base64.getMimeDecoder().decode(signature));
    }

    static DnsRrsigRecord rrsig(DnsName owner, DnsRecordType typeCovered, DnssecAlgorithm algorithm, int labels,
                                long originalTtl, long expiration, long inception, int keyTag, byte[] signerName,
                                byte[] signature) {
        ByteArrayOutputStream rdata = new ByteArrayOutputStream();
        writeShort(rdata, typeCovered.intValue());
        rdata.write(algorithm.intValue());
        rdata.write(labels);
        writeInt(rdata, originalTtl);
        writeInt(rdata, expiration);
        writeInt(rdata, inception);
        writeShort(rdata, keyTag);
        rdata.write(signerName, 0, signerName.length);
        rdata.write(signature, 0, signature.length);
        return new DnsRrsigRecord(owner.toString(), DnsRecordType.RRSIG, DnsRecord.CLASS_IN, 3600, owner,
                Unpooled.wrappedBuffer(rdata.toByteArray()));
    }

    /**
     * A {@link DnssecRecord} of any type, which is what an RRset of a type this package has no parsed record for,
     * such as {@code MX}, is made of.
     */
    static DnssecRecord rawRecord(DnsName owner, DnsRecordType type, long timeToLive, byte[] rdata) {
        return rawRecord(owner, type, DnsRecord.CLASS_IN, timeToLive, rdata);
    }

    static DnssecRecord rawRecord(DnsName owner, DnsRecordType type, int dnsClass, long timeToLive, byte[] rdata) {
        return new DefaultDnssecRawRecord(owner.toString(), type, dnsClass, timeToLive, owner,
                Unpooled.wrappedBuffer(rdata));
    }

    /**
     * The {@code RDATA} of the RFC 4035, appendix A zone signing key, with two octets of the modulus varied until
     * the key tag is {@code tag} and one more varied to make otherwise identical keys distinguishable.
     *
     * <p>A key tag is a 16-bit sum over the RDATA, so a collision is a search over two octets rather than a
     * cryptographic problem: that is what makes the LockCram shape of KeyTrap cheap to mount and worth bounding.
     * The modulus that comes out is not a real one, but it is well formed, which is what the tests need — they
     * assert on the work the verifier does before and around the signature check.</p>
     */
    static DnsDnskeyRecord keyWithTag(DnsName owner, int tag, int distinguisher) {
        byte[] rdata = zoneSigningKeyRdata();
        // Octet 4 of the RDATA is the RFC 3110 exponent length and octet 6 starts the modulus, whose leading octet
        // has to keep its high bit set for the modulus to be the 1024 bits the parser insists on.
        rdata[6] = (byte) (0x80 | distinguisher & 0x3f);
        for (int carry = 0; carry < 8; carry++) {
            rdata[7] = (byte) carry;
            for (int high = 0; high <= 0xff; high++) {
                for (int low = 0; low <= 0xff; low++) {
                    rdata[rdata.length - 3] = (byte) low;
                    rdata[rdata.length - 2] = (byte) high;
                    if (DnssecKeyTag.compute(rdata) == tag) {
                        return new DnsDnskeyRecord(owner.toString(), DnsRecordType.DNSKEY, DnsRecord.CLASS_IN, 3600,
                                owner, Unpooled.wrappedBuffer(rdata));
                    }
                }
            }
        }
        throw new AssertionError("no modulus tweak in the searched range gives key tag " + tag);
    }

    /**
     * A well-formed {@code RSASHA1} {@code DNSKEY} that differs from every other one this method returns, without
     * caring what its key tag comes out as.
     */
    static DnsDnskeyRecord distinctKey(DnsName owner, int distinguisher) {
        byte[] rdata = zoneSigningKeyRdata();
        rdata[6] = (byte) (0x80 | distinguisher & 0x3f);
        return new DnsDnskeyRecord(owner.toString(), DnsRecordType.DNSKEY, DnsRecord.CLASS_IN, 3600, owner,
                Unpooled.wrappedBuffer(rdata));
    }

    static byte[] zoneSigningKeyRdata() {
        DnsDnskeyRecord key = zoneSigningKey();
        try {
            return ByteBufUtil.getBytes(key.content());
        } finally {
            key.release();
        }
    }

    /**
     * A clock pinned to {@code seconds} since the epoch, without which none of the published vectors can be
     * exercised: every one of them expired long ago.
     */
    static DnssecClock clockAt(final long seconds) {
        return new DnssecClock() {
            @Override
            public long currentTimeMillis() {
                return seconds * 1000L;
            }
        };
    }

    /**
     * Writes a domain name in wire form, keeping the case of every label exactly as given, which is what makes the
     * RFC 6840, section 5.1 tests able to tell a correct implementation from a wrong one.
     */
    static byte[] wireName(String name) {
        if (".".equals(name)) {
            return new byte[] { 0 };
        }
        String stripped = name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String label : stripped.split("\\.", -1)) {
            out.write(label.length());
            for (int i = 0; i < label.length(); i++) {
                out.write(label.charAt(i));
            }
        }
        out.write(0);
        return out.toByteArray();
    }

    static byte[] hex(String hex) {
        StringBuilder digits = new StringBuilder(hex.length());
        for (int i = 0; i < hex.length(); i++) {
            char c = hex.charAt(i);
            if (c != ' ' && c != '\n') {
                digits.append(c);
            }
        }
        byte[] bytes = new byte[digits.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(digits.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, result, offset, part.length);
            offset += part.length;
        }
        return result;
    }

    static void releaseAll(Object... records) {
        for (Object record : records) {
            ReferenceCountUtil.release(record);
        }
    }

    private static void writeShort(ByteArrayOutputStream out, int value) {
        out.write(value >> 8);
        out.write(value);
    }

    private static void writeInt(ByteArrayOutputStream out, long value) {
        out.write((int) (value >> 24));
        out.write((int) (value >> 16));
        out.write((int) (value >> 8));
        out.write((int) value);
    }
}
