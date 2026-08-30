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
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.dns.DefaultDnsQuestion;
import io.netty.handler.codec.dns.DefaultDnsResponse;
import io.netty.handler.codec.dns.DnsOpCode;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.handler.codec.dns.DnsResponseCode;
import io.netty.handler.codec.dns.DnsSection;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.EventExecutor;
import io.netty.util.concurrent.Future;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds signed zones for {@link DnssecValidatorTest}.
 *
 * <p>The RFC 4035 appendix A zone is a genuine signed zone and its signatures are used verbatim where they reach
 * far enough, but its private keys are not published, so anything that needs a record the RFC does not contain —
 * a delegation into a second signed zone, a wildcard with its proof, an NSEC3 opt-out span — has to be signed
 * here. These zones use ECDSA P-256 (algorithm 13) because key generation and signing are both fast enough to do
 * inside a unit test, unlike the 1024-bit RSA of appendix A.</p>
 *
 * <p>Everything is written from the RFC text. Nothing here is derived from another implementation's code or test
 * data.</p>
 */
final class DnssecChainTestSupport {

    /** {@code 2023-11-14T22:13:20Z}, the Signature Inception of every signature made here. */
    static final long INCEPTION = 1700000000L;

    /** {@code 2027-01-15T08:00:00Z}, the Signature Expiration of every signature made here. */
    static final long EXPIRATION = 1800000000L;

    /** {@code 2025-06-15T14:26:40Z}, comfortably inside the validity period above. */
    static final long NOW_SECONDS = 1750000000L;

    static final long TTL = 3600L;

    /** The RR type numbers used to build {@code NSEC} type bit maps here. */
    static final int A = DnsRecordType.A.intValue();
    static final int NS = DnsRecordType.NS.intValue();
    static final int SOA = DnsRecordType.SOA.intValue();
    static final int CNAME = DnsRecordType.CNAME.intValue();
    static final int MX = DnsRecordType.MX.intValue();
    static final int DS = DnsRecordType.DS.intValue();
    static final int RRSIG = DnsRecordType.RRSIG.intValue();
    static final int NSEC = DnsRecordType.NSEC.intValue();
    static final int DNSKEY = DnsRecordType.DNSKEY.intValue();

    private DnssecChainTestSupport() {
    }

    static DnssecClock clock() {
        return DnssecRRsetFixtures.clockAt(NOW_SECONDS);
    }

    // -----------------------------------------------------------------------------------------------------------
    // A signed zone

    /**
     * One zone with one key, which both signs the zone's data and, being its own secure entry point, signs the
     * {@code DNSKEY} RRset that carries it. A single combined signing key is legal DNSSEC and keeps the fixtures
     * to the point.
     */
    static final class TestZone {

        final DnsName name;
        final DnsDnskeyRecord dnskey;
        final int keyTag;
        private final KeyPair keyPair;

        TestZone(String zone) {
            this(zone, 257);
        }

        TestZone(String zone, int flags) {
            name = DnsName.fromString(zone);
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new ECGenParameterSpec("secp256r1"));
                keyPair = generator.generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException("ECDSA P-256 is unavailable", e);
            }
            byte[] raw = rawPublicKey((ECPublicKey) keyPair.getPublic());
            dnskey = DnssecRRsetFixtures.dnskey(name, flags, 3, DnssecAlgorithm.ECDSAP256SHA256,
                    Base64.getEncoder().encodeToString(raw));
            keyTag = dnskey.keyTag();
        }

        /**
         * Signs an RRset with the {@code Labels} field the owner name calls for, which is the ordinary case.
         */
        DnsRrsigRecord sign(List<? extends DnssecRecord> records) {
            return sign(records, DnssecCanonicalizer.ownerLabelCount(records.get(0).owner()));
        }

        /**
         * Signs an RRset with an explicit {@code Labels} field, which is how a wildcard expansion is made: the
         * signature then covers {@code *.} followed by the rightmost {@code labels} labels of the owner.
         */
        DnsRrsigRecord sign(List<? extends DnssecRecord> records, int labels) {
            return sign(records, labels, INCEPTION, EXPIRATION);
        }

        DnsRrsigRecord sign(List<? extends DnssecRecord> records, int labels, long inception, long expiration) {
            DnssecRecord first = records.get(0);
            DnsRRset rrset = new DnsRRset(first.owner(), first.type(), DnsRecord.CLASS_IN, records,
                    Collections.<DnsRrsigRecord>emptyList());
            DnsRrsigRecord placeholder = rrsig(rrset, labels, inception, expiration, EMPTY_SIGNATURE);
            byte[] preimage;
            ByteBuf signedData = null;
            try {
                signedData = DnssecCanonicalizer.signedData(ByteBufAllocator.DEFAULT, placeholder, rrset);
                preimage = new byte[signedData.readableBytes()];
                signedData.getBytes(signedData.readerIndex(), preimage);
            } finally {
                if (signedData != null) {
                    signedData.release();
                }
                placeholder.release();
            }
            byte[] signature;
            try {
                Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(keyPair.getPrivate());
                signer.update(preimage);
                signature = derToRaw(signer.sign(), 32);
            } catch (Exception e) {
                throw new IllegalStateException("signing failed", e);
            }
            return rrsig(rrset, labels, inception, expiration, signature);
        }

        private DnsRrsigRecord rrsig(DnsRRset rrset, int labels, long inception, long expiration,
                                     byte[] signature) {
            return DnssecRRsetFixtures.rrsig(rrset.owner(), rrset.type(), DnssecAlgorithm.ECDSAP256SHA256, labels,
                    TTL, expiration, inception, keyTag, name.toWireBytes(), signature);
        }

        /**
         * Returns the {@code DS} record this zone's parent would publish for {@code child}.
         */
        DnsDsRecord delegationTo(TestZone child, DnssecDigestType digestType) {
            byte[] digest = DnssecDsMatcher.digest(digestType, child.name, child.dnskey);
            return DnssecRRsetFixtures.ds(child.name, child.keyTag, DnssecAlgorithm.ECDSAP256SHA256, digestType,
                    toHex(digest));
        }

        /**
         * Returns the trust anchor an operator would configure for this zone: the same tag, algorithm, digest type
         * and digest a parent {@code DS} would carry.
         */
        DnssecTrustAnchor anchor() {
            byte[] digest = DnssecDsMatcher.digest(DnssecDigestType.SHA256, name, dnskey);
            return new DnssecTrustAnchor(name, keyTag, DnssecAlgorithm.ECDSAP256SHA256, DnssecDigestType.SHA256,
                    digest);
        }
    }

    private static final byte[] EMPTY_SIGNATURE = new byte[0];

    // -----------------------------------------------------------------------------------------------------------
    // Records

    static DnssecRecord a(String owner, String address) {
        String[] parts = address.split("\\.");
        byte[] rdata = new byte[4];
        for (int i = 0; i < 4; i++) {
            rdata[i] = (byte) Integer.parseInt(parts[i]);
        }
        return DnssecRRsetFixtures.rawRecord(DnsName.fromString(owner), DnsRecordType.A, TTL, rdata);
    }

    static DnssecRecord cname(String owner, String target) {
        return DnssecRRsetFixtures.rawRecord(DnsName.fromString(owner), DnsRecordType.CNAME, TTL,
                DnsName.fromString(target).toWireBytes());
    }

    static DnssecRecord dname(String owner, String target) {
        return DnssecRRsetFixtures.rawRecord(DnsName.fromString(owner), DnsRecordType.DNAME, TTL,
                DnsName.fromString(target).toWireBytes());
    }

    static DnssecRecord ns(String owner, String target) {
        return DnssecRRsetFixtures.rawRecord(DnsName.fromString(owner), DnsRecordType.NS, TTL,
                DnsName.fromString(target).toWireBytes());
    }

    /**
     * Builds an {@code NSEC} record. The type bit map is written as a single window block, which covers every type
     * below 256 and so every type these fixtures use.
     */
    static DnsNsecRecord nsec(String owner, String next, int... types) {
        DnsName ownerName = DnsName.fromString(owner);
        byte[] rdata = DnssecRRsetFixtures.concat(DnsName.fromString(next).toWireBytes(), typeBitmap(types));
        return new DnsNsecRecord(ownerName.toString(), DnsRecordType.NSEC, DnsRecord.CLASS_IN, TTL, ownerName,
                Unpooled.wrappedBuffer(rdata));
    }

    /**
     * Builds an {@code NSEC3} record whose owner name is the base32hex label of {@code hashedOwner} under
     * {@code zone}, per RFC 5155, Section 3.
     */
    static DnsNsec3Record nsec3(DnsName zone, byte[] hashedOwner, byte[] nextHashedOwner, int flags,
                                int iterations, byte[] salt, int... types) {
        byte[] bitmap = typeBitmap(types);
        byte[] rdata = new byte[6 + salt.length + nextHashedOwner.length + bitmap.length];
        int i = 0;
        rdata[i++] = 1;
        rdata[i++] = (byte) flags;
        rdata[i++] = (byte) (iterations >> 8);
        rdata[i++] = (byte) iterations;
        rdata[i++] = (byte) salt.length;
        System.arraycopy(salt, 0, rdata, i, salt.length);
        i += salt.length;
        rdata[i++] = (byte) nextHashedOwner.length;
        System.arraycopy(nextHashedOwner, 0, rdata, i, nextHashedOwner.length);
        i += nextHashedOwner.length;
        System.arraycopy(bitmap, 0, rdata, i, bitmap.length);
        DnsName owner = DnsName.fromString(DnsNsec3Hasher.toLabel(hashedOwner) + '.' + zone);
        return new DnsNsec3Record(owner.toString(), DnsRecordType.NSEC3, DnsRecord.CLASS_IN, TTL, owner,
                Unpooled.wrappedBuffer(rdata));
    }

    static byte[] typeBitmap(int... types) {
        int highest = 0;
        for (int i = 0; i < types.length; i++) {
            highest = Math.max(highest, types[i]);
        }
        byte[] bitmap = new byte[2 + highest / 8 + 1];
        bitmap[0] = 0;
        bitmap[1] = (byte) (highest / 8 + 1);
        for (int i = 0; i < types.length; i++) {
            bitmap[2 + types[i] / 8] |= (byte) (0x80 >>> (types[i] % 8));
        }
        return bitmap;
    }

    // -----------------------------------------------------------------------------------------------------------
    // Messages

    static DefaultDnsResponse response(String qname, DnsRecordType qtype, DnsResponseCode code,
                                       List<? extends DnsRecord> answers, List<? extends DnsRecord> authorities) {
        DefaultDnsResponse response = new DefaultDnsResponse(1, DnsOpCode.QUERY, code);
        response.addRecord(DnsSection.QUESTION, new DefaultDnsQuestion(qname, qtype));
        addAll(response, DnsSection.ANSWER, answers);
        addAll(response, DnsSection.AUTHORITY, authorities);
        return response;
    }

    private static void addAll(DefaultDnsResponse response, DnsSection section,
                               List<? extends DnsRecord> records) {
        for (int i = 0; i < records.size(); i++) {
            response.addRecord(section, ReferenceCountUtil.retain(records.get(i)));
        }
    }

    @SafeVarargs
    static <T> List<T> list(T... items) {
        return new ArrayList<T>(Arrays.asList(items));
    }

    // -----------------------------------------------------------------------------------------------------------
    // The fetcher

    /**
     * A {@link DnssecRecordFetcher} over a fixed table. There is no network anywhere in these tests: a lookup that
     * was not set up fails, so a missing fixture shows up as an Indeterminate verdict naming the query rather than
     * as a hang.
     */
    static final class InMemoryFetcher implements DnssecRecordFetcher {

        private final EventExecutor executor;
        private final Map<String, Answer> answers = new HashMap<String, Answer>();
        private final List<String> queries = new ArrayList<String>();

        InMemoryFetcher(EventExecutor executor) {
            this.executor = executor;
        }

        void put(DnsName name, DnsRecordType type, DnsResponseCode code, List<? extends DnsRecord> answerRecords,
                 List<? extends DnsRecord> authorityRecords) {
            answers.put(key(name, type), new Answer(code, answerRecords, authorityRecords, null));
        }

        void fail(DnsName name, DnsRecordType type, Throwable cause) {
            answers.put(key(name, type), new Answer(null, null, null, cause));
        }

        List<String> queries() {
            return queries;
        }

        @Override
        public Future<DnssecFetchResult> fetch(DnsName name, DnsRecordType type) {
            String key = key(name, type);
            queries.add(key);
            Answer answer = answers.get(key);
            if (answer == null) {
                return executor.newFailedFuture(new IllegalStateException("no fixture for " + key));
            }
            if (answer.cause != null) {
                return executor.newFailedFuture(answer.cause);
            }
            DefaultDnsResponse response = new DefaultDnsResponse(1, DnsOpCode.QUERY, answer.code);
            try {
                response.addRecord(DnsSection.QUESTION, new DefaultDnsQuestion(name.toString(), type));
                addAll(response, DnsSection.ANSWER, answer.answers);
                addAll(response, DnsSection.AUTHORITY, answer.authorities);
                return executor.newSucceededFuture(DnssecFetchResult.fromResponse(response));
            } finally {
                response.release();
            }
        }

        private static String key(DnsName name, DnsRecordType type) {
            return name + " " + type;
        }

        private static final class Answer {

            final DnsResponseCode code;
            final List<? extends DnsRecord> answers;
            final List<? extends DnsRecord> authorities;
            final Throwable cause;

            Answer(DnsResponseCode code, List<? extends DnsRecord> answers,
                   List<? extends DnsRecord> authorities, Throwable cause) {
                this.code = code;
                this.answers = answers;
                this.authorities = authorities;
                this.cause = cause;
            }
        }
    }

    // -----------------------------------------------------------------------------------------------------------
    // Crypto plumbing

    /**
     * RFC 6605, Section 4: a P-256 {@code DNSKEY} carries {@code x} and {@code y} as 32 octets each, with no
     * {@code 0x04} prefix.
     */
    private static byte[] rawPublicKey(ECPublicKey key) {
        byte[] raw = new byte[64];
        writeFixed(key.getW().getAffineX().toByteArray(), raw, 0, 32);
        writeFixed(key.getW().getAffineY().toByteArray(), raw, 32, 32);
        return raw;
    }

    private static void writeFixed(byte[] value, byte[] out, int offset, int length) {
        int start = 0;
        int len = value.length;
        while (len > length && value[start] == 0) {
            start++;
            len--;
        }
        if (len > length) {
            throw new IllegalStateException("value is " + len + " octets, expected at most " + length);
        }
        System.arraycopy(value, start, out, offset + length - len, len);
    }

    /**
     * Converts the ASN.1 {@code SEQUENCE { INTEGER r, INTEGER s }} the JDK produces into the fixed-width
     * {@code r || s} an {@code RRSIG} carries, which is the inverse of what
     * {@link DnssecSignatures#toDer(byte[], int)} does.
     */
    static byte[] derToRaw(byte[] der, int half) {
        int i = 0;
        if (der[i++] != 0x30) {
            throw new IllegalStateException("not a DER SEQUENCE");
        }
        int length = der[i++] & 0xff;
        if (length > 0x80) {
            int octets = length - 0x80;
            for (int j = 0; j < octets; j++) {
                i++;
            }
        }
        byte[] raw = new byte[half * 2];
        i = readInteger(der, i, raw, 0, half);
        readInteger(der, i, raw, half, half);
        return raw;
    }

    private static int readInteger(byte[] der, int offset, byte[] out, int at, int half) {
        int i = offset;
        if (der[i++] != 0x02) {
            throw new IllegalStateException("not a DER INTEGER");
        }
        int length = der[i++] & 0xff;
        int end = i + length;
        int start = i;
        int len = length;
        while (len > 0 && der[start] == 0) {
            start++;
            len--;
        }
        if (len > half) {
            throw new IllegalStateException("integer is " + len + " octets, expected at most " + half);
        }
        System.arraycopy(der, start, out, at + half - len, len);
        return end;
    }

    static String toHex(byte[] bytes) {
        StringBuilder buf = new StringBuilder(bytes.length * 2);
        for (int i = 0; i < bytes.length; i++) {
            buf.append(Character.forDigit((bytes[i] >> 4) & 0xf, 16));
            buf.append(Character.forDigit(bytes[i] & 0xf, 16));
        }
        return buf.toString();
    }
}
