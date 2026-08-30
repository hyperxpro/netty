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
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Rebuilds the signed form of RFC 4035, section 5.3.2 out of what the decoder hands over and checks it against the
 * signature published in RFC 4035, appendix A.
 * <p>
 * This is not the canonicalisation layer, which is still to be written; it is the proof that a typed record
 * carries everything that layer will need, and it pins down the one canonicalisation rule that is easy to get
 * backwards.
 * <p>
 * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.1">RFC 6840, section 5.1</a> corrects RFC 4034,
 * section 6.2: names in {@code NSEC} {@code RDATA} are <em>not</em> down-cased, while names in {@code RRSIG}
 * {@code RDATA} are. RFC 4034 wrongly lists NSEC among the types to down-case. Following RFC 4034 alone makes a
 * validator accept an {@code NSEC} whose octets are not the ones the zone signed, so the signature stops
 * committing to the exact wire form; it also produces a spurious {@code Bogus} against a zone that genuinely
 * publishes mixed-case {@code NSEC} {@code RDATA}. It is not a denial-of-existence bypass, because name
 * comparison and the canonical ordering are case-insensitive, so re-casing the next domain name does not let an
 * attacker prove a different range.
 */
public class DnssecSignedFormTest {

    private static final int HEADER_LENGTH = 12;

    /**
     * Everything of an RRSIG's RDATA up to and including the key tag; the signer's name follows it.
     */
    private static final int RRSIG_FIXED_LENGTH = 18;

    private static ByteBuf message(DnsName owner, DnsRecordType type, long timeToLive, byte[] rdata) {
        ByteBuf buf = Unpooled.buffer();
        buf.writeZero(HEADER_LENGTH);
        owner.writeTo(buf);
        buf.writeShort(type.intValue());
        buf.writeShort(DnsRecord.CLASS_IN);
        buf.writeInt((int) timeToLive);
        buf.writeShort(rdata.length);
        buf.writeBytes(rdata);
        buf.readerIndex(HEADER_LENGTH);
        return buf;
    }

    /**
     * {@code RRSIG_RDATA | RR}, where {@code RRSIG_RDATA} is the RRSIG's own RDATA without the signature and with
     * the signer's name down-cased, and {@code RR} is the covered record in canonical form. See RFC 4034,
     * section 6.2 and RFC 4035, section 5.3.2.
     *
     * @param downcaseNsecRdata whether to apply RFC 4034, section 6.2's list literally, which wrongly includes
     *                          NSEC. Passing {@code true} models the bug RFC 6840, section 5.1 corrects.
     */
    private static byte[] signedData(DnsRrsigRecord rrsig, DnsNsecRecord covered, boolean downcaseNsecRdata) {
        ByteBuf out = Unpooled.buffer();
        try {
            ByteBuf rrsigRdata = rrsig.content();
            out.writeBytes(rrsigRdata, rrsigRdata.readerIndex(), RRSIG_FIXED_LENGTH);
            rrsig.signerName().toLowerCase().writeTo(out);

            covered.owner().toLowerCase().writeTo(out);
            out.writeShort(covered.type().intValue());
            out.writeShort(covered.dnsClass());
            out.writeInt((int) rrsig.originalTtl());

            ByteBuf rdata = Unpooled.buffer();
            try {
                if (downcaseNsecRdata) {
                    covered.nextDomainName().toLowerCase().writeTo(rdata);
                } else {
                    covered.nextDomainName().writeTo(rdata);
                }
                covered.types().writeTo(rdata);
                out.writeShort(rdata.readableBytes());
                out.writeBytes(rdata);
            } finally {
                rdata.release();
            }
            return ByteBufUtil.getBytes(out);
        } finally {
            out.release();
        }
    }

    private static boolean verifies(DnsDnskeyRecord key, DnsRrsigRecord rrsig, byte[] signedData) throws Exception {
        PublicKey publicKey = DnssecPublicKeys.decode(key.algorithm(), key.publicKey());
        Signature signature = Signature.getInstance(rrsig.algorithm().signatureAlgorithm());
        signature.initVerify(publicKey);
        signature.update(signedData);
        return signature.verify(rrsig.signature());
    }

    private static <T extends DnsRecord> T decode(ByteBuf message) throws Exception {
        return DnssecDnsRecordDecoder.INSTANCE.decodeRecord(message);
    }

    /**
     * The NSEC of the RFC 4035 example zone, with its next domain name re-cased to {@code nextName}. The name
     * occupies the first 11 octets of the RDATA; the type bit maps follow.
     */
    private static byte[] nsecRdata(String nextName) {
        byte[] rdata = DnssecTestVectors.RFC4035_NSEC.clone();
        byte[] name = DnsName.fromString(nextName).toWireBytes();
        assertEquals(11, name.length, "the re-cased name must be the same length as a.example.");
        System.arraycopy(name, 0, rdata, 0, name.length);
        return rdata;
    }

    /**
     * The published RRSIG over the published NSEC verifies. Nothing here is self-signed, so this cannot pass by
     * agreeing with a bug in our own encoder.
     */
    @Test
    public void testPublishedNsecVerifiesAgainstItsPublishedRrsig() throws Exception {
        ByteBuf keyMessage = message(DnsName.fromString("example."), DnsRecordType.DNSKEY, 3600,
                DnssecTestVectors.RFC4035_DNSKEY_ZSK);
        ByteBuf nsecMessage = message(DnsName.fromString("example."), DnsRecordType.NSEC, 3600,
                DnssecTestVectors.RFC4035_NSEC);
        ByteBuf rrsigMessage = message(DnsName.fromString("example."), DnsRecordType.RRSIG, 3600,
                DnssecTestVectors.RFC4035_RRSIG);
        DnsDnskeyRecord key = decode(keyMessage);
        DnsNsecRecord nsec = decode(nsecMessage);
        DnsRrsigRecord rrsig = decode(rrsigMessage);
        try {
            assertEquals(38519, key.keyTag());
            assertEquals(rrsig.keyTag(), key.keyTag());
            assertEquals(DnsRecordType.NSEC, rrsig.typeCovered());
            assertTrue(verifies(key, rrsig, signedData(rrsig, nsec, false)),
                    "the RFC 4035 appendix A signature must verify over the record the decoder produced");
        } finally {
            ReferenceCountUtil.release(key);
            ReferenceCountUtil.release(nsec);
            ReferenceCountUtil.release(rrsig);
            keyMessage.release();
            nsecMessage.release();
            rrsigMessage.release();
        }
    }

    /**
     * The discriminating case. An attacker re-cases the NSEC next domain name on the wire. A validator that
     * follows RFC 6840, section 5.1 and does not down-case NSEC RDATA sees the tampering; one that follows RFC
     * 4034, section 6.2's list literally accepts it. A lower-case fixture produces identical octets under both
     * rules and cannot tell them apart, which is why this one is re-cased.
     */
    @Test
    public void testRecasedNsecRdataIsDetectedOnlyWithoutDowncasing() throws Exception {
        ByteBuf keyMessage = message(DnsName.fromString("example."), DnsRecordType.DNSKEY, 3600,
                DnssecTestVectors.RFC4035_DNSKEY_ZSK);
        ByteBuf nsecMessage = message(DnsName.fromString("example."), DnsRecordType.NSEC, 3600,
                nsecRdata("A.EXAMPLE."));
        ByteBuf rrsigMessage = message(DnsName.fromString("example."), DnsRecordType.RRSIG, 3600,
                DnssecTestVectors.RFC4035_RRSIG);
        DnsDnskeyRecord key = decode(keyMessage);
        DnsNsecRecord nsec = decode(nsecMessage);
        DnsRrsigRecord rrsig = decode(rrsigMessage);
        try {
            // The decoder must hand over the octets it read, upper case and all.
            assertArrayEquals(DnsName.fromString("A.EXAMPLE.").toWireBytes(),
                    nsec.nextDomainName().toWireBytes());

            assertFalse(verifies(key, rrsig, signedData(rrsig, nsec, false)),
                    "RFC 6840 section 5.1: NSEC RDATA is not down-cased, so the re-cased record must not verify");
            assertTrue(verifies(key, rrsig, signedData(rrsig, nsec, true)),
                    "down-casing NSEC RDATA accepts the tampered record, which is the bug this fixture exists to"
                            + " catch; if this ever fails the fixture has stopped discriminating");
        } finally {
            ReferenceCountUtil.release(key);
            ReferenceCountUtil.release(nsec);
            ReferenceCountUtil.release(rrsig);
            keyMessage.release();
            nsecMessage.release();
            rrsigMessage.release();
        }
    }

    /**
     * The NSEC record itself must survive the codec unchanged, including its case, or the signature over it stops
     * matching whatever is re-encoded.
     */
    @Test
    public void testMixedCaseNsecRoundTripsUnchanged() throws Exception {
        byte[] rdata = nsecRdata("A.EXAMPLE.");
        ByteBuf message = message(DnsName.fromString("ExAmPlE."), DnsRecordType.NSEC, 3600, rdata);
        byte[] expected = ByteBufUtil.getBytes(message, HEADER_LENGTH, message.writerIndex() - HEADER_LENGTH);
        DnsNsecRecord nsec = decode(message);
        ByteBuf out = Unpooled.buffer();
        try {
            assertArrayEquals(rdata, ByteBufUtil.getBytes(nsec.content()));
            assertArrayEquals(DnsName.fromString("ExAmPlE.").toWireBytes(), nsec.owner().toWireBytes());
            DnssecDnsRecordEncoder.INSTANCE.encodeRecord(nsec, out);
            assertArrayEquals(expected, ByteBufUtil.getBytes(out));
        } finally {
            out.release();
            ReferenceCountUtil.release(nsec);
            message.release();
        }
    }
}
