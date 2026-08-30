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

/**
 * {@code RDATA} taken from the worked examples of the DNSSEC RFCs. Every constant here is the wire form of a record
 * that appears in a published example zone, so a decoder that agrees with these agrees with the specification's own
 * idea of what the octets mean.
 */
final class DnssecTestVectors {

    private DnssecTestVectors() {
    }

    /**
     * {@code example. 3600 IN DNSKEY 256 3 5 (AQOy1bZVvpPqhg4j...)}, the zone signing key of the signed zone in
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#appendix-A">RFC 4035, appendix A</a>. Its key tag is
     * 38519, which is the tag the RRSIGs in that zone name.
     */
    static final byte[] RFC4035_DNSKEY_ZSK = {
            (byte) 0x01, (byte) 0x00, (byte) 0x03, (byte) 0x05, (byte) 0x01, (byte) 0x03,
            (byte) 0xb2, (byte) 0xd5, (byte) 0xb6, (byte) 0x55, (byte) 0xbe, (byte) 0x93,
            (byte) 0xea, (byte) 0x86, (byte) 0x0e, (byte) 0x23, (byte) 0xec, (byte) 0x42,
            (byte) 0x68, (byte) 0x33, (byte) 0xda, (byte) 0xc8, (byte) 0xdd, (byte) 0x99,
            (byte) 0xb2, (byte) 0x13, (byte) 0x1d, (byte) 0x8e, (byte) 0xcc, (byte) 0x30,
            (byte) 0x55, (byte) 0xad, (byte) 0x9c, (byte) 0xbf, (byte) 0x96, (byte) 0xf2,
            (byte) 0x39, (byte) 0x09, (byte) 0x07, (byte) 0x8f, (byte) 0xc5, (byte) 0x71,
            (byte) 0xd9, (byte) 0x4b, (byte) 0x88, (byte) 0xbc, (byte) 0x74, (byte) 0x03,
            (byte) 0x47, (byte) 0xe0, (byte) 0x35, (byte) 0xf7, (byte) 0xb5, (byte) 0xb1,
            (byte) 0xe8, (byte) 0x97, (byte) 0xad, (byte) 0x5e, (byte) 0x93, (byte) 0xc1,
            (byte) 0x05, (byte) 0x31, (byte) 0xcb, (byte) 0x06, (byte) 0x5f, (byte) 0x12,
            (byte) 0x9c, (byte) 0x88, (byte) 0x91, (byte) 0x47, (byte) 0xca, (byte) 0x19,
            (byte) 0x7d, (byte) 0xe0, (byte) 0x2f, (byte) 0x8d, (byte) 0xc0, (byte) 0x82,
            (byte) 0xd0, (byte) 0x77, (byte) 0x3b, (byte) 0x14, (byte) 0x95, (byte) 0x21,
            (byte) 0x68, (byte) 0xbc, (byte) 0x16, (byte) 0x6c, (byte) 0xca, (byte) 0x5f,
            (byte) 0xcd, (byte) 0x5f, (byte) 0xac, (byte) 0x84, (byte) 0x6e, (byte) 0xdc,
            (byte) 0x3f, (byte) 0xc4, (byte) 0xdf, (byte) 0x59, (byte) 0x35, (byte) 0xca,
            (byte) 0xdb, (byte) 0x62, (byte) 0xf8, (byte) 0x23, (byte) 0x8d, (byte) 0x9f,
            (byte) 0xd4, (byte) 0x54, (byte) 0xf6, (byte) 0x48, (byte) 0xc9, (byte) 0x21,
            (byte) 0x4d, (byte) 0xb2, (byte) 0x01, (byte) 0x18, (byte) 0xbe, (byte) 0x1d,
            (byte) 0x33, (byte) 0xdb, (byte) 0x9e, (byte) 0x36, (byte) 0x97, (byte) 0x33,
            (byte) 0x0a, (byte) 0x47, (byte) 0x80, (byte) 0xe1, (byte) 0xf2, (byte) 0xe6,
            (byte) 0x5f, (byte) 0x7d
    };

    /**
     * {@code example. 3600 IN DNSKEY 257 3 5 (AQOeX7+baTmvpVHb...)}, the key signing key of the same zone. Its key
     * tag is 9465 and it has the Secure Entry Point flag set.
     */
    static final byte[] RFC4035_DNSKEY_KSK = {
            (byte) 0x01, (byte) 0x01, (byte) 0x03, (byte) 0x05, (byte) 0x01, (byte) 0x03,
            (byte) 0x9e, (byte) 0x5f, (byte) 0xbf, (byte) 0x9b, (byte) 0x69, (byte) 0x39,
            (byte) 0xaf, (byte) 0xa5, (byte) 0x51, (byte) 0xdb, (byte) 0xd8, (byte) 0x27,
            (byte) 0x0b, (byte) 0x9c, (byte) 0xbd, (byte) 0x5d, (byte) 0x31, (byte) 0x15,
            (byte) 0x9b, (byte) 0xba, (byte) 0xc7, (byte) 0x11, (byte) 0xbc, (byte) 0x75,
            (byte) 0xe5, (byte) 0x2e, (byte) 0x75, (byte) 0xf0, (byte) 0x0f, (byte) 0x3b,
            (byte) 0xea, (byte) 0xa7, (byte) 0x8b, (byte) 0x59, (byte) 0x54, (byte) 0xaa,
            (byte) 0x75, (byte) 0xb1, (byte) 0x93, (byte) 0x1e, (byte) 0xa4, (byte) 0x56,
            (byte) 0xfc, (byte) 0x32, (byte) 0xfc, (byte) 0x61, (byte) 0x85, (byte) 0x6d,
            (byte) 0xf2, (byte) 0xff, (byte) 0x44, (byte) 0x19, (byte) 0xb3, (byte) 0x20,
            (byte) 0xa3, (byte) 0x73, (byte) 0x31, (byte) 0x89, (byte) 0xd6, (byte) 0xa9,
            (byte) 0x3c, (byte) 0xbc, (byte) 0x97, (byte) 0xb9, (byte) 0xda, (byte) 0x23,
            (byte) 0xa1, (byte) 0x22, (byte) 0x72, (byte) 0x91, (byte) 0x39, (byte) 0x52,
            (byte) 0xd1, (byte) 0xc3, (byte) 0x11, (byte) 0xa9, (byte) 0x31, (byte) 0xfc,
            (byte) 0xcf, (byte) 0x44, (byte) 0xb3, (byte) 0x25, (byte) 0x1b, (byte) 0x26,
            (byte) 0xeb, (byte) 0xe7, (byte) 0x56, (byte) 0xce, (byte) 0x57, (byte) 0xfd,
            (byte) 0x6c, (byte) 0x7b, (byte) 0x43, (byte) 0x83, (byte) 0x69, (byte) 0xc8,
            (byte) 0xf7, (byte) 0x0e, (byte) 0x89, (byte) 0xb2, (byte) 0x07, (byte) 0x84,
            (byte) 0x01, (byte) 0xe6, (byte) 0x02, (byte) 0x93, (byte) 0x62, (byte) 0x8b,
            (byte) 0x7f, (byte) 0x2b, (byte) 0xd6, (byte) 0xa5, (byte) 0x93, (byte) 0x9f,
            (byte) 0xe3, (byte) 0xf2, (byte) 0xf7, (byte) 0xdd, (byte) 0xe2, (byte) 0x35,
            (byte) 0x82, (byte) 0x58, (byte) 0x3f, (byte) 0x84, (byte) 0xd5, (byte) 0x2c,
            (byte) 0xde, (byte) 0xd1
    };

    /**
     * {@code a.example. 3600 DS 57855 5 1 (B6DCD485719ADCA18E5F3D48A2331627FDD3636B)} from
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#appendix-A">RFC 4035, appendix A</a>.
     */
    static final byte[] RFC4035_DS = {
            (byte) 0xe1, (byte) 0xff, (byte) 0x05, (byte) 0x01, (byte) 0xb6, (byte) 0xdc,
            (byte) 0xd4, (byte) 0x85, (byte) 0x71, (byte) 0x9a, (byte) 0xdc, (byte) 0xa1,
            (byte) 0x8e, (byte) 0x5f, (byte) 0x3d, (byte) 0x48, (byte) 0xa2, (byte) 0x33,
            (byte) 0x16, (byte) 0x27, (byte) 0xfd, (byte) 0xd3, (byte) 0x63, (byte) 0x6b
    };

    /**
     * {@code example. 3600 RRSIG NSEC 5 1 3600 20040509183619 20040409183619 38519 example. (O0k558jHhyrC...)} from
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#appendix-A">RFC 4035, appendix A</a>. The two timestamps
     * are 1084127779 and 1081535779 seconds since the epoch.
     */
    static final byte[] RFC4035_RRSIG = {
            (byte) 0x00, (byte) 0x2f, (byte) 0x05, (byte) 0x01, (byte) 0x00, (byte) 0x00,
            (byte) 0x0e, (byte) 0x10, (byte) 0x40, (byte) 0x9e, (byte) 0x7a, (byte) 0x23,
            (byte) 0x40, (byte) 0x76, (byte) 0xed, (byte) 0x23, (byte) 0x96, (byte) 0x77,
            (byte) 0x07, (byte) 0x65, (byte) 0x78, (byte) 0x61, (byte) 0x6d, (byte) 0x70,
            (byte) 0x6c, (byte) 0x65, (byte) 0x00, (byte) 0x3b, (byte) 0x49, (byte) 0x39,
            (byte) 0xe7, (byte) 0xc8, (byte) 0xc7, (byte) 0x87, (byte) 0x2a, (byte) 0xc2,
            (byte) 0xf7, (byte) 0xb2, (byte) 0x12, (byte) 0x1e, (byte) 0x78, (byte) 0xac,
            (byte) 0x96, (byte) 0x6e, (byte) 0x24, (byte) 0x2c, (byte) 0xc5, (byte) 0xb8,
            (byte) 0xf0, (byte) 0x2e, (byte) 0xd4, (byte) 0xed, (byte) 0xc0, (byte) 0x66,
            (byte) 0x15, (byte) 0x37, (byte) 0xe1, (byte) 0x91, (byte) 0xee, (byte) 0x62,
            (byte) 0x56, (byte) 0xa3, (byte) 0x51, (byte) 0x55, (byte) 0x30, (byte) 0x75,
            (byte) 0x49, (byte) 0x32, (byte) 0xcc, (byte) 0xa6, (byte) 0x0a, (byte) 0x5b,
            (byte) 0x0c, (byte) 0x80, (byte) 0xbd, (byte) 0x85, (byte) 0xca, (byte) 0xf2,
            (byte) 0xa0, (byte) 0xed, (byte) 0x15, (byte) 0x67, (byte) 0xd3, (byte) 0x04,
            (byte) 0xe7, (byte) 0x13, (byte) 0xf3, (byte) 0x50, (byte) 0x48, (byte) 0x5b,
            (byte) 0xbc, (byte) 0x69, (byte) 0xc7, (byte) 0x77, (byte) 0x9b, (byte) 0x1f,
            (byte) 0xce, (byte) 0x01, (byte) 0x55, (byte) 0x78, (byte) 0x6c, (byte) 0x6b,
            (byte) 0xe4, (byte) 0xdc, (byte) 0xb2, (byte) 0xab, (byte) 0x8b, (byte) 0x56,
            (byte) 0x48, (byte) 0x30, (byte) 0x60, (byte) 0x20, (byte) 0x18, (byte) 0x8b,
            (byte) 0x41, (byte) 0x4b, (byte) 0xf5, (byte) 0x8a, (byte) 0xfc, (byte) 0xb6,
            (byte) 0xf6, (byte) 0xf8, (byte) 0x57, (byte) 0xcb, (byte) 0xb5, (byte) 0xa0,
            (byte) 0x47, (byte) 0xad, (byte) 0x9d, (byte) 0x3e, (byte) 0xb6, (byte) 0x74,
            (byte) 0x3d, (byte) 0x6b, (byte) 0xe6, (byte) 0x8d, (byte) 0xf1, (byte) 0x49,
            (byte) 0xe5, (byte) 0xaa, (byte) 0xd7, (byte) 0x7f, (byte) 0x89, (byte) 0xcf,
            (byte) 0xc6, (byte) 0x9f, (byte) 0xe4, (byte) 0x12, (byte) 0x8c, (byte) 0x06,
            (byte) 0x80, (byte) 0x14, (byte) 0x73, (byte) 0x63, (byte) 0xf5
    };

    /**
     * The {@code RDATA} of {@code alfa.example.com. 86400 IN NSEC host.example.com. (A MX RRSIG NSEC TYPE1234)},
     * copied verbatim from the encoding published in
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-4.3">RFC 4034, section 4.3</a>.
     */
    static final byte[] RFC4034_NSEC = {
            // host.example.com.
            0x04, 0x68, 0x6f, 0x73, 0x74,
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x03, 0x63, 0x6f, 0x6d,
            0x00,
            // Window block 0, six octets of bitmap: A (1), MX (15), RRSIG (46) and NSEC (47).
            0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03,
            // Window block 4, 27 octets of bitmap, with only bit 2 of the 27th octet set:
            // 4 * 256 + 26 * 8 + 2 == 1234.
            0x04, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20,
    };

    /**
     * {@code example. 3600 NSEC a.example. NS SOA MX RRSIG NSEC DNSKEY} from
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#appendix-A">RFC 4035, appendix A</a>.
     */
    static final byte[] RFC4035_NSEC = {
            (byte) 0x01, (byte) 0x61, (byte) 0x07, (byte) 0x65, (byte) 0x78, (byte) 0x61,
            (byte) 0x6d, (byte) 0x70, (byte) 0x6c, (byte) 0x65, (byte) 0x00, (byte) 0x00,
            (byte) 0x07, (byte) 0x22, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x03, (byte) 0x80
    };

    /**
     * {@code 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. NSEC3 1 1 12 aabbccdd
     * 2t7b4g4vsa5smi47k61mv5bv1a22bojr (MX DNSKEY NS SOA NSEC3PARAM RRSIG)}, the apex NSEC3 of the example zone in
     * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#appendix-A">RFC 5155, appendix A</a>. The next hashed
     * owner name is the base32hex string {@code 2t7b4g4vsa5smi47k61mv5bv1a22bojr} decoded to 20 octets.
     */
    static final byte[] RFC5155_NSEC3 = {
            (byte) 0x01, (byte) 0x01, (byte) 0x00, (byte) 0x0c, (byte) 0x04, (byte) 0xaa,
            (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0x14, (byte) 0x17, (byte) 0x4e,
            (byte) 0xb2, (byte) 0x40, (byte) 0x9f, (byte) 0xe2, (byte) 0x8b, (byte) 0xcb,
            (byte) 0x48, (byte) 0x87, (byte) 0xa1, (byte) 0x83, (byte) 0x6f, (byte) 0x95,
            (byte) 0x7f, (byte) 0x0a, (byte) 0x84, (byte) 0x25, (byte) 0xe2, (byte) 0x7b,
            (byte) 0x00, (byte) 0x07, (byte) 0x22, (byte) 0x01, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x02, (byte) 0x90
    };

    /**
     * {@code ji6neoaepv8b5o6k4ev33abha8ht9fgc.example. NSEC3 1 1 12 aabbccdd
     * k8udemvp1j2f7eg6jebps17vp3n8i58h} from
     * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#appendix-A">RFC 5155, appendix A</a>. It matches the
     * empty non-terminal {@code y.w.example} and therefore has no type bit maps at all.
     */
    static final byte[] RFC5155_NSEC3_EMPTY_NON_TERMINAL = {
            (byte) 0x01, (byte) 0x01, (byte) 0x00, (byte) 0x0c, (byte) 0x04, (byte) 0xaa,
            (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0x14, (byte) 0xa2, (byte) 0x3c,
            (byte) 0xd7, (byte) 0x5b, (byte) 0xf9, (byte) 0x0c, (byte) 0xc4, (byte) 0xf3,
            (byte) 0xba, (byte) 0x06, (byte) 0x9b, (byte) 0x97, (byte) 0x9e, (byte) 0x04,
            (byte) 0xff, (byte) 0xc8, (byte) 0xee, (byte) 0x89, (byte) 0x15, (byte) 0x11
    };

    /**
     * {@code example. NSEC3PARAM 1 0 12 aabbccdd} from
     * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#appendix-A">RFC 5155, appendix A</a>.
     */
    static final byte[] RFC5155_NSEC3PARAM = {
            (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x0c, (byte) 0x04, (byte) 0xaa,
            (byte) 0xbb, (byte) 0xcc, (byte) 0xdd
    };
}
