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

import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.dns.DnsName;
import io.netty.util.CharsetUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.MessageDigest;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class Base32HexTest {

    /**
     * The salt of the example zone of
     * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#appendix-A">RFC 5155, appendix A</a>, which uses SHA-1
     * with 12 iterations.
     */
    private static final byte[] RFC5155_SALT = { (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd };

    private static final int RFC5155_ITERATIONS = 12;

    /**
     * The <a href="https://www.rfc-editor.org/rfc/rfc4648.html#section-10">RFC 4648, section 10</a> base32hex test
     * vectors with the padding removed, which is the form NSEC3 uses.
     */
    @ParameterizedTest
    @CsvSource({
            "f,        CO",
            "fo,       CPNG",
            "foo,      CPNMU",
            "foob,     CPNMUOG",
            "fooba,    CPNMUOJ1",
            "foobar,   CPNMUOJ1E8",
    })
    public void testRfc4648Vectors(String decoded, String encoded) {
        byte[] octets = decoded.getBytes(CharsetUtil.US_ASCII);
        assertEquals(encoded, Base32Hex.encode(octets));
        assertArrayEquals(octets, Base32Hex.decode(ascii(encoded)));
    }

    /**
     * The hashed owner names of the example zone of
     * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#appendix-A">RFC 5155, appendix A</a>. The hash is
     * recomputed here from the name so the fixture is anchored to the definition in
     * <a href="https://www.rfc-editor.org/rfc/rfc5155.html#section-5">RFC 5155, section 5</a> rather than to a
     * transcription, which also pins down that the alphabet really is base32hex and not base32.
     */
    @ParameterizedTest
    @CsvSource({
            "example.,        0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM",
            "a.example.,      35MTHGPGCU1QG68FAB165KLNSNK3DPVL",
            "ai.example.,     GJEQE526PLBF1G8MKLP59ENFD789NJGI",
            "ns1.example.,    2T7B4G4VSA5SMI47K61MV5BV1A22BOJR",
            "ns2.example.,    Q04JKCEVQVMU85R014C7DKBA38O0JI5R",
            "w.example.,      K8UDEMVP1J2F7EG6JEBPS17VP3N8I58H",
            "*.w.example.,    R53BQ7CC2UVMUBFU5OCMM6PERS9TK9EN",
            "x.w.example.,    B4UM86EGHHDS6NEA196SMVMLO4ORS995",
            "y.w.example.,    JI6NEOAEPV8B5O6K4EV33ABHA8HT9FGC",
            "x.y.w.example.,  2VPTU5TIMAMQTTGL4LUU9KG21E0AOR3S",
            "xx.example.,     T644EBQK9BIBCNA874GIVR6JOJ62MLHV",
    })
    public void testRfc5155Nsec3OwnerNames(String name, String label) throws Exception {
        byte[] hash = nsec3Hash(DnsName.fromString(name));
        assertEquals(20, hash.length);
        assertEquals(label, Base32Hex.encode(hash));
        assertArrayEquals(hash, Base32Hex.decode(ascii(label)));
        // RFC 5155, section 3.3 (as corrected by erratum 3544) calls the digits case-insensitive, and a
        // 0x20-randomised query makes a lower case label the normal case rather than the exception.
        assertArrayEquals(hash, Base32Hex.decode(ascii(toAsciiLowerCase(label))));
    }

    @Test
    public void testEmptyInput() {
        assertEquals("", Base32Hex.encode(new byte[0]));
        assertEquals(0, Base32Hex.decode(new byte[0]).length);
    }

    @Test
    public void testDecodeRange() {
        byte[] src = ascii("xxCPNMUOJ1E8xx");
        assertArrayEquals("foobar".getBytes(CharsetUtil.US_ASCII), Base32Hex.decode(src, 2, 10));
    }

    @Test
    public void testDecodeRejectsARangeOutsideTheArray() {
        assertThrows(IndexOutOfBoundsException.class, () -> Base32Hex.decode(ascii("CO"), 1, 2));
    }

    @Test
    public void testDecodeRejectsPadding() {
        // "CO======" is what a padded RFC 4648 encoder produces, and it has a length an unpadded encoder could also
        // produce, so the padding characters themselves have to be rejected.
        assertThrows(CorruptedFrameException.class, () -> Base32Hex.decode(ascii("CO======")));
        assertThrows(CorruptedFrameException.class, () -> Base32Hex.decode(ascii("CPNMUOG=")));
    }

    @ParameterizedTest
    @ValueSource(strings = { "C", "CPN", "CPNMUO", "CPNMUOJ1E" })
    public void testDecodeRejectsImpossibleLengths(String encoded) {
        assertThrows(CorruptedFrameException.class, () -> Base32Hex.decode(ascii(encoded)));
    }

    @ParameterizedTest
    @ValueSource(strings = { "CW", "CX", "CY", "CZ", "C-", "C.", "CWNG", "CO CPNG" })
    public void testDecodeRejectsCharactersOutsideTheAlphabet(String encoded) {
        // 'W' to 'Z' are in the plain base32 alphabet but not in the base32hex one, which is exactly the mix-up
        // that RFC 5155 erratum 3544 is about.
        assertThrows(CorruptedFrameException.class, () -> Base32Hex.decode(ascii(encoded)));
    }

    @Test
    public void testDecodeRejectsNonAsciiOctets() {
        assertThrows(CorruptedFrameException.class, () -> Base32Hex.decode(new byte[] { 'C', (byte) 0xff }));
    }

    @Test
    public void testDecodeRejectsNonZeroTrailingBits() {
        // "CO" and "CP" both carry the octet 0x66, but only "CO" leaves the two unused bits clear. Accepting "CP"
        // would give the same NSEC3 hash two spellings, and therefore an owner name a second form.
        assertArrayEquals(new byte[] { 0x66 }, Base32Hex.decode(ascii("CO")));
        assertThrows(CorruptedFrameException.class, () -> Base32Hex.decode(ascii("CP")));
        assertThrows(CorruptedFrameException.class, () -> Base32Hex.decode(ascii("CPNH")));
        assertThrows(CorruptedFrameException.class, () -> Base32Hex.decode(ascii("CPNMUOJ1E9")));
    }

    @Test
    public void testEncodeAndDecodeRoundTrip() {
        Random random = new Random(0x5155);
        for (int length = 0; length <= 64; length++) {
            byte[] octets = new byte[length];
            random.nextBytes(octets);
            String encoded = Base32Hex.encode(octets);
            assertArrayEquals(octets, Base32Hex.decode(ascii(encoded)), "round trip failed for " + encoded);
        }
    }

    @Test
    public void testEncodeUsesTheHexAlphabetInUpperCase() {
        // The first eight octets of the alphabet map to '0' to '7', where plain base32 would use 'A' to 'H'.
        assertEquals("00000000", Base32Hex.encode(new byte[5]));
        byte[] all = new byte[5];
        for (int i = 0; i < all.length; i++) {
            all[i] = (byte) 0xff;
        }
        assertEquals("VVVVVVVV", Base32Hex.encode(all));
    }

    /**
     * The iterated hash of <a href="https://www.rfc-editor.org/rfc/rfc5155.html#section-5">RFC 5155, section 5</a>:
     * {@code IH(salt, x, 0) = H(x || salt)} and {@code IH(salt, x, k) = H(IH(salt, x, k - 1) || salt)}.
     */
    private static byte[] nsec3Hash(DnsName name) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        digest.update(name.toLowerCase().toWireBytes());
        digest.update(RFC5155_SALT);
        byte[] hash = digest.digest();
        for (int i = 0; i < RFC5155_ITERATIONS; i++) {
            digest.reset();
            digest.update(hash);
            digest.update(RFC5155_SALT);
            hash = digest.digest();
        }
        return hash;
    }

    private static byte[] ascii(String text) {
        return text.getBytes(CharsetUtil.US_ASCII);
    }

    private static String toAsciiLowerCase(String text) {
        StringBuilder buf = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            buf.append(c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c);
        }
        return buf.toString();
    }
}
