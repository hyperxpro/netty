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
package io.netty.handler.codec.dns;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.util.CharsetUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnsNameTest {

    /**
     * The ordering published in <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-6.1">RFC 4034,
     * section 6.1</a>, which {@link DnsName#CANONICAL_ORDER} has to reproduce exactly.
     */
    private static final String[] RFC4034_CANONICAL_ORDER = {
            "example.",
            "a.example.",
            "yljkjljk.a.example.",
            "Z.a.example.",
            "zABC.a.EXAMPLE.",
            "z.example.",
            "\\001.z.example.",
            "*.z.example.",
            "\\200.z.example.",
    };

    /**
     * Octets that have historically confused name parsers: the terminator, the label separator, the escape
     * character, the wildcard and octets with the most significant bit set.
     */
    private static final int[] INTERESTING_OCTETS = { 0x00, 0x2e, 0x5c, 0x2a, 0x20, 0x41, 0x5a, 0x61, 0x7a,
            0x7f, 0x80, 0xc0, 0xff };

    // A DNS message that holds "netty.io." at offset 0 and the compressed "www.netty.io." at offset 10.
    private static final byte[] COMPRESSED_MESSAGE = {
            5, 'n', 'e', 't', 't', 'y', 2, 'i', 'o', 0,
            3, 'w', 'w', 'w', (byte) 0xc0, 0,
    };

    @Test
    public void testRootIsASingleZeroOctet() {
        assertTrue(DnsName.ROOT.isRoot());
        assertEquals(0, DnsName.ROOT.labelCount());
        assertEquals(1, DnsName.ROOT.wireLength());
        assertArrayEquals(new byte[] { 0 }, DnsName.ROOT.toWireBytes());
        assertEquals(".", DnsName.ROOT.toString());
        assertSame(DnsName.ROOT, DnsName.ROOT.parent());
    }

    @Test
    public void testDecodeUncompressedName() {
        ByteBuf in = Unpooled.wrappedBuffer(COMPRESSED_MESSAGE);
        try {
            DnsName name = DnsName.decode(in, 0, in.writerIndex());
            assertEquals("netty.io.", name.toString());
            assertEquals(10, DnsName.encodedLength(in, 0, in.writerIndex()));
            assertEquals(0, in.readerIndex(), "the absolute-offset overload must not move the reader index");
        } finally {
            in.release();
        }
    }

    @Test
    public void testDecodeFollowsCompressionPointer() {
        ByteBuf in = Unpooled.wrappedBuffer(COMPRESSED_MESSAGE);
        try {
            DnsName name = DnsName.decode(in, 10, in.writerIndex());
            assertEquals("www.netty.io.", name.toString());
            assertArrayEquals(new byte[] { 3, 'w', 'w', 'w', 5, 'n', 'e', 't', 't', 'y', 2, 'i', 'o', 0 },
                    name.toWireBytes(), "the pointer must be expanded, not preserved");
            // Three label octets, one length octet and the two octets of the pointer.
            assertEquals(6, DnsName.encodedLength(in, 10, in.writerIndex()));
        } finally {
            in.release();
        }
    }

    @Test
    public void testDecodeAdvancesReaderIndexPastThePointerOnly() {
        ByteBuf in = Unpooled.wrappedBuffer(COMPRESSED_MESSAGE);
        try {
            in.readerIndex(10);
            DnsName name = DnsName.decode(in, in.writerIndex());
            assertEquals("www.netty.io.", name.toString());
            assertEquals(16, in.readerIndex());
        } finally {
            in.release();
        }
    }

    @Test
    public void testDecodeFollowsAChainOfPointers() {
        // "io." at 0, "netty." + pointer to 0 at 3, "www." + pointer to 3 at 11.
        byte[] message = {
                2, 'i', 'o', 0,
                5, 'n', 'e', 't', 't', 'y', (byte) 0xc0, 0,
                3, 'w', 'w', 'w', (byte) 0xc0, 4,
        };
        ByteBuf in = Unpooled.wrappedBuffer(message);
        try {
            assertEquals("www.netty.io.", DnsName.decode(in, 12, in.writerIndex()).toString());
        } finally {
            in.release();
        }
    }

    @Test
    public void testDecodeRejectsSelfReferencingPointer() {
        assertDecodeFails(new byte[] { (byte) 0xc0, 0 }, 0);
    }

    @Test
    public void testDecodeRejectsForwardPointer() {
        // A forward pointer is how a name is made to loop or to name octets the sender has not written yet.
        assertDecodeFails(new byte[] { (byte) 0xc0, 2, 1, 'a', 0 }, 0);
    }

    @Test
    public void testDecodeRejectsTooManyPointerHops() {
        // The root at offset 0, then a chain of backwards pointers each landing on the previous one.
        int hops = 17;
        byte[] message = new byte[1 + hops * 2];
        message[0] = 0;
        for (int i = 0; i < hops; i++) {
            int target = i == 0 ? 0 : 1 + (i - 1) * 2;
            message[1 + i * 2] = (byte) 0xc0;
            message[2 + i * 2] = (byte) target;
        }
        ByteBuf in = Unpooled.wrappedBuffer(message);
        try {
            // Sixteen hops is still fine, the seventeenth is one too many.
            assertEquals(".", DnsName.decode(in, 1 + 15 * 2, in.writerIndex()).toString());
            assertThrows(CorruptedFrameException.class,
                    () -> DnsName.decode(in, 1 + 16 * 2, in.writerIndex()));
        } finally {
            in.release();
        }
    }

    @ParameterizedTest
    @ValueSource(ints = { 0x40, 0x80 })
    public void testDecodeRejectsReservedLabelTypes(int labelType) {
        assertDecodeFails(new byte[] { (byte) labelType, 0 }, 0);
    }

    @Test
    public void testDecodeRejectsTruncatedLabel() {
        assertDecodeFails(new byte[] { 5, 'a', 'b' }, 0);
    }

    @Test
    public void testDecodeRejectsMissingRootLabel() {
        // Some servers omit the terminating zero octet for empty names, but a name that takes part in a signature
        // has to be exactly what the signer saw, so guessing is not an option here.
        assertDecodeFails(new byte[] { 5, 'n', 'e', 't', 't', 'y' }, 0);
    }

    @Test
    public void testDecodeRejectsTruncatedPointer() {
        assertDecodeFails(new byte[] { (byte) 0xc0 }, 0);
    }

    @Test
    public void testDecodeRejectsOffsetOutsideTheMessage() {
        assertDecodeFails(new byte[] { 0 }, 1);
        assertDecodeFails(new byte[] { 0 }, -1);
    }

    @Test
    public void testDecodeRejectsMessageEndPastTheBuffer() {
        ByteBuf in = Unpooled.wrappedBuffer(new byte[] { 0 });
        try {
            assertThrows(CorruptedFrameException.class, () -> DnsName.decode(in, 0, 2));
        } finally {
            in.release();
        }
    }

    @Test
    public void testDecodeAcceptsAMaximumLengthName() {
        // 64 + 64 + 64 + 62 + 1 == 255.
        ByteBuf in = Unpooled.wrappedBuffer(wireName(63, 63, 63, 61));
        try {
            DnsName name = DnsName.decode(in, 0, in.writerIndex());
            assertEquals(DnsName.MAX_NAME_LENGTH, name.wireLength());
            assertEquals(4, name.labelCount());
        } finally {
            in.release();
        }
    }

    @Test
    public void testDecodeRejectsAnOverlongName() {
        assertDecodeFails(wireName(63, 63, 63, 62), 0);
    }

    @Test
    public void testDecodeRejectsAnOverlongNameAssembledFromPointers() {
        // Three maximum-length labels followed by a pointer back to a fourth one, which pushes the assembled name
        // past 255 octets even though no single part of the message is oversized.
        byte[] tail = wireName(62);
        byte[] head = wireName(63, 63, 63);
        byte[] message = new byte[tail.length + head.length + 1];
        System.arraycopy(tail, 0, message, 0, tail.length);
        // Drop the root octet of the head so the pointer can take its place.
        System.arraycopy(head, 0, message, tail.length, head.length - 1);
        message[message.length - 2] = (byte) 0xc0;
        message[message.length - 1] = 0;
        assertDecodeFails(message, tail.length);
    }

    @Test
    public void testFromStringAndToStringRoundTripPlainNames() {
        DnsName name = DnsName.fromString("www.example.com.");
        assertEquals("www.example.com.", name.toString());
        assertEquals(3, name.labelCount());
        assertArrayEquals("www".getBytes(CharsetUtil.US_ASCII), name.label(0));
        assertArrayEquals("example".getBytes(CharsetUtil.US_ASCII), name.label(1));
        assertArrayEquals("com".getBytes(CharsetUtil.US_ASCII), name.label(2));
    }

    @Test
    public void testFromStringTreatsARelativeNameAsAbsolute() {
        assertEquals(DnsName.fromString("example.com."), DnsName.fromString("example.com"));
    }

    @Test
    public void testFromStringAcceptsTheRoot() {
        assertSame(DnsName.ROOT, DnsName.fromString("."));
        assertSame(DnsName.ROOT, DnsName.fromString(""));
    }

    @Test
    public void testFromStringDecodesDecimalEscapes() {
        DnsName name = DnsName.fromString("\\000\\255\\046.example.");
        assertArrayEquals(new byte[] { 0, (byte) 0xff, '.' }, name.label(0));
        assertEquals("\\000\\255\\046.example.", name.toString());
    }

    @Test
    public void testFromStringDecodesCharacterEscapes() {
        assertArrayEquals(new byte[] { 'a', '.', 'b' }, DnsName.fromString("a\\.b.example.").label(0));
        assertArrayEquals(new byte[] { '\\' }, DnsName.fromString("\\\\.example.").label(0));
        assertArrayEquals(new byte[] { '*' }, DnsName.fromString("\\*.example.").label(0));
    }

    @Test
    public void testToStringEscapesEverythingOutsideTheHostnameAlphabet() {
        // '*', '.', '\\' and every octet below 0x21 or above 0x7e become a \DDD escape; letters, digits, '-' and
        // '_' are left alone so ordinary names stay readable.
        assertEquals("\\042.example.", DnsName.fromString("*.example.").toString());
        assertEquals("a-b_c9.example.", DnsName.fromString("a-b_c9.example.").toString());
        assertEquals("\\032.example.", DnsName.fromString("\\032.example.").toString());
        assertEquals("\\127\\128.example.", DnsName.fromString("\\127\\128.example.").toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            ".a.example.",       // leading empty label
            "a..example.",       // interior empty label
            "a.example..",       // two trailing dots
            "a\\",               // dangling backslash
            "a\\12",             // truncated \DDD escape
            "a\\1x2.example.",   // malformed \DDD escape
            "\\256.example.",    // out-of-range \DDD escape
    })
    public void testFromStringRejectsMalformedInput(String name) {
        assertThrows(IllegalArgumentException.class, () -> DnsName.fromString(name));
    }

    @Test
    public void testFromStringRejectsANonOctetCharacter() {
        assertThrows(IllegalArgumentException.class, () -> DnsName.fromString("\u0100.example."));
    }

    @Test
    public void testFromStringRejectsAnOverlongLabel() {
        StringBuilder label = new StringBuilder();
        for (int i = 0; i < DnsName.MAX_LABEL_LENGTH; i++) {
            label.append('a');
        }
        assertEquals(DnsName.MAX_LABEL_LENGTH, DnsName.fromString(label + ".example.").label(0).length);
        assertThrows(IllegalArgumentException.class, () -> DnsName.fromString(label + "a.example."));
    }

    @Test
    public void testFromStringRejectsAnOverlongName() {
        assertEquals(DnsName.MAX_NAME_LENGTH, DnsName.fromString(presentationName(63, 63, 63, 61)).wireLength());
        assertThrows(IllegalArgumentException.class, () -> DnsName.fromString(presentationName(63, 63, 63, 62)));
    }

    @Test
    public void testPresentationFormRoundTripsArbitraryOctets() {
        Random random = new Random(0x4034);
        for (int i = 0; i < 2000; i++) {
            DnsName original = randomName(random);
            DnsName reparsed = DnsName.fromString(original.toString());
            assertEquals(original, reparsed);
            assertArrayEquals(original.toWireBytes(), reparsed.toWireBytes(),
                    "presentation form " + original + " did not round trip octet for octet");
            assertEquals(original.toString(), reparsed.toString());
        }
    }

    @Test
    public void testWriteToProducesTheUncompressedWireForm() {
        ByteBuf out = Unpooled.buffer();
        try {
            DnsName name = DnsName.fromString("netty.io.");
            name.writeTo(out);
            assertEquals(name.wireLength(), out.readableBytes());
            byte[] written = new byte[out.readableBytes()];
            out.readBytes(written);
            assertArrayEquals(new byte[] { 5, 'n', 'e', 't', 't', 'y', 2, 'i', 'o', 0 }, written);
        } finally {
            out.release();
        }
    }

    @Test
    public void testToWireBytesIsADefensiveCopy() {
        DnsName name = DnsName.fromString("netty.io.");
        byte[] wire = name.toWireBytes();
        wire[0] = 0;
        assertEquals("netty.io.", name.toString());
    }

    @Test
    public void testToLowerCaseFoldsOnlyTheTwentySixAsciiLetters() {
        // Exhaustive over every octet: only 0x41 to 0x5a moves, and it moves by exactly 0x20. This is what keeps
        // the canonical form independent of the default locale and of the Unicode case mappings, both of which
        // would fold octets such as 0xc0 or map 0x49 to something other than 0x69.
        for (int octet = 0; octet <= 0xff; octet++) {
            DnsName name = DnsName.fromString(escape(octet) + ".example.");
            int expected = octet >= 'A' && octet <= 'Z' ? octet + 0x20 : octet;
            assertArrayEquals(new byte[] { (byte) expected }, name.toLowerCase().label(0),
                    "octet 0x" + Integer.toHexString(octet) + " was folded incorrectly");
        }
    }

    @Test
    public void testToLowerCaseKeepsLengthOctetsIntact() {
        // A length octet is at most 63 and must never be touched, not even for a name whose labels are that long.
        ByteBuf in = Unpooled.wrappedBuffer(wireName(63, 63, 63, 61));
        try {
            DnsName lowerCase = DnsName.decode(in, 0, in.writerIndex()).toLowerCase();
            assertEquals(DnsName.MAX_NAME_LENGTH, lowerCase.wireLength());
            assertEquals(4, lowerCase.labelCount());
            assertEquals(63, lowerCase.label(0).length);
        } finally {
            in.release();
        }
    }

    @Test
    public void testToLowerCaseReturnsTheSameInstanceWhenNothingChanges() {
        DnsName name = DnsName.fromString("example.com.");
        assertSame(name, name.toLowerCase());
    }

    @Test
    public void testEqualsAndHashCodeIgnoreCase() {
        DnsName upperCase = DnsName.fromString("EXAMPLE.COM.");
        DnsName lowerCase = DnsName.fromString("example.com.");
        assertEquals(upperCase, lowerCase);
        assertEquals(upperCase.hashCode(), lowerCase.hashCode());

        Map<DnsName, String> map = new HashMap<DnsName, String>();
        map.put(lowerCase, "value");
        assertEquals("value", map.get(upperCase));
        assertEquals("value", map.get(DnsName.fromString("ExAmPlE.cOm.")));
    }

    @Test
    public void testEqualsDoesNotFoldNonAsciiOctets() {
        // 0xc0 is 'À' in ISO-8859-1 and 0xe0 is 'à', but DNS case folding is defined over 'A' to 'Z' only.
        assertNotEquals(DnsName.fromString("\\192.example."), DnsName.fromString("\\224.example."));
    }

    @Test
    public void testEqualsRejectsOtherTypes() {
        assertNotEquals(DnsName.fromString("example."), "example.");
        assertFalse(DnsName.fromString("example.").equals(null));
    }

    @Test
    public void testLabelAccessors() {
        DnsName name = DnsName.fromString("www.example.com.");
        assertEquals(3, name.labelCount());
        assertEquals("example.com.", name.parent().toString());
        assertEquals("com.", name.parent().parent().toString());
        assertEquals(".", name.parent().parent().parent().toString());
        assertEquals(".", name.parent().parent().parent().parent().toString());

        assertEquals("www.example.com.", name.stripLeftmostLabels(0).toString());
        assertEquals("com.", name.stripLeftmostLabels(2).toString());
        assertEquals(DnsName.ROOT, name.stripLeftmostLabels(3));
        assertThrows(IllegalArgumentException.class, () -> name.stripLeftmostLabels(4));
        assertThrows(IllegalArgumentException.class, () -> name.stripLeftmostLabels(-1));

        assertThrows(IndexOutOfBoundsException.class, () -> name.label(3));
        assertThrows(IndexOutOfBoundsException.class, () -> name.label(-1));
        assertThrows(IndexOutOfBoundsException.class, () -> DnsName.ROOT.label(0));
    }

    @Test
    public void testLabelIsADefensiveCopy() {
        DnsName name = DnsName.fromString("www.example.com.");
        name.label(0)[0] = 'x';
        assertEquals("www.example.com.", name.toString());
    }

    @Test
    public void testToWildcard() {
        assertEquals(DnsName.fromString("*.example.com."), DnsName.fromString("example.com.").toWildcard());
        assertEquals(DnsName.fromString("*."), DnsName.ROOT.toWildcard());
        assertThrows(IllegalArgumentException.class,
                () -> DnsName.fromString(presentationName(63, 63, 63, 61)).toWildcard());
    }

    @Test
    public void testSubDomainTests() {
        DnsName child = DnsName.fromString("a.b.example.com.");
        DnsName parent = DnsName.fromString("B.EXAMPLE.COM.");
        DnsName sibling = DnsName.fromString("c.example.com.");

        assertTrue(child.equalsOrIsSubDomainOf(parent));
        assertTrue(child.isStrictSubDomainOf(parent));
        assertTrue(child.equalsOrIsSubDomainOf(child));
        assertFalse(child.isStrictSubDomainOf(child));
        assertFalse(parent.equalsOrIsSubDomainOf(child));
        assertFalse(child.equalsOrIsSubDomainOf(sibling));

        assertTrue(child.equalsOrIsSubDomainOf(DnsName.ROOT));
        assertTrue(child.isStrictSubDomainOf(DnsName.ROOT));
        assertTrue(DnsName.ROOT.equalsOrIsSubDomainOf(DnsName.ROOT));
        assertFalse(DnsName.ROOT.isStrictSubDomainOf(DnsName.ROOT));
    }

    @Test
    public void testSubDomainTestIsAlignedToLabelBoundaries() {
        // "notexample.com." ends with the octets of "example.com." but is not below it.
        assertFalse(DnsName.fromString("notexample.com.")
                .equalsOrIsSubDomainOf(DnsName.fromString("example.com.")));
    }

    @Test
    public void testCanonicalOrderReproducesTheRfc4034Vector() {
        List<DnsName> expected = parseAll(RFC4034_CANONICAL_ORDER);
        for (long seed = 0; seed < 64; seed++) {
            List<DnsName> shuffled = new ArrayList<DnsName>(expected);
            Collections.shuffle(shuffled, new Random(seed));
            Collections.sort(shuffled, DnsName.CANONICAL_ORDER);
            assertEquals(toStrings(expected), toStrings(shuffled), "seed " + seed);
        }
    }

    @Test
    public void testCanonicalOrderIsATotalOrderOnTheRfc4034Vector() {
        List<DnsName> names = parseAll(RFC4034_CANONICAL_ORDER);
        assertTotalOrder(names);
    }

    @Test
    public void testCanonicalOrderComparesLabelsAsUnsignedOctets() {
        // 0x80 is above '*' (0x2a) unsigned but below it if the octet were read as a signed byte.
        assertTrue(DnsName.CANONICAL_ORDER.compare(
                DnsName.fromString("*.z.example."), DnsName.fromString("\\200.z.example.")) < 0);
    }

    @Test
    public void testCanonicalOrderTreatsAMissingOctetAsSortingBeforeAZeroOctet() {
        assertTrue(DnsName.CANONICAL_ORDER.compare(
                DnsName.fromString("a.example."), DnsName.fromString("a\\000.example.")) < 0);
    }

    @Test
    public void testCanonicalOrderIsConsistentWithEquals() {
        assertEquals(0, DnsName.CANONICAL_ORDER.compare(
                DnsName.fromString("EXAMPLE.com."), DnsName.fromString("example.COM.")));
    }

    @Test
    public void testCanonicalOrderIsATotalOrderOnRandomNames() {
        Random random = new Random(0x6001);
        List<DnsName> names = new ArrayList<DnsName>();
        for (int i = 0; i < 60; i++) {
            names.add(randomName(random));
        }
        assertTotalOrder(names);
    }

    private static void assertTotalOrder(List<DnsName> names) {
        for (DnsName a : names) {
            for (DnsName b : names) {
                int ab = signum(DnsName.CANONICAL_ORDER.compare(a, b));
                int ba = signum(DnsName.CANONICAL_ORDER.compare(b, a));
                assertEquals(-ab, ba, "not antisymmetric: " + a + " and " + b);
                assertEquals(ab == 0, a.equals(b), "compare and equals disagree on " + a + " and " + b);
                for (DnsName c : names) {
                    int bc = signum(DnsName.CANONICAL_ORDER.compare(b, c));
                    if (ab <= 0 && bc <= 0) {
                        assertTrue(signum(DnsName.CANONICAL_ORDER.compare(a, c)) <= 0,
                                "not transitive: " + a + ", " + b + ", " + c);
                    }
                }
            }
        }
    }

    private static int signum(int value) {
        return value < 0 ? -1 : value > 0 ? 1 : 0;
    }

    private static List<DnsName> parseAll(String[] names) {
        List<DnsName> parsed = new ArrayList<DnsName>(names.length);
        for (String name : names) {
            parsed.add(DnsName.fromString(name));
        }
        return parsed;
    }

    private static List<String> toStrings(List<DnsName> names) {
        List<String> strings = new ArrayList<String>(names.size());
        for (DnsName name : names) {
            strings.add(name.toString());
        }
        return strings;
    }

    private static DnsName randomName(Random random) {
        StringBuilder buf = new StringBuilder();
        int labels = 1 + random.nextInt(4);
        for (int i = 0; i < labels; i++) {
            int length = 1 + random.nextInt(6);
            for (int j = 0; j < length; j++) {
                int octet = random.nextInt(4) == 0
                        ? INTERESTING_OCTETS[random.nextInt(INTERESTING_OCTETS.length)]
                        : random.nextInt(256);
                buf.append(escape(octet));
            }
            buf.append('.');
        }
        return DnsName.fromString(buf.toString());
    }

    private static String escape(int octet) {
        return "\\" + (char) ('0' + octet / 100) + (char) ('0' + octet / 10 % 10) + (char) ('0' + octet % 10);
    }

    private static byte[] wireName(int... labelLengths) {
        int length = 1;
        for (int labelLength : labelLengths) {
            length += 1 + labelLength;
        }
        byte[] wire = new byte[length];
        int pos = 0;
        for (int labelLength : labelLengths) {
            wire[pos++] = (byte) labelLength;
            Arrays.fill(wire, pos, pos + labelLength, (byte) 'a');
            pos += labelLength;
        }
        return wire;
    }

    private static String presentationName(int... labelLengths) {
        StringBuilder buf = new StringBuilder();
        for (int labelLength : labelLengths) {
            for (int i = 0; i < labelLength; i++) {
                buf.append('a');
            }
            buf.append('.');
        }
        return buf.toString();
    }

    private static void assertDecodeFails(byte[] message, int offset) {
        ByteBuf in = Unpooled.wrappedBuffer(message);
        try {
            assertThrows(CorruptedFrameException.class, () -> DnsName.decode(in, offset, in.writerIndex()));
        } finally {
            in.release();
        }
    }
}
