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
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.util.internal.ObjectUtil;

import java.util.Comparator;

/**
 * An immutable domain name held in its uncompressed
 * <a href="https://www.rfc-editor.org/rfc/rfc1035.html#section-3.1">RFC 1035, section 3.1</a> wire form: a sequence
 * of length-prefixed labels terminated by a zero octet.
 * <p>
 * DNSSEC signatures are computed over the exact octets of a name, so a name that takes part in validation must never
 * be round-tripped through a {@link String}. {@link DnsRecord#name()} decodes label octets
 * as UTF-8, which is lossy for the arbitrary octets a label may legally contain, and is therefore unusable for that
 * purpose. This type keeps the octets and only converts to and from a {@link String} through the escaped presentation
 * form of <a href="https://www.rfc-editor.org/rfc/rfc1035.html#section-5.1">RFC 1035, section 5.1</a>, which is
 * lossless.
 * <p>
 * Instances are immutable and safe to share between threads. {@link #equals(Object)} and {@link #hashCode()} treat
 * {@code A} to {@code Z} as equal to {@code a} to {@code z}, matching the case-insensitive comparison that
 * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-6.1">RFC 4034, section 6.1</a> mandates, so a
 * {@code DnsName} is a safe key in a {@link java.util.HashMap}.
 */
public final class DnsName {

    /**
     * The maximum length of a single label in octets, see
     * <a href="https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4">RFC 1035, section 2.3.4</a>.
     */
    public static final int MAX_LABEL_LENGTH = 63;

    /**
     * The maximum length of a whole name in octets, including every length octet and the zero octet that
     * terminates it. See <a href="https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4">RFC 1035,
     * section 2.3.4</a>.
     */
    public static final int MAX_NAME_LENGTH = 255;

    /**
     * The root of the DNS name space, written {@code "."}.
     */
    public static final DnsName ROOT = new DnsName(new byte[] { 0 });

    /**
     * Orders names in the DNS canonical order of
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-6.1">RFC 4034, section 6.1</a>, which is the
     * order the owner names of an NSEC chain are in and the order in which the RRs of an RRset are sorted before
     * they are signed.
     * <p>
     * Names are compared label by label, starting with the rightmost label. Each label is compared as an unsigned,
     * left-justified octet string with {@code A} to {@code Z} treated as {@code a} to {@code z}; where one label is
     * a prefix of the other the shorter one sorts first, because "the absence of an octet sorts before a zero value
     * octet". A name with fewer labels sorts before a name that extends it.
     * <p>
     * This ordering is consistent with {@link #equals(Object)}.
     */
    public static final Comparator<DnsName> CANONICAL_ORDER = new CanonicalOrder();

    /**
     * The number of compression pointers a single name may be assembled from. Pointers are already required to
     * point strictly backwards, which by itself bounds the work, but a low explicit cap keeps a name that is spread
     * over dozens of pointers from turning into a random-access scan of the whole message.
     */
    private static final int MAX_POINTER_HOPS = 16;

    private final byte[] name;
    private int hash;

    private DnsName(byte[] name) {
        this.name = name;
    }

    /**
     * Decodes the name that starts at {@code offset}, following any compression pointers, and returns it in
     * uncompressed form. Neither the reader index nor the writer index of {@code in} is modified.
     *
     * @param in         the buffer holding the whole DNS message; compression pointers are resolved against it
     * @param offset     the absolute index the name starts at
     * @param messageEnd the absolute index one past the last octet of the message, which bounds every read
     * @throws CorruptedFrameException if the name is truncated, longer than {@value #MAX_NAME_LENGTH} octets, uses a
     *                                 reserved label type, or contains a pointer that does not point strictly
     *                                 backwards
     */
    public static DnsName decode(ByteBuf in, int offset, int messageEnd) {
        ObjectUtil.checkNotNull(in, "in");
        byte[] scratch = new byte[MAX_NAME_LENGTH];
        int length = assemble(in, offset, messageEnd, scratch);
        byte[] wire = new byte[length];
        System.arraycopy(scratch, 0, wire, 0, length);
        return new DnsName(wire);
    }

    /**
     * Decodes the name that starts at {@code in.readerIndex()} and advances the reader index past it. The name
     * occupies two octets in the buffer when it is a compression pointer, however many labels it expands to.
     *
     * @param in         the buffer holding the whole DNS message, positioned at the start of the name
     * @param messageEnd the absolute index one past the last octet of the message, which bounds every read
     * @throws CorruptedFrameException if the name is malformed, see {@link #decode(ByteBuf, int, int)}
     */
    public static DnsName decode(ByteBuf in, int messageEnd) {
        ObjectUtil.checkNotNull(in, "in");
        int offset = in.readerIndex();
        DnsName decoded = decode(in, offset, messageEnd);
        in.readerIndex(offset + encodedLength(in, offset, messageEnd));
        return decoded;
    }

    /**
     * Returns the number of octets the name at {@code offset} occupies in {@code in}, which is two for a name that
     * is a compression pointer and the uncompressed length for a name that is not compressed. Neither the reader
     * index nor the writer index of {@code in} is modified.
     *
     * @throws CorruptedFrameException if the name is truncated or uses a reserved label type
     */
    public static int encodedLength(ByteBuf in, int offset, int messageEnd) {
        ObjectUtil.checkNotNull(in, "in");
        checkMessageEnd(in, messageEnd);
        int pos = offset;
        for (;;) {
            if (pos < 0 || pos >= messageEnd) {
                throw new CorruptedFrameException("truncated domain name at offset " + pos);
            }
            int len = in.getUnsignedByte(pos);
            int labelType = len & 0xc0;
            if (labelType == 0xc0) {
                if (pos + 1 >= messageEnd) {
                    throw new CorruptedFrameException("truncated compression pointer at offset " + pos);
                }
                return pos + 2 - offset;
            }
            if (labelType != 0) {
                throw reservedLabelType(labelType, pos);
            }
            if (len == 0) {
                return pos + 1 - offset;
            }
            pos += 1 + len;
        }
    }

    /**
     * Parses the escaped presentation form of
     * <a href="https://www.rfc-editor.org/rfc/rfc1035.html#section-5.1">RFC 1035, section 5.1</a>: labels separated
     * by {@code '.'}, where {@code \DDD} is the octet with the decimal value {@code DDD} and {@code \X} is the octet
     * {@code X} itself. An empty string and {@code "."} both denote the root. A single trailing {@code '.'} is
     * accepted and ignored; the name is always absolute either way.
     *
     * @throws IllegalArgumentException if the name is malformed, has an empty label, has a label longer than
     *                                 {@value #MAX_LABEL_LENGTH} octets, or is longer than
     *                                 {@value #MAX_NAME_LENGTH} octets in wire form
     */
    public static DnsName fromString(String name) {
        ObjectUtil.checkNotNull(name, "name");
        final int end = name.length();
        if (end == 0 || ".".equals(name)) {
            return ROOT;
        }
        byte[] wire = new byte[MAX_NAME_LENGTH];
        int length = 0;
        int i = 0;
        while (i < end) {
            if (length + 2 > MAX_NAME_LENGTH) {
                throw nameTooLong(name);
            }
            final int lengthIndex = length++;
            int labelLength = 0;
            boolean separated = false;
            while (i < end) {
                char c = name.charAt(i++);
                if (c == '.') {
                    separated = true;
                    break;
                }
                int octet;
                if (c == '\\') {
                    if (i >= end) {
                        throw new IllegalArgumentException("DNS name ends with a dangling '\\': " + name);
                    }
                    char escaped = name.charAt(i++);
                    if (escaped >= '0' && escaped <= '9') {
                        if (i + 1 >= end) {
                            throw new IllegalArgumentException("DNS name contains a truncated \\DDD escape: " + name);
                        }
                        char tens = name.charAt(i++);
                        char ones = name.charAt(i++);
                        if (tens < '0' || tens > '9' || ones < '0' || ones > '9') {
                            throw new IllegalArgumentException("DNS name contains a malformed \\DDD escape: " + name);
                        }
                        octet = (escaped - '0') * 100 + (tens - '0') * 10 + (ones - '0');
                        if (octet > 0xff) {
                            throw new IllegalArgumentException(
                                    "DNS name contains an out-of-range \\DDD escape: " + name);
                        }
                    } else {
                        octet = escaped;
                    }
                } else {
                    octet = c;
                }
                if (octet > 0xff) {
                    throw new IllegalArgumentException("DNS name contains the non-octet character U+"
                            + Integer.toHexString(octet) + ", which must be written as a \\DDD escape: " + name);
                }
                if (++labelLength > MAX_LABEL_LENGTH) {
                    throw new IllegalArgumentException("DNS name contains a label longer than " + MAX_LABEL_LENGTH
                            + " octets: " + name);
                }
                if (length + 2 > MAX_NAME_LENGTH) {
                    throw nameTooLong(name);
                }
                wire[length++] = (byte) octet;
            }
            if (labelLength == 0) {
                throw new IllegalArgumentException("DNS name contains an empty label: " + name);
            }
            wire[lengthIndex] = (byte) labelLength;
            if (separated && i == end) {
                // A single trailing '.' just terminates the name.
                break;
            }
        }
        wire[length++] = 0;
        byte[] result = new byte[length];
        System.arraycopy(wire, 0, result, 0, length);
        return new DnsName(result);
    }

    /**
     * Returns {@code true} if this is the root name.
     */
    public boolean isRoot() {
        return name.length == 1;
    }

    /**
     * Returns the number of labels this name has, not counting the root. The root itself has {@code 0} labels and
     * {@code www.example.com.} has {@code 3}.
     */
    public int labelCount() {
        int count = 0;
        int pos = 0;
        while (name[pos] != 0) {
            count++;
            pos += 1 + (name[pos] & 0xff);
        }
        return count;
    }

    /**
     * Returns a copy of the octets of the label at {@code index}, counted from the left, so that {@code label(0)}
     * of {@code www.example.com.} is {@code www}. This is how the leftmost label of an NSEC3 owner name is obtained
     * before it is base32hex-decoded back into the hash it encodes.
     *
     * @throws IndexOutOfBoundsException if {@code index} is negative or is not less than {@link #labelCount()}
     */
    public byte[] label(int index) {
        int pos = labelOffset(index);
        if (name[pos] == 0) {
            throw new IndexOutOfBoundsException("index: " + index + " (expected: 0 <= index < " + labelCount() + ')');
        }
        int length = name[pos] & 0xff;
        byte[] label = new byte[length];
        System.arraycopy(name, pos + 1, label, 0, length);
        return label;
    }

    /**
     * Returns this name with its leftmost label removed. The parent of the root is the root.
     */
    public DnsName parent() {
        if (isRoot()) {
            return this;
        }
        return suffix(1 + (name[0] & 0xff));
    }

    /**
     * Returns this name with its {@code count} leftmost labels removed.
     *
     * @throws IllegalArgumentException if {@code count} is negative or greater than {@link #labelCount()}
     */
    public DnsName stripLeftmostLabels(int count) {
        ObjectUtil.checkPositiveOrZero(count, "count");
        int pos = 0;
        for (int i = 0; i < count; i++) {
            if (name[pos] == 0) {
                throw new IllegalArgumentException("cannot strip " + count + " labels from " + this + ", which has "
                        + labelCount() + " labels");
            }
            pos += 1 + (name[pos] & 0xff);
        }
        return pos == 0 ? this : suffix(pos);
    }

    /**
     * Returns the wildcard name {@code *.} followed by this name, which is the owner name a wildcard covering this
     * name's children would have, see
     * <a href="https://www.rfc-editor.org/rfc/rfc4592.html#section-2.1.1">RFC 4592, section 2.1.1</a>.
     *
     * @throws IllegalArgumentException if prepending the label would push the name past {@value #MAX_NAME_LENGTH}
     *                                 octets
     */
    public DnsName toWildcard() {
        if (name.length + 2 > MAX_NAME_LENGTH) {
            throw new IllegalArgumentException("cannot prepend a wildcard label to " + this
                    + ", the result would be longer than " + MAX_NAME_LENGTH + " octets");
        }
        byte[] wildcard = new byte[name.length + 2];
        wildcard[0] = 1;
        wildcard[1] = '*';
        System.arraycopy(name, 0, wildcard, 2, name.length);
        return new DnsName(wildcard);
    }

    /**
     * Returns {@code true} if this name is {@code ancestor} or lies below it, so
     * {@code a.example.equalsOrIsSubDomainOf(example)} and {@code example.equalsOrIsSubDomainOf(example)} are both
     * {@code true}. Every name is at or below the root.
     */
    public boolean equalsOrIsSubDomainOf(DnsName ancestor) {
        ObjectUtil.checkNotNull(ancestor, "ancestor");
        int extraLabels = labelCount() - ancestor.labelCount();
        if (extraLabels < 0) {
            return false;
        }
        return suffixEqualsIgnoreCase(labelOffset(extraLabels), ancestor);
    }

    /**
     * Returns {@code true} if this name lies strictly below {@code ancestor}, that is, if it is at or below it and
     * is not equal to it.
     */
    public boolean isStrictSubDomainOf(DnsName ancestor) {
        ObjectUtil.checkNotNull(ancestor, "ancestor");
        return labelCount() > ancestor.labelCount() && equalsOrIsSubDomainOf(ancestor);
    }

    /**
     * Returns this name in the canonical form of
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-6.2">RFC 4034, section 6.2</a>: every octet in
     * the inclusive range {@code 'A'} to {@code 'Z'} replaced by the octet {@code 0x20} above it, and every other
     * octet left exactly as it is.
     * <p>
     * This deliberately does not go through {@link String#toLowerCase()} or {@link Character#toLowerCase(char)}.
     * Signatures are computed over these octets, so the mapping has to be the fixed 26-letter one the RFC defines
     * and must not vary with the default locale or follow the Unicode case mappings.
     * <p>
     * <strong>Which names to apply this to is the caller's decision, and the published list is wrong.</strong> The
     * owner name of an RR is always downcased (RFC 4034, section 6.2, item 2), but for names embedded in RDATA the
     * type code list in item 3 has two known errors, both corrected by
     * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.1">RFC 6840, section 5.1</a>:
     * <ul>
     *   <li>names in <em>NSEC</em> RDATA are <em>not</em> downcased, even though item 3 lists NSEC. Names in RRSIG
     *       RDATA are. Downcasing an NSEC {@code Next Domain Name} makes every signature over a mixed-case NSEC
     *       fail, which shows up as a spurious BOGUS on a zone that is in fact correctly signed;</li>
     *   <li>HINFO is listed, twice, but holds no domain name at all and is not subject to case conversion. See
     *       also <a href="https://www.rfc-editor.org/errata/eid1062">RFC 4034 erratum 1062</a>, which notes that
     *       the list was copied from <a href="https://www.rfc-editor.org/rfc/rfc3597.html#section-7">RFC 3597,
     *       section 7</a> along with the duplicate.</li>
     * </ul>
     */
    public DnsName toLowerCase() {
        int i = 0;
        // A length octet is at most 63 (0x3f) and can therefore never fall in the [0x41, 0x5a] range that is
        // rewritten here, so a single pass over the whole wire form touches label octets only.
        while (i < name.length && !isUpperCase(name[i])) {
            i++;
        }
        if (i == name.length) {
            return this;
        }
        byte[] lowerCase = name.clone();
        for (; i < lowerCase.length; i++) {
            if (isUpperCase(lowerCase[i])) {
                lowerCase[i] += 'a' - 'A';
            }
        }
        return new DnsName(lowerCase);
    }

    /**
     * Returns the number of octets the uncompressed wire form of this name occupies.
     */
    public int wireLength() {
        return name.length;
    }

    /**
     * Writes the uncompressed wire form of this name to {@code out}. Compression is never applied: a name inside the
     * RDATA of a DNSSEC record must not be compressed, see
     * <a href="https://www.rfc-editor.org/rfc/rfc3597.html#section-4">RFC 3597, section 4</a>.
     */
    public void writeTo(ByteBuf out) {
        ObjectUtil.checkNotNull(out, "out").writeBytes(name);
    }

    /**
     * Returns a copy of the uncompressed wire form of this name.
     */
    public byte[] toWireBytes() {
        return name.clone();
    }

    /**
     * Returns the escaped presentation form of this name, always ending with the root {@code '.'}. Every octet
     * outside {@code [0-9A-Za-z_-]} is written as a {@code \DDD} escape, so the result is unambiguous and
     * {@link #fromString(String)} maps it back to exactly these octets.
     */
    @Override
    public String toString() {
        if (isRoot()) {
            return ".";
        }
        StringBuilder buf = new StringBuilder(name.length << 2);
        int pos = 0;
        while (name[pos] != 0) {
            int length = name[pos] & 0xff;
            for (int i = pos + 1, labelEnd = pos + 1 + length; i < labelEnd; i++) {
                appendOctet(buf, name[i] & 0xff);
            }
            buf.append('.');
            pos += 1 + length;
        }
        return buf.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DnsName)) {
            return false;
        }
        // Case folding never changes the length, so names of different lengths can never be equal.
        byte[] other = ((DnsName) obj).name;
        if (other.length != name.length) {
            return false;
        }
        for (int i = 0; i < name.length; i++) {
            if (toLowerCase(name[i]) != toLowerCase(other[i])) {
                return false;
            }
        }
        return true;
    }

    @Override
    public int hashCode() {
        int h = hash;
        if (h == 0) {
            for (byte b : name) {
                h = 31 * h + toLowerCase(b);
            }
            hash = h;
        }
        return h;
    }

    /**
     * Assembles the name that starts at {@code offset} into {@code dst} and returns its length in octets.
     */
    private static int assemble(ByteBuf in, int offset, int messageEnd, byte[] dst) {
        checkMessageEnd(in, messageEnd);
        int pos = offset;
        int length = 0;
        int hops = 0;
        for (;;) {
            if (pos < 0 || pos >= messageEnd) {
                throw new CorruptedFrameException("truncated domain name at offset " + pos);
            }
            int len = in.getUnsignedByte(pos);
            int labelType = len & 0xc0;
            if (labelType == 0xc0) {
                if (pos + 1 >= messageEnd) {
                    throw new CorruptedFrameException("truncated compression pointer at offset " + pos);
                }
                int target = ((len & 0x3f) << 8) | in.getUnsignedByte(pos + 1);
                // RFC 1035 does not spell this out, but a pointer that does not point strictly backwards is either
                // part of a loop or names octets the sender had not written yet, so no legitimate encoder emits one.
                // Requiring it to point backwards makes the walk strictly decreasing and therefore terminating.
                if (target >= pos) {
                    throw new CorruptedFrameException("compression pointer at offset " + pos
                            + " points to " + target + " instead of strictly backwards");
                }
                if (++hops > MAX_POINTER_HOPS) {
                    throw new CorruptedFrameException("domain name follows more than " + MAX_POINTER_HOPS
                            + " compression pointers");
                }
                pos = target;
                continue;
            }
            if (labelType != 0) {
                throw reservedLabelType(labelType, pos);
            }
            if (len == 0) {
                dst[length++] = 0;
                return length;
            }
            // len cannot exceed MAX_LABEL_LENGTH here, its two most significant bits are known to be zero.
            if (pos + 1 + len > messageEnd) {
                throw new CorruptedFrameException("truncated label at offset " + pos);
            }
            // One octet for the length prefix and one for the root label that will terminate the name.
            if (length + len + 2 > MAX_NAME_LENGTH) {
                throw new CorruptedFrameException("domain name is longer than " + MAX_NAME_LENGTH + " octets");
            }
            dst[length++] = (byte) len;
            in.getBytes(pos + 1, dst, length, len);
            length += len;
            pos += 1 + len;
        }
    }

    private static void checkMessageEnd(ByteBuf in, int messageEnd) {
        if (messageEnd > in.writerIndex()) {
            throw new CorruptedFrameException("messageEnd " + messageEnd + " is past the end of the buffer, which is "
                    + in.writerIndex());
        }
    }

    private static CorruptedFrameException reservedLabelType(int labelType, int offset) {
        // 0x40 and 0x80 are reserved, see RFC 1035 section 4.1.4 and RFC 6891 section 6.1.
        return new CorruptedFrameException("reserved label type 0x" + Integer.toHexString(labelType)
                + " at offset " + offset);
    }

    private static IllegalArgumentException nameTooLong(String name) {
        return new IllegalArgumentException("DNS name is longer than " + MAX_NAME_LENGTH + " octets in wire form: "
                + name);
    }

    private static void appendOctet(StringBuilder buf, int octet) {
        if (octet >= '0' && octet <= '9' || octet >= 'A' && octet <= 'Z' || octet >= 'a' && octet <= 'z'
                || octet == '-' || octet == '_') {
            buf.append((char) octet);
            return;
        }
        buf.append('\\')
           .append((char) ('0' + octet / 100))
           .append((char) ('0' + octet / 10 % 10))
           .append((char) ('0' + octet % 10));
    }

    private static boolean isUpperCase(byte b) {
        return b >= 'A' && b <= 'Z';
    }

    private static byte toLowerCase(byte b) {
        return isUpperCase(b) ? (byte) (b + ('a' - 'A')) : b;
    }

    /**
     * Returns the offset of the length octet of the {@code index}-th label counted from the left. An {@code index}
     * equal to {@link #labelCount()} yields the offset of the terminating zero octet.
     */
    private int labelOffset(int index) {
        if (index < 0) {
            throw new IndexOutOfBoundsException("index: " + index + " (expected: >= 0)");
        }
        int pos = 0;
        for (int i = 0; i < index; i++) {
            if (name[pos] == 0) {
                throw new IndexOutOfBoundsException("index: " + index + " (expected: 0 <= index <= " + labelCount()
                        + ')');
            }
            pos += 1 + (name[pos] & 0xff);
        }
        return pos;
    }

    private DnsName suffix(int offset) {
        byte[] wire = new byte[name.length - offset];
        System.arraycopy(name, offset, wire, 0, wire.length);
        return new DnsName(wire);
    }

    private boolean suffixEqualsIgnoreCase(int offset, DnsName other) {
        byte[] suffix = other.name;
        if (name.length - offset != suffix.length) {
            return false;
        }
        for (int i = 0; i < suffix.length; i++) {
            if (toLowerCase(name[offset + i]) != toLowerCase(suffix[i])) {
                return false;
            }
        }
        return true;
    }

    private static final class CanonicalOrder implements Comparator<DnsName> {

        @Override
        public int compare(DnsName left, DnsName right) {
            if (left == right) {
                return 0;
            }
            int leftCount = left.labelCount();
            int rightCount = right.labelCount();
            int common = Math.min(leftCount, rightCount);
            // A name holds at most 127 labels, so walking to each label from the left stays cheap even though it
            // makes this quadratic in the number of labels.
            for (int i = 1; i <= common; i++) {
                int cmp = compareLabel(left, left.labelOffset(leftCount - i), right, right.labelOffset(rightCount - i));
                if (cmp != 0) {
                    return cmp;
                }
            }
            // Every label the two names share is equal, so the shorter name is a suffix of the longer one and
            // therefore sorts first.
            return leftCount - rightCount;
        }

        private static int compareLabel(DnsName left, int leftOffset, DnsName right, int rightOffset) {
            byte[] leftName = left.name;
            byte[] rightName = right.name;
            int leftLength = leftName[leftOffset] & 0xff;
            int rightLength = rightName[rightOffset] & 0xff;
            int common = Math.min(leftLength, rightLength);
            for (int i = 1; i <= common; i++) {
                int cmp = (toLowerCase(leftName[leftOffset + i]) & 0xff)
                        - (toLowerCase(rightName[rightOffset + i]) & 0xff);
                if (cmp != 0) {
                    return cmp;
                }
            }
            // "The absence of an octet sorts before a zero value octet", so the shorter label sorts first.
            return leftLength - rightLength;
        }
    }
}
