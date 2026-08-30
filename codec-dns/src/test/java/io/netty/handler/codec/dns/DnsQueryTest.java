/*
 * Copyright 2013 The Netty Project
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

import io.netty.channel.embedded.EmbeddedChannel;

import io.netty.channel.socket.DatagramPacket;
import io.netty.util.internal.SocketUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnsQueryTest {

    static Stream<DnsOpCode> opCodes() {
        return Stream.of(
                DnsOpCode.QUERY,
                DnsOpCode.IQUERY,
                DnsOpCode.STATUS,
                DnsOpCode.NOTIFY,
                DnsOpCode.UPDATE);
    }

    static Stream<Arguments> opCodesAndExpectedFlags() {
        return Stream.of(
                // RFC 1035 section 4.1.1: QR(1) OPCODE(4) AA TC RD RA Z(3) RCODE(4), so the OPCODE
                // occupies bits 14-11 and RD is bit 8.
                Arguments.of(DnsOpCode.QUERY, false, 0x0000),
                Arguments.of(DnsOpCode.QUERY, true, 0x0100),
                Arguments.of(DnsOpCode.IQUERY, false, 0x0800),
                Arguments.of(DnsOpCode.IQUERY, true, 0x0900),
                Arguments.of(DnsOpCode.STATUS, false, 0x1000),
                Arguments.of(DnsOpCode.STATUS, true, 0x1100),
                Arguments.of(DnsOpCode.NOTIFY, false, 0x2000),
                Arguments.of(DnsOpCode.NOTIFY, true, 0x2100),
                Arguments.of(DnsOpCode.UPDATE, false, 0x2800),
                Arguments.of(DnsOpCode.UPDATE, true, 0x2900),

                // DnsOpCode does not range check, and an OPCODE that does not fit the four bits
                // reserved for it must not reach the neighbouring QR bit.
                Arguments.of(DnsOpCode.valueOf(16), false, 0x0000));
    }

    static Stream<Arguments> zValuesAndExpectedFlags() {
        return Stream.of(
                // RFC 1035 section 4.1.1 puts Z at bits 6-4. RFC 4035 then assigned the low two of those
                // three bits: AD is bit 5 and CD is bit 4, leaving only bit 6 reserved.
                Arguments.of(0, 0x0000),
                Arguments.of(1, 0x0010),   // CD
                Arguments.of(2, 0x0020),   // AD
                Arguments.of(3, 0x0030),   // AD + CD
                Arguments.of(4, 0x0040),   // the still-reserved bit
                Arguments.of(7, 0x0070));
    }

    @Test
    public void testEncodeAndDecodeQuery() {
        InetSocketAddress addr = SocketUtils.socketAddress("8.8.8.8", 53);
        EmbeddedChannel writeChannel = new EmbeddedChannel(new DatagramDnsQueryEncoder());
        EmbeddedChannel readChannel = new EmbeddedChannel(new DatagramDnsQueryDecoder());

        List<DnsQuery> queries = new ArrayList<DnsQuery>(5);
        queries.add(new DatagramDnsQuery(null, addr, 1).setRecord(
                DnsSection.QUESTION,
                new DefaultDnsQuestion("1.0.0.127.in-addr.arpa", DnsRecordType.PTR)));
        queries.add(new DatagramDnsQuery(null, addr, 1).setRecord(
                DnsSection.QUESTION,
                new DefaultDnsQuestion("www.example.com", DnsRecordType.A)));
        queries.add(new DatagramDnsQuery(null, addr, 1).setRecord(
                DnsSection.QUESTION,
                new DefaultDnsQuestion("example.com", DnsRecordType.AAAA)));
        queries.add(new DatagramDnsQuery(null, addr, 1).setRecord(
                DnsSection.QUESTION,
                new DefaultDnsQuestion("example.com", DnsRecordType.MX)));
        queries.add(new DatagramDnsQuery(null, addr, 1).setRecord(
                DnsSection.QUESTION,
                new DefaultDnsQuestion("example.com", DnsRecordType.CNAME)));

        for (DnsQuery query: queries) {
            assertEquals(1, query.count(DnsSection.QUESTION));
            assertEquals(0, query.count(DnsSection.ANSWER));
            assertEquals(0, query.count(DnsSection.AUTHORITY));
            assertEquals(0, query.count(DnsSection.ADDITIONAL));

            assertTrue(writeChannel.writeOutbound(query));

            DatagramPacket packet = writeChannel.readOutbound();
            assertTrue(packet.content().isReadable());
            assertTrue(readChannel.writeInbound(packet));

            DnsQuery decodedDnsQuery = readChannel.readInbound();
            assertEquals(query, decodedDnsQuery);
            assertTrue(decodedDnsQuery.release());

            assertNull(writeChannel.readOutbound());
            assertNull(readChannel.readInbound());
        }

        assertFalse(writeChannel.finish());
        assertFalse(readChannel.finish());
    }

    @ParameterizedTest
    @MethodSource("opCodes")
    public void testOpCodeSurvivesEncodeAndDecode(DnsOpCode opCode) {
        InetSocketAddress addr = SocketUtils.socketAddress("8.8.8.8", 53);
        EmbeddedChannel writeChannel = new EmbeddedChannel(new DatagramDnsQueryEncoder());
        EmbeddedChannel readChannel = new EmbeddedChannel(new DatagramDnsQueryDecoder());

        DnsQuery query = new DatagramDnsQuery(null, addr, 1, opCode).setRecord(
                DnsSection.QUESTION,
                new DefaultDnsQuestion("example.com", DnsRecordType.A));

        assertTrue(writeChannel.writeOutbound(query));
        DatagramPacket packet = writeChannel.readOutbound();
        assertTrue(readChannel.writeInbound(packet));

        DnsQuery decodedDnsQuery = readChannel.readInbound();
        assertEquals(opCode, decodedDnsQuery.opCode());
        assertTrue(decodedDnsQuery.release());

        assertFalse(writeChannel.finish());
        assertFalse(readChannel.finish());
    }

    @ParameterizedTest
    @MethodSource("opCodesAndExpectedFlags")
    public void testOpCodeIsEncodedIntoBits14To11(DnsOpCode opCode, boolean recursionDesired, int expectedFlags) {
        InetSocketAddress addr = SocketUtils.socketAddress("8.8.8.8", 53);
        EmbeddedChannel writeChannel = new EmbeddedChannel(new DatagramDnsQueryEncoder());

        DnsQuery query = new DatagramDnsQuery(null, addr, 1, opCode)
                .setRecursionDesired(recursionDesired);
        query.setRecord(DnsSection.QUESTION, new DefaultDnsQuestion("example.com", DnsRecordType.A));

        assertTrue(writeChannel.writeOutbound(query));
        DatagramPacket packet = writeChannel.readOutbound();
        assertEquals(expectedFlags, packet.content().getUnsignedShort(2));

        assertTrue(packet.release());
        assertFalse(writeChannel.finish());
    }

    @ParameterizedTest
    @MethodSource("zValuesAndExpectedFlags")
    public void testZIsEncodedIntoBits6To4(int z, int expectedFlags) {
        InetSocketAddress addr = SocketUtils.socketAddress("8.8.8.8", 53);
        EmbeddedChannel writeChannel = new EmbeddedChannel(new DatagramDnsQueryEncoder());

        DnsQuery query = new DatagramDnsQuery(null, addr, 1).setZ(z);
        query.setRecord(DnsSection.QUESTION, new DefaultDnsQuestion("example.com", DnsRecordType.A));

        assertTrue(writeChannel.writeOutbound(query));
        DatagramPacket packet = writeChannel.readOutbound();
        assertEquals(expectedFlags, packet.content().getUnsignedShort(2));

        assertTrue(packet.release());
        assertFalse(writeChannel.finish());
    }

    @ParameterizedTest
    @MethodSource("zValuesAndExpectedFlags")
    public void testZSurvivesEncodeAndDecode(int z, int expectedFlags) {
        InetSocketAddress addr = SocketUtils.socketAddress("8.8.8.8", 53);
        EmbeddedChannel writeChannel = new EmbeddedChannel(new DatagramDnsQueryEncoder());
        EmbeddedChannel readChannel = new EmbeddedChannel(new DatagramDnsQueryDecoder());

        DnsQuery query = new DatagramDnsQuery(null, addr, 1).setZ(z);
        query.setRecord(DnsSection.QUESTION, new DefaultDnsQuestion("example.com", DnsRecordType.A));

        assertTrue(writeChannel.writeOutbound(query));
        assertTrue(readChannel.writeInbound(writeChannel.<DatagramPacket>readOutbound()));

        DnsQuery decoded = readChannel.readInbound();
        assertEquals(z, decoded.z());
        assertEquals((z & 0x2) != 0, decoded.isAuthenticData());
        assertEquals((z & 0x1) != 0, decoded.isCheckingDisabled());
        assertTrue(decoded.release());

        assertFalse(writeChannel.finish());
        assertFalse(readChannel.finish());
    }

    /**
     * A validating resolver sets {@code CD} on every upstream query (RFC 6840, section 5.9); before the
     * encoder wrote {@code Z} that was impossible to express.
     */
    @Test
    public void testCheckingDisabledReachesTheWire() {
        InetSocketAddress addr = SocketUtils.socketAddress("8.8.8.8", 53);
        EmbeddedChannel writeChannel = new EmbeddedChannel(new DatagramDnsQueryEncoder());

        DnsQuery query = new DatagramDnsQuery(null, addr, 1);
        query.setCheckingDisabled(true);
        query.setRecord(DnsSection.QUESTION, new DefaultDnsQuestion("example.com", DnsRecordType.A));

        assertTrue(query.isCheckingDisabled());
        assertFalse(query.isAuthenticData());
        assertTrue(writeChannel.writeOutbound(query));

        DatagramPacket packet = writeChannel.readOutbound();
        assertEquals(0x0010, packet.content().getUnsignedShort(2));

        assertTrue(packet.release());
        assertFalse(writeChannel.finish());
    }

    @Test
    public void testAuthenticDataAndCheckingDisabledAreIndependent() {
        InetSocketAddress addr = SocketUtils.socketAddress("8.8.8.8", 53);
        DnsQuery query = new DatagramDnsQuery(null, addr, 1);

        query.setAuthenticData(true);
        assertTrue(query.isAuthenticData());
        assertFalse(query.isCheckingDisabled());
        assertEquals(0x2, query.z());

        query.setCheckingDisabled(true);
        assertTrue(query.isAuthenticData());
        assertTrue(query.isCheckingDisabled());
        assertEquals(0x3, query.z());

        // Clearing one must leave the other, and must leave the still-reserved bit 6 alone.
        query.setZ(0x7);
        query.setAuthenticData(false);
        assertEquals(0x5, query.z());
        query.setCheckingDisabled(false);
        assertEquals(0x4, query.z());

        assertTrue(query.release());
    }
}
