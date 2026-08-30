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

import org.junit.jupiter.api.Test;

import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnssecDigestTypeTest {

    /**
     * The values and descriptions of the IANA Digest Algorithms registry, as tabulated by RFC 9904, Table 3.
     */
    @Test
    public void testRegistryValuesAndDescriptions() {
        assertValueAndName(0, "NULL", DnssecDigestType.NULL);
        assertValueAndName(1, "SHA-1", DnssecDigestType.SHA1);
        assertValueAndName(2, "SHA-256", DnssecDigestType.SHA256);
        assertValueAndName(3, "GOST R 34.11-94", DnssecDigestType.GOST_R_34_11_94);
        assertValueAndName(4, "SHA-384", DnssecDigestType.SHA384);
        assertValueAndName(5, "GOST R 34.11-2012", DnssecDigestType.GOST_R_34_11_2012);
        assertValueAndName(6, "SM3", DnssecDigestType.SM3);
    }

    private static void assertValueAndName(int intValue, String name, DnssecDigestType digestType) {
        assertEquals(intValue, digestType.intValue());
        assertEquals(name, digestType.name());
        assertSame(digestType, DnssecDigestType.valueOf(intValue));
        assertSame(digestType, DnssecDigestType.valueOf(name));
    }

    /**
     * The digest lengths are fixed by the algorithms, and are cross-checked against the JDK rather than restated,
     * so a typo here cannot pass.
     */
    @Test
    public void testSupportedDigestTypes() throws Exception {
        assertSupported(DnssecDigestType.SHA1, "SHA-1", 20);
        assertSupported(DnssecDigestType.SHA256, "SHA-256", 32);
        assertSupported(DnssecDigestType.SHA384, "SHA-384", 48);
    }

    private static void assertSupported(DnssecDigestType digestType, String algorithm, int digestLength)
            throws Exception {
        assertTrue(digestType.isSupported(), digestType.toString());
        assertEquals(algorithm, digestType.algorithm());
        assertEquals(digestLength, digestType.digestLength());
        assertEquals(MessageDigest.getInstance(algorithm).getDigestLength(), digestType.digestLength());
    }

    @Test
    public void testUnsupportedDigestTypes() {
        DnssecDigestType[] unsupported = {
                DnssecDigestType.NULL, DnssecDigestType.GOST_R_34_11_94, DnssecDigestType.GOST_R_34_11_2012,
                DnssecDigestType.SM3
        };
        for (DnssecDigestType digestType : unsupported) {
            assertFalse(digestType.isSupported(), digestType.toString());
            assertNull(digestType.algorithm(), digestType.toString());
            assertEquals(0, digestType.digestLength(), digestType.toString());
        }
    }

    @Test
    public void testUnknownDigestTypesFlowThrough() {
        for (int intValue : new int[] {7, 100, 255}) {
            DnssecDigestType digestType = DnssecDigestType.valueOf(intValue);
            assertEquals(intValue, digestType.intValue());
            assertEquals("UNKNOWN", digestType.name());
            assertFalse(digestType.isSupported());
            assertNull(digestType.algorithm());
            assertEquals(0, digestType.digestLength());
            assertEquals("UNKNOWN(" + intValue + ')', digestType.toString());
        }
    }

    @Test
    public void testOutOfRangeDigestTypesAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> DnssecDigestType.valueOf(-1));
        assertThrows(IllegalArgumentException.class, () -> DnssecDigestType.valueOf(256));
    }

    @Test
    public void testUnknownDescriptionsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> DnssecDigestType.valueOf("SHA1"));
        assertThrows(NullPointerException.class, () -> DnssecDigestType.valueOf((String) null));
    }

    @Test
    public void testEqualityIsByValue() {
        assertEquals(DnssecDigestType.SHA256, DnssecDigestType.valueOf(2));
        assertEquals(DnssecDigestType.SHA256.hashCode(), DnssecDigestType.valueOf(2).hashCode());
        assertNotEquals(DnssecDigestType.SHA256, DnssecDigestType.SHA384);
        assertNotEquals(DnssecDigestType.SHA256, new Object());
        assertTrue(DnssecDigestType.SHA1.compareTo(DnssecDigestType.SHA384) < 0);
        assertEquals(0, DnssecDigestType.SHA384.compareTo(DnssecDigestType.valueOf(4)));
    }

    @Test
    public void testToStringIncludesDescriptionAndValue() {
        assertEquals("SHA-256(2)", DnssecDigestType.SHA256.toString());
        assertEquals("NULL(0)", DnssecDigestType.NULL.toString());
    }
}
