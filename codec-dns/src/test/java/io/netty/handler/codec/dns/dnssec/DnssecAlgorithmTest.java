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

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DnssecAlgorithmTest {

    /**
     * The numbers and mnemonics of the IANA DNS Security Algorithm Numbers registry, as tabulated by RFC 9904,
     * Table 2.
     */
    @Test
    public void testRegistryNumbersAndMnemonics() {
        assertNumberAndName(1, "RSAMD5", DnssecAlgorithm.RSAMD5);
        assertNumberAndName(3, "DSA", DnssecAlgorithm.DSA);
        assertNumberAndName(5, "RSASHA1", DnssecAlgorithm.RSASHA1);
        assertNumberAndName(6, "DSA-NSEC3-SHA1", DnssecAlgorithm.DSA_NSEC3_SHA1);
        assertNumberAndName(7, "RSASHA1-NSEC3-SHA1", DnssecAlgorithm.RSASHA1_NSEC3_SHA1);
        assertNumberAndName(8, "RSASHA256", DnssecAlgorithm.RSASHA256);
        assertNumberAndName(10, "RSASHA512", DnssecAlgorithm.RSASHA512);
        assertNumberAndName(12, "ECC-GOST", DnssecAlgorithm.ECC_GOST);
        assertNumberAndName(13, "ECDSAP256SHA256", DnssecAlgorithm.ECDSAP256SHA256);
        assertNumberAndName(14, "ECDSAP384SHA384", DnssecAlgorithm.ECDSAP384SHA384);
        assertNumberAndName(15, "ED25519", DnssecAlgorithm.ED25519);
        assertNumberAndName(16, "ED448", DnssecAlgorithm.ED448);
        assertNumberAndName(17, "SM2SM3", DnssecAlgorithm.SM2SM3);
        assertNumberAndName(23, "ECC-GOST12", DnssecAlgorithm.ECC_GOST12);
        assertNumberAndName(253, "PRIVATEDNS", DnssecAlgorithm.PRIVATEDNS);
        assertNumberAndName(254, "PRIVATEOID", DnssecAlgorithm.PRIVATEOID);
    }

    private static void assertNumberAndName(int intValue, String name, DnssecAlgorithm algorithm) {
        assertEquals(intValue, algorithm.intValue());
        assertEquals(name, algorithm.name());
        assertSame(algorithm, DnssecAlgorithm.valueOf(intValue));
        assertSame(algorithm, DnssecAlgorithm.valueOf(name));
    }

    /**
     * Every algorithm marked MUST or RECOMMENDED to implement for validation by RFC 9904, Table 2 must be supported
     * here, given a JDK that offers the underlying primitive.
     */
    @Test
    public void testMustAndRecommendedAlgorithmsAreSupported() {
        assertSupported(DnssecAlgorithm.RSASHA1, "SHA1withRSA", "RSA");
        assertSupported(DnssecAlgorithm.RSASHA1_NSEC3_SHA1, "SHA1withRSA", "RSA");
        assertSupported(DnssecAlgorithm.RSASHA256, "SHA256withRSA", "RSA");
        assertSupported(DnssecAlgorithm.RSASHA512, "SHA512withRSA", "RSA");
        assertSupported(DnssecAlgorithm.ECDSAP256SHA256, "SHA256withECDSA", "EC");
        assertSupported(DnssecAlgorithm.ECDSAP384SHA384, "SHA384withECDSA", "EC");
        assertSupported(DnssecAlgorithm.ED25519, "Ed25519", "Ed25519");
        assertSupported(DnssecAlgorithm.ED448, "Ed448", "Ed448");
    }

    private static void assertSupported(DnssecAlgorithm algorithm, String signature, String keyFactory) {
        assertEquals(signature, algorithm.signatureAlgorithm());
        assertEquals(keyFactory, algorithm.keyFactoryAlgorithm());
        // isSupported() must agree with what the running JDK actually offers, not merely with our own table.
        assertEquals(isAvailable(signature, keyFactory), algorithm.isSupported(), algorithm.toString());
    }

    private static boolean isAvailable(String signature, String keyFactory) {
        try {
            Signature.getInstance(signature);
            KeyFactory.getInstance(keyFactory);
            return true;
        } catch (NoSuchAlgorithmException ignored) {
            return false;
        }
    }

    /**
     * Everything RFC 9904 marks MUST NOT, plus the MAY entries and the private-use range that RFC 6840, Section 5.3
     * lets a validator decline, must report as unsupported and expose no JCA name to accidentally use.
     */
    @Test
    public void testMustNotAndPrivateUseAlgorithmsAreUnsupported() {
        DnssecAlgorithm[] unsupported = {
                DnssecAlgorithm.RSAMD5, DnssecAlgorithm.DSA, DnssecAlgorithm.DSA_NSEC3_SHA1,
                DnssecAlgorithm.ECC_GOST, DnssecAlgorithm.SM2SM3, DnssecAlgorithm.ECC_GOST12,
                DnssecAlgorithm.PRIVATEDNS, DnssecAlgorithm.PRIVATEOID
        };
        for (DnssecAlgorithm algorithm : unsupported) {
            assertFalse(algorithm.isSupported(), algorithm.toString());
            assertNull(algorithm.signatureAlgorithm(), algorithm.toString());
            assertNull(algorithm.keyFactoryAlgorithm(), algorithm.toString());
        }
    }

    @Test
    public void testFamilies() {
        DnssecAlgorithm[] rsa = {
                DnssecAlgorithm.RSAMD5, DnssecAlgorithm.RSASHA1, DnssecAlgorithm.RSASHA1_NSEC3_SHA1,
                DnssecAlgorithm.RSASHA256, DnssecAlgorithm.RSASHA512
        };
        for (DnssecAlgorithm algorithm : rsa) {
            assertTrue(algorithm.isRsa(), algorithm.toString());
            assertFalse(algorithm.isEcdsa(), algorithm.toString());
            assertFalse(algorithm.isEdDsa(), algorithm.toString());
        }

        DnssecAlgorithm[] ecdsa = {DnssecAlgorithm.ECDSAP256SHA256, DnssecAlgorithm.ECDSAP384SHA384};
        for (DnssecAlgorithm algorithm : ecdsa) {
            assertTrue(algorithm.isEcdsa(), algorithm.toString());
            assertFalse(algorithm.isRsa(), algorithm.toString());
            assertFalse(algorithm.isEdDsa(), algorithm.toString());
        }

        DnssecAlgorithm[] eddsa = {DnssecAlgorithm.ED25519, DnssecAlgorithm.ED448};
        for (DnssecAlgorithm algorithm : eddsa) {
            assertTrue(algorithm.isEdDsa(), algorithm.toString());
            assertFalse(algorithm.isRsa(), algorithm.toString());
            assertFalse(algorithm.isEcdsa(), algorithm.toString());
        }

        DnssecAlgorithm[] neither = {
                DnssecAlgorithm.DSA, DnssecAlgorithm.DSA_NSEC3_SHA1, DnssecAlgorithm.ECC_GOST,
                DnssecAlgorithm.ECC_GOST12, DnssecAlgorithm.SM2SM3, DnssecAlgorithm.PRIVATEDNS,
                DnssecAlgorithm.PRIVATEOID, DnssecAlgorithm.valueOf(200)
        };
        for (DnssecAlgorithm algorithm : neither) {
            assertFalse(algorithm.isRsa(), algorithm.toString());
            assertFalse(algorithm.isEcdsa(), algorithm.toString());
            assertFalse(algorithm.isEdDsa(), algorithm.toString());
        }
    }

    /**
     * An unassigned algorithm number must survive parsing, because a validator has to be able to report it as
     * unsupported and treat the zone as Insecure rather than abort.
     */
    @Test
    public void testUnknownAlgorithmNumbersFlowThrough() {
        for (int intValue : new int[] {0, 2, 4, 9, 11, 200, 252, 255}) {
            DnssecAlgorithm algorithm = DnssecAlgorithm.valueOf(intValue);
            assertEquals(intValue, algorithm.intValue());
            assertEquals("UNKNOWN", algorithm.name());
            assertFalse(algorithm.isSupported());
            assertNull(algorithm.signatureAlgorithm());
            assertEquals("UNKNOWN(" + intValue + ')', algorithm.toString());
        }
    }

    @Test
    public void testOutOfRangeAlgorithmNumbersAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> DnssecAlgorithm.valueOf(-1));
        assertThrows(IllegalArgumentException.class, () -> DnssecAlgorithm.valueOf(256));
        assertThrows(IllegalArgumentException.class, () -> DnssecAlgorithm.valueOf(Integer.MAX_VALUE));
    }

    @Test
    public void testUnknownMnemonicsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> DnssecAlgorithm.valueOf("NOPE"));
        assertThrows(IllegalArgumentException.class, () -> DnssecAlgorithm.valueOf("rsasha256"));
        assertThrows(NullPointerException.class, () -> DnssecAlgorithm.valueOf((String) null));
    }

    @Test
    public void testEqualityIsByNumber() {
        assertEquals(DnssecAlgorithm.RSASHA256, DnssecAlgorithm.valueOf(8));
        assertEquals(DnssecAlgorithm.valueOf(200), DnssecAlgorithm.valueOf(200));
        assertEquals(DnssecAlgorithm.RSASHA256.hashCode(), DnssecAlgorithm.valueOf(8).hashCode());
        assertNotEquals(DnssecAlgorithm.RSASHA256, DnssecAlgorithm.RSASHA512);
        assertNotEquals(DnssecAlgorithm.RSASHA256, new Object());
        assertTrue(DnssecAlgorithm.RSASHA256.compareTo(DnssecAlgorithm.RSASHA512) < 0);
        assertTrue(DnssecAlgorithm.ED448.compareTo(DnssecAlgorithm.ED25519) > 0);
        assertEquals(0, DnssecAlgorithm.ED448.compareTo(DnssecAlgorithm.valueOf(16)));
    }

    @Test
    public void testToStringIncludesMnemonicAndNumber() {
        assertEquals("ECDSAP256SHA256(13)", DnssecAlgorithm.ECDSAP256SHA256.toString());
        assertEquals("RSAMD5(1)", DnssecAlgorithm.RSAMD5.toString());
    }
}
