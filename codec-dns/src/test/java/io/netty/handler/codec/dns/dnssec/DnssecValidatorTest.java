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

import io.netty.buffer.Unpooled;
import io.netty.handler.codec.dns.DefaultDnsResponse;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.handler.codec.dns.DnsResponseCode;
import io.netty.handler.codec.dns.DnsSection;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.DefaultEventExecutor;
import io.netty.util.concurrent.EventExecutor;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.ImmediateEventExecutor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.A;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.DNSKEY;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.DS;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.InMemoryFetcher;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.MX;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.NS;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.NSEC;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.RRSIG;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.SOA;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.TestZone;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.a;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.cname;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.list;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.nsec;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.nsec3;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.response;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The chain-of-trust engine, driven over an in-memory fetcher. There is no network here and no timing: every
 * fixture is a fixed table of responses and every bound is asserted from {@link DnssecBudget}'s counters.
 *
 * <p>Two sources of signed data are used. The RFC 4035 appendix A zone is real — its {@code RRSIG}s verify
 * cryptographically against the published key — and it carries the end-to-end chain from a trust anchor through a
 * key-signing key to an answer. Everything the RFC does not publish, which is anything needing a private key, is
 * signed by {@link DnssecChainTestSupport} over freshly generated ECDSA P-256 zones.</p>
 */
public class DnssecValidatorTest {

    private static final int HINFO = 13;
    private static final int AAAA = 28;
    private static final int NSEC3PARAM = 51;

    /** The RFC 5155 appendix A parameters: SHA-1, 12 iterations, salt {@code aabbccdd}. */
    private static final byte[] NSEC3_SALT = { (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd };
    private static final int NSEC3_ITERATIONS = 12;
    private static final int NSEC3_OPT_OUT = 1;

    private final EventExecutor executor = ImmediateEventExecutor.INSTANCE;
    private final List<DnsRecord> owned = new ArrayList<DnsRecord>();

    @AfterEach
    public void releaseRecords() {
        for (int i = 0; i < owned.size(); i++) {
            ReferenceCountUtil.release(owned.get(i));
        }
        owned.clear();
    }

    // -----------------------------------------------------------------------------------------------------------
    // The RFC 4035 appendix A zone, with its published signatures

    /**
     * The whole chain, end to end, over published data: a trust anchor names the key-signing key of
     * {@code example.}; that key's own signature over the {@code DNSKEY} RRset makes the zone-signing key trusted;
     * the {@code DS} probe on the way down is answered by the appendix A {@code NSEC}; and the zone-signing key
     * authenticates the answer.
     */
    @Test
    public void testSecureChainFromTrustAnchorOverPublishedZone() {
        Rfc4035Zone zone = new Rfc4035Zone();
        DnssecValidationResult result = zone.validateAiExample(zone.dnskeyAnswer(zone.rrsigDnskeyByKsk()));

        assertEquals(DnssecStatus.SECURE, result.status(), result.toString());
        assertEquals(DnssecFailureReason.NONE, result.reason());
        assertEquals(DnsName.fromString("example."), result.signerName());
        assertNull(result.insecureDelegation());
        assertNull(result.cause());
        assertFalse(result.trace().isEmpty());
        // One DNSKEY lookup and one DS probe at ai.example., which is not a zone cut.
        assertEquals(2, result.budget().fetches());
        assertEquals(1, result.budget().delegations());
    }

    /**
     * <a href="https://www.cve.org/CVERecord?id=CVE-2025-25188">CVE-2025-25188</a>, the trust-anchor half: an
     * anchor authenticates exactly one key, and the RRset that key sits in becomes trusted only once an
     * {@code RRSIG} <em>made by that key</em> validates over it.
     *
     * <p>The fixture is the published one with a single change: the {@code DNSKEY} RRset is offered with only the
     * signature made by the zone-signing key 38519, and the anchor names the key-signing key 9465. Both signatures
     * are genuine and both verify cryptographically, so a validator that accepts the RRset because <em>some</em>
     * key in it matched the anchor gets Secure here. There is no such thing as a valid chain through 38519,
     * because nothing outside the zone vouches for it.</p>
     */
    @Test
    public void testAnchorMatchingOneKeyDoesNotTrustASignatureMadeByAnother() {
        Rfc4035Zone zone = new Rfc4035Zone();
        DnssecValidationResult result = zone.validateAiExample(zone.dnskeyAnswer(zone.rrsigDnskeyByZsk()));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.KEY_TAG_NO_MATCH, result.reason());
        assertTrue(result.message().contains("not signed by any of the"), result.message());
    }

    /**
     * A tampered signature is Bogus, and specifically not Insecure: the zone is signed and the data does not match
     * what it signed.
     */
    @Test
    public void testTamperedAnswerSignatureIsBogus() {
        Rfc4035Zone zone = new Rfc4035Zone();
        DnsRrsigRecord broken = keep(zone.tamper(zone.rrsigAiA()));
        DnssecValidationResult result = zone.validate(list(zone.aiA(), broken), zone.aiNsecProof(),
                zone.dnskeyAnswer(zone.rrsigDnskeyByKsk()));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
    }

    /**
     * <a href="https://www.cve.org/CVERecord?id=CVE-2024-25638">CVE-2024-25638</a>: a record the validator has no
     * reason to look at is still a record the caller will read. Validating around it and reporting Secure hands the
     * caller a verdict that does not cover the message it holds.
     */
    @Test
    public void testUnrelatedRecordInTheAnswerSectionIsBogus() {
        Rfc4035Zone zone = new Rfc4035Zone();
        DnssecRecord intruder = keep(DnssecRRsetFixtures.rawRecord(DnsName.fromString("evil.example.net."),
                DnsRecordType.A, 3600, new byte[] { 10, 0, 0, 1 }));
        DnssecValidationResult result = zone.validate(list(zone.aiA(), zone.rrsigAiA(), intruder),
                zone.aiNsecProof(), zone.dnskeyAnswer(zone.rrsigDnskeyByKsk()));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.BAILIWICK_VIOLATION, result.reason());
        assertTrue(result.message().contains("evil.example.net"), result.message());
    }

    /**
     * <a href="https://www.cve.org/CVERecord?id=CVE-2026-42960">CVE-2026-42960</a>: the additional section is not
     * authenticated data. Moving the answer's {@code RRSIG} there leaves the answer unsigned as far as validation
     * is concerned, whatever the message appears to contain.
     */
    @Test
    public void testAdditionalSectionIsNeverTreatedAsAuthenticated() {
        Rfc4035Zone zone = new Rfc4035Zone();
        DefaultDnsResponse response = response("ai.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                list((DnsRecord) zone.aiA()), zone.aiNsecProof());
        response.addRecord(DnsSection.ADDITIONAL, ReferenceCountUtil.retain(zone.rrsigAiA()));

        DnssecValidationResult result = zone.run(response, zone.dnskeyAnswer(zone.rrsigDnskeyByKsk()));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.RRSIGS_MISSING, result.reason());
    }

    /**
     * A response that answers a different question is rejected before anything in it is examined.
     */
    @Test
    public void testResponseAnsweringADifferentQuestionIsBogus() {
        Rfc4035Zone zone = new Rfc4035Zone();
        DefaultDnsResponse response = response("b.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                list(zone.aiA(), zone.rrsigAiA()), zone.aiNsecProof());

        DnssecValidationResult result = zone.run(response, zone.dnskeyAnswer(zone.rrsigDnskeyByKsk()));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.BAILIWICK_VIOLATION, result.reason());
        assertEquals(0, result.budget().fetches(), "nothing should have been looked up");
    }

    /**
     * The caller owns the response and must be able to release it the moment {@code validate} returns.
     */
    @Test
    public void testResponseMayBeReleasedAsSoonAsValidateReturns() {
        Rfc4035Zone zone = new Rfc4035Zone();
        DnssecValidator validator = zone.validator(zone.fetcher(zone.dnskeyAnswer(zone.rrsigDnskeyByKsk())));
        DefaultDnsResponse response = response("ai.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                list(zone.aiA(), zone.rrsigAiA()), zone.aiNsecProof());

        Future<DnssecValidationResult> future =
                validator.validate(DnsName.fromString("ai.example."), DnsRecordType.A, response, executor);
        assertEquals(1, response.refCnt());
        response.release();

        assertTrue(future.isDone());
        assertEquals(DnssecStatus.SECURE, future.getNow().status(), String.valueOf(future.getNow()));
    }

    /**
     * The same validation, driven from another thread, to show the hop onto the validation's executor works and
     * that the verdict survives being read from a third one.
     */
    @Test
    public void testValidationHopsOntoItsExecutor() throws Exception {
        DefaultEventExecutor loop = new DefaultEventExecutor();
        try {
            Rfc4035Zone zone = new Rfc4035Zone(loop);
            DnssecValidator validator = zone.validator(zone.fetcher(zone.dnskeyAnswer(zone.rrsigDnskeyByKsk())));
            DefaultDnsResponse response = response("ai.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                    list(zone.aiA(), zone.rrsigAiA()), zone.aiNsecProof());
            Future<DnssecValidationResult> future;
            try {
                future = validator.validate(DnsName.fromString("ai.example."), DnsRecordType.A, response, loop);
            } finally {
                response.release();
            }
            assertTrue(future.await(30, TimeUnit.SECONDS));
            assertEquals(DnssecStatus.SECURE, future.getNow().status(), String.valueOf(future.getNow()));
        } finally {
            loop.shutdownGracefully(0, 0, TimeUnit.SECONDS).await(30, TimeUnit.SECONDS);
        }
    }

    /**
     * A truncated response is missing records by construction. Judging what arrived would be judging half a
     * message, and Bogus would blame the zone for the transport.
     */
    @Test
    public void testTruncatedResponseIsIndeterminate() {
        Rfc4035Zone zone = new Rfc4035Zone();
        DefaultDnsResponse response = response("ai.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                list(zone.aiA(), zone.rrsigAiA()), zone.aiNsecProof());
        response.setTruncated(true);

        DnssecValidationResult result = zone.run(response, zone.dnskeyAnswer(zone.rrsigDnskeyByKsk()));

        assertEquals(DnssecStatus.INDETERMINATE, result.status(), result.toString());
        assertTrue(result.message().contains("truncated"), result.message());
        assertEquals(0, result.budget().fetches());
    }

    // -----------------------------------------------------------------------------------------------------------
    // Indeterminate

    @Test
    public void testNoTrustAnchorIsIndeterminate() {
        Rfc4035Zone zone = new Rfc4035Zone();
        DnssecValidator validator = DnssecValidator.newBuilder()
                .trustAnchors(DnssecTrustAnchors.newBuilder().build())
                .fetcher(zone.fetcher(zone.dnskeyAnswer(zone.rrsigDnskeyByKsk())))
                .clock(zone.clock)
                .keyCache(DnssecKeyCache.noop())
                .build();

        DnssecValidationResult result = zone.run(validator, response("ai.example.", DnsRecordType.A,
                DnsResponseCode.NOERROR, list(zone.aiA(), zone.rrsigAiA()), zone.aiNsecProof()));

        assertEquals(DnssecStatus.INDETERMINATE, result.status(), result.toString());
        assertEquals(DnssecFailureReason.NO_TRUST_ANCHOR, result.reason());
        assertEquals(0, result.budget().fetches());
    }

    /**
     * An anchor outside its validity window is not an anchor. It is deliberately not replaced by one at a
     * shallower name.
     */
    @Test
    public void testTrustAnchorOutsideItsValidityWindowIsIndeterminate() {
        Rfc4035Zone zone = new Rfc4035Zone();
        DnssecTrustAnchor expired = new DnssecTrustAnchor(DnsName.fromString("example."), zone.kskKeyTag(),
                DnssecAlgorithm.RSASHA1, DnssecDigestType.SHA256, zone.kskDigest(),
                0L, 1000L);
        DnssecValidator validator = DnssecValidator.newBuilder()
                .trustAnchors(DnssecTrustAnchors.newBuilder().addAnchor(expired).build())
                .fetcher(zone.fetcher(zone.dnskeyAnswer(zone.rrsigDnskeyByKsk())))
                .clock(zone.clock)
                .keyCache(DnssecKeyCache.noop())
                .build();

        DnssecValidationResult result = zone.run(validator, response("ai.example.", DnsRecordType.A,
                DnsResponseCode.NOERROR, list(zone.aiA(), zone.rrsigAiA()), zone.aiNsecProof()));

        assertEquals(DnssecStatus.INDETERMINATE, result.status(), result.toString());
        assertEquals(DnssecFailureReason.NO_TRUST_ANCHOR, result.reason());
        assertTrue(result.message().contains("validity window"), result.message());
    }

    /**
     * A lookup that never answered leaves the validator with nothing to judge. That is Indeterminate, not Insecure:
     * an attacker who can drop packets must not be able to strip DNSSEC from a signed zone that way.
     */
    @Test
    public void testFailedFetchIsIndeterminateAndCarriesItsCause() {
        Rfc4035Zone zone = new Rfc4035Zone();
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        IOException cause = new IOException("no route to the resolver");
        fetcher.fail(DnsName.fromString("example."), DnsRecordType.DNSKEY, cause);

        DnssecValidationResult result = zone.run(zone.validator(fetcher), response("ai.example.",
                DnsRecordType.A, DnsResponseCode.NOERROR, list(zone.aiA(), zone.rrsigAiA()), zone.aiNsecProof()));

        assertEquals(DnssecStatus.INDETERMINATE, result.status(), result.toString());
        assertEquals(DnssecFailureReason.FETCH_FAILED, result.reason());
        assertSame(cause, result.cause());
    }

    // -----------------------------------------------------------------------------------------------------------
    // Delegations

    /**
     * An authenticated denial of the {@code DS} RRset at a delegation is the one thing that makes a subtree
     * Insecure. Note it is the {@code NS} bit that makes this a delegation rather than an ordinary name.
     */
    @Test
    public void testProvenAbsentDsMakesTheDelegationInsecure() {
        TestZone parent = new TestZone("example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, parent);
        putUnsignedDelegation(fetcher, parent, "sub.example.", "zz.example.");

        DnssecValidationResult result = validate(parent, fetcher, "www.sub.example.", DnsRecordType.A,
                response("www.sub.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                        list(keep(a("www.sub.example.", "192.0.2.7"))),
                        Collections.<DnsRecord>emptyList()));

        assertEquals(DnssecStatus.INSECURE, result.status(), result.toString());
        assertEquals(DnssecFailureReason.UNSIGNED_DELEGATION, result.reason());
        assertEquals(DnsName.fromString("sub.example."), result.insecureDelegation());
    }

    /**
     * RFC 5155, Section 8.9: with opt-out an insecure delegation need not have an {@code NSEC3} of its own, and a
     * covering opt-out record is the proof. The fixture is the shape of RFC 5155 appendix B.3, with the hashes
     * recomputed here rather than copied.
     */
    @Test
    public void testOptOutCoveredDelegationIsInsecure() {
        TestZone parent = new TestZone("example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, parent);

        DnsNsec3Record closestEncloser = keep(nsec3(parent.name, hash("example."), hash("ns1.example."),
                NSEC3_OPT_OUT, NSEC3_ITERATIONS, NSEC3_SALT, MX, DNSKEY, NS, SOA, NSEC3PARAM, RRSIG));
        DnsNsec3Record covering = keep(nsec3(parent.name, hash("a.example."), hash("x.w.example."),
                NSEC3_OPT_OUT, NSEC3_ITERATIONS, NSEC3_SALT, NS, DS, RRSIG));
        fetcher.put(DnsName.fromString("c.example."), DnsRecordType.DS, DnsResponseCode.NOERROR,
                Collections.<DnsRecord>emptyList(),
                list(closestEncloser, keep(parent.sign(list(closestEncloser))),
                        covering, keep(parent.sign(list(covering)))));

        DnssecValidationResult result = validate(parent, fetcher, "www.c.example.", DnsRecordType.A,
                response("www.c.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                        list(keep(a("www.c.example.", "192.0.2.8"))), Collections.<DnsRecord>emptyList()));

        assertEquals(DnssecStatus.INSECURE, result.status(), result.toString());
        assertEquals(DnssecFailureReason.NSEC3_OPT_OUT, result.reason());
        assertEquals(DnsName.fromString("c.example."), result.insecureDelegation());
    }

    /**
     * <a href="https://www.cve.org/CVERecord?id=CVE-2025-25188">CVE-2025-25188</a>, the delegation half: the same
     * rule at a {@code DS} rather than at a trust anchor. The child publishes two keys and signs its {@code DNSKEY}
     * RRset with the one the parent does <em>not</em> vouch for.
     */
    @Test
    public void testDsVouchingForOneKeyDoesNotTrustASignatureMadeByAnother() {
        TestZone parent = new TestZone("example.");
        TestZone child = new TestZone("sub.example.");
        TestZone rogue = new TestZone("sub.example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, parent);
        putSignedDelegation(fetcher, parent, child);

        List<DnssecRecord> keys = list((DnssecRecord) child.dnskey, rogue.dnskey);
        fetcher.put(child.name, DnsRecordType.DNSKEY, DnsResponseCode.NOERROR,
                list(child.dnskey, rogue.dnskey, keep(rogue.sign(keys))), Collections.<DnsRecord>emptyList());

        // A perfectly good answer signed by the rogue key, so that a validator which accepted the RRset because
        // *some* key in it was vouched for reaches Secure rather than merely a different failure.
        DnssecRecord answer = keep(a("sub.example.", "192.0.2.13"));
        DnssecValidationResult result = validate(parent, fetcher, "sub.example.", DnsRecordType.A,
                response("sub.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                        list(answer, keep(rogue.sign(list(answer)))), Collections.<DnsRecord>emptyList()));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.KEY_TAG_NO_MATCH, result.reason());
        assertTrue(result.message().contains("the parent DS RRset"), result.message());
    }

    /**
     * The control for the test above: signed by the key the parent vouches for, the whole RRset is trusted and the
     * other key in it with it, which is how a zone-signing key becomes usable at all.
     */
    @Test
    public void testDsVouchingForOneKeyTrustsTheRrsetThatKeySigns() {
        TestZone parent = new TestZone("example.");
        TestZone child = new TestZone("sub.example.");
        TestZone second = new TestZone("sub.example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, parent);
        putSignedDelegation(fetcher, parent, child);

        List<DnssecRecord> keys = list((DnssecRecord) child.dnskey, second.dnskey);
        fetcher.put(child.name, DnsRecordType.DNSKEY, DnsResponseCode.NOERROR,
                list(child.dnskey, second.dnskey, keep(child.sign(keys))), Collections.<DnsRecord>emptyList());

        // Signed by the key the parent never named, which the RRset above has just made trustworthy.
        DnssecRecord answer = keep(a("sub.example.", "192.0.2.9"));
        DnssecValidationResult result = validate(parent, fetcher, "sub.example.", DnsRecordType.A,
                response("sub.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                        list(answer, keep(second.sign(list(answer)))), Collections.<DnsRecord>emptyList()));

        assertEquals(DnssecStatus.SECURE, result.status(), result.toString());
        assertEquals(child.name, result.signerName());
    }

    /**
     * The zone an RRset belongs to is decided by the chain walk and not by the Signer's Name the {@code RRSIG}
     * claims. Here the answer really is signed, by the parent's real key, for a name that lies below a secure
     * delegation: the parent has no authority over it, and a validator that walked only as far as the claimed
     * signer would take it.
     */
    @Test
    public void testParentKeyCannotSignBelowASecureDelegation() {
        TestZone parent = new TestZone("example.");
        TestZone child = new TestZone("sub.example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, parent);
        putDnskey(fetcher, child);
        putSignedDelegation(fetcher, parent, child);
        putNoDelegation(fetcher, child, "host.sub.example.", "zz.sub.example.", A, RRSIG, NSEC);

        DnssecRecord address = keep(a("host.sub.example.", "192.0.2.12"));
        DnssecValidationResult result = validate(parent, fetcher, "host.sub.example.", DnsRecordType.A,
                response("host.sub.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                        list(address, keep(parent.sign(list(address)))), Collections.<DnsRecord>emptyList()));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.KEY_TAG_NO_MATCH, result.reason());
        assertTrue(result.message().contains("keys of sub.example."), result.message());
    }

    /**
     * The same rule on the negative path: an answer section that is not part of the chain is a reason to reject the
     * response even when the verdict itself came from the authority section.
     */
    @Test
    public void testUnrelatedAnswerRecordOnANegativeResponseIsBogus() {
        TestZone zone = new TestZone("example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, zone);
        DnsNsecRecord covering = keep(nsec("example.", "b.example.", NS, SOA, RRSIG, NSEC, DNSKEY));
        putNameErrorDsProbe(fetcher, zone, "a.example.", covering);
        DnssecRecord intruder = keep(a("evil.example.net.", "10.0.0.1"));

        DnssecValidationResult result = validate(zone, fetcher, "a.example.", DnsRecordType.A,
                response("a.example.", DnsRecordType.A, DnsResponseCode.NXDOMAIN,
                        list((DnsRecord) intruder), list(covering, keep(zone.sign(list(covering))))));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.BAILIWICK_VIOLATION, result.reason());
    }

    // -----------------------------------------------------------------------------------------------------------
    // Wildcards

    /**
     * RFC 4035, Section 5.3.4: a wildcard-expanded answer needs a proof that the queried name does not exist.
     * Without it the answer is indistinguishable from the same signature replayed over a name the zone defines.
     */
    @Test
    public void testWildcardAnswerWithoutItsDenialOfExistenceIsNotSecure() {
        Wildcard fixture = new Wildcard();
        DnssecValidationResult result = fixture.validate(Collections.<DnsRecord>emptyList());

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.WILDCARD_PROOF_MISSING, result.reason());
    }

    @Test
    public void testWildcardAnswerWithItsDenialOfExistenceIsSecure() {
        Wildcard fixture = new Wildcard();
        DnssecValidationResult result = fixture.validate(fixture.proof());

        assertEquals(DnssecStatus.SECURE, result.status(), result.toString());
        assertEquals(DnsName.fromString("example."), result.signerName());
    }

    /**
     * The proof itself has to be in bailiwick. An {@code NSEC} from somewhere else is not evidence about this zone,
     * whatever it says.
     */
    @Test
    public void testOutOfBailiwickProofRecordIsBogus() {
        Wildcard fixture = new Wildcard();
        DnsNsecRecord intruder = keep(nsec("a.example.net.", "b.example.net.", MX, RRSIG, NSEC));
        DnssecValidationResult result = fixture.validate(list(intruder, keep(fixture.zone.sign(list(intruder)))));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.BAILIWICK_VIOLATION, result.reason());
    }

    // -----------------------------------------------------------------------------------------------------------
    // Aliases

    /**
     * Each link of a {@code CNAME} chain is validated against the keys of its own signer, and the walk re-enters
     * the chain of trust when the target lands in another zone.
     */
    @Test
    public void testCnameChainCrossingAZoneCutIsSecure() {
        TestZone parent = new TestZone("example.");
        TestZone child = new TestZone("sub.example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, parent);
        putDnskey(fetcher, child);
        putSignedDelegation(fetcher, parent, child);
        putNoDelegation(fetcher, parent, "alias.example.", "b.example.", A, RRSIG, NSEC);
        putNoDelegation(fetcher, child, "host.sub.example.", "zz.sub.example.", A, RRSIG, NSEC);

        DnssecRecord alias = keep(cname("alias.example.", "host.sub.example."));
        DnssecRecord address = keep(a("host.sub.example.", "192.0.2.10"));
        DnssecValidationResult result = validate(parent, fetcher, "alias.example.", DnsRecordType.A,
                response("alias.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                        list(alias, keep(parent.sign(list(alias))), address, keep(child.sign(list(address)))),
                        Collections.<DnsRecord>emptyList()));

        assertEquals(DnssecStatus.SECURE, result.status(), result.toString());
        assertEquals(child.name, result.signerName());
        assertEquals(1, result.budget().cnameLinks());
    }

    /**
     * A {@code CNAME} link signed by the wrong zone does not become authentic because the link after it is fine.
     */
    @Test
    public void testCnameLinkSignedByTheWrongZoneIsBogus() {
        TestZone parent = new TestZone("example.");
        TestZone child = new TestZone("sub.example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, parent);
        putDnskey(fetcher, child);
        putSignedDelegation(fetcher, parent, child);
        putNoDelegation(fetcher, parent, "alias.example.", "b.example.", A, RRSIG, NSEC);

        DnssecRecord alias = keep(cname("alias.example.", "host.sub.example."));
        DnssecValidationResult result = validate(parent, fetcher, "alias.example.", DnsRecordType.A,
                response("alias.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                        list(alias, keep(child.sign(list(alias)))), Collections.<DnsRecord>emptyList()));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
    }

    // -----------------------------------------------------------------------------------------------------------
    // Negative answers

    @Test
    public void testProvenNameErrorIsSecure() {
        TestZone zone = new TestZone("example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, zone);

        // example. < *.example. < a.example. < b.example. in canonical order, so this one NSEC covers both the
        // queried name and the wildcard whose absence RFC 4035, Section 5.4 also requires denying.
        DnsNsecRecord covering = keep(nsec("example.", "b.example.", NS, SOA, RRSIG, NSEC, DNSKEY));
        putNameErrorDsProbe(fetcher, zone, "a.example.", covering);
        DnssecValidationResult result = validate(zone, fetcher, "a.example.", DnsRecordType.A,
                response("a.example.", DnsRecordType.A, DnsResponseCode.NXDOMAIN,
                        Collections.<DnsRecord>emptyList(),
                        list(covering, keep(zone.sign(list(covering))))));

        assertEquals(DnssecStatus.SECURE, result.status(), result.toString());
        assertEquals(zone.name, result.signerName());
    }

    @Test
    public void testNameErrorWithoutAProofIsBogus() {
        TestZone zone = new TestZone("example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, zone);
        putNameErrorDsProbe(fetcher, zone, "a.example.",
                keep(nsec("example.", "b.example.", NS, SOA, RRSIG, NSEC, DNSKEY)));

        DnssecValidationResult result = validate(zone, fetcher, "a.example.", DnsRecordType.A,
                response("a.example.", DnsRecordType.A, DnsResponseCode.NXDOMAIN,
                        Collections.<DnsRecord>emptyList(), Collections.<DnsRecord>emptyList()));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
    }

    /**
     * The proof records are verified before they are believed. {@link DnssecDenialOfExistence} checks no
     * signatures, so handing it whatever arrived would let anyone supply their own denial.
     */
    @Test
    public void testUnsignedProofRecordsAreNotBelieved() {
        TestZone zone = new TestZone("example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, zone);

        DnsNsecRecord covering = keep(nsec("example.", "b.example.", NS, SOA, RRSIG, NSEC, DNSKEY));
        putNameErrorDsProbe(fetcher, zone, "a.example.", covering);
        DnssecValidationResult result = validate(zone, fetcher, "a.example.", DnsRecordType.A,
                response("a.example.", DnsRecordType.A, DnsResponseCode.NXDOMAIN,
                        Collections.<DnsRecord>emptyList(), list((DnsRecord) covering)));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.RRSIGS_MISSING, result.reason());
    }

    // -----------------------------------------------------------------------------------------------------------
    // Budget

    @Test
    public void testMaxFetchesBinds() {
        DnssecValidationResult result = limited(DnssecLimits.newBuilder().maxFetches(1).build());

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.LIMIT_EXCEEDED, result.reason());
        assertEquals(1, result.budget().fetches());
    }

    @Test
    public void testMaxDelegationDepthBinds() {
        TestZone parent = new TestZone("example.");
        TestZone child = new TestZone("sub.example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, parent);
        putDnskey(fetcher, child);
        putSignedDelegation(fetcher, parent, child);
        putNoDelegation(fetcher, child, "host.sub.example.", "zz.sub.example.", A, RRSIG, NSEC);

        DnssecRecord address = keep(a("host.sub.example.", "192.0.2.11"));
        DnssecValidationResult result = validate(parent, fetcher, "host.sub.example.", DnsRecordType.A,
                DnssecLimits.newBuilder().maxDelegationDepth(1).build(),
                response("host.sub.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                        list(address, keep(child.sign(list(address)))), Collections.<DnsRecord>emptyList()));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.LIMIT_EXCEEDED, result.reason());
        assertEquals(1, result.budget().delegations());
    }

    @Test
    public void testMaxSignatureVerificationsPerValidationBinds() {
        DnssecValidationResult result =
                limited(DnssecLimits.newBuilder().maxSignatureVerificationsPerRrset(1)
                        .maxSignatureVerificationsPerValidation(1).build());

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.LIMIT_EXCEEDED, result.reason());
        assertEquals(1, result.budget().signatureVerifications());
    }

    @Test
    public void testMaxRecordsPerSectionBinds() {
        DnssecValidationResult result = limited(DnssecLimits.newBuilder().maxRecordsPerSection(1).build());

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.LIMIT_EXCEEDED, result.reason());
        assertEquals(0, result.budget().fetches(), "the section is rejected before anything is looked up");
    }

    @Test
    public void testMaxCnameChainLengthBinds() {
        TestZone zone = new TestZone("example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, zone);
        putNoDelegation(fetcher, zone, "one.example.", "p.example.", A, RRSIG, NSEC);
        putNoDelegation(fetcher, zone, "two.example.", "q.example.", A, RRSIG, NSEC);

        DnssecRecord first = keep(cname("one.example.", "two.example."));
        DnssecRecord second = keep(cname("two.example.", "three.example."));
        DnssecValidationResult result = validate(zone, fetcher, "one.example.", DnsRecordType.A,
                DnssecLimits.newBuilder().maxCnameChainLength(1).build(),
                response("one.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                        list(first, keep(zone.sign(list(first))), second, keep(zone.sign(list(second)))),
                        Collections.<DnsRecord>emptyList()));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.LIMIT_EXCEEDED, result.reason());
        assertEquals(1, result.budget().cnameLinks());
    }

    /**
     * A key tag is a 16-bit checksum and RFC 4034, appendix B says outright that it does not identify a key, so an
     * attacker can offer as many keys with the anchor's tag as they like. Each one costs a digest, and the number
     * of digests is bounded.
     */
    @Test
    public void testMaxDsMatchFailuresBinds() {
        DnsName example = DnsName.fromString("example.");
        List<DnssecRecord> keys = new ArrayList<DnssecRecord>();
        for (int i = 0; i < 8; i++) {
            keys.add(keep(DnssecRRsetFixtures.keyWithTag(example, 4242, i)));
        }
        DnssecTrustAnchor anchor = new DnssecTrustAnchor(example, 4242, DnssecAlgorithm.RSASHA1,
                DnssecDigestType.SHA256, new byte[32]);
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        List<DnsRecord> answer = new ArrayList<DnsRecord>(keys);
        fetcher.put(example, DnsRecordType.DNSKEY, DnsResponseCode.NOERROR, answer,
                Collections.<DnsRecord>emptyList());

        DnssecLimits limits = DnssecLimits.newBuilder().maxDsMatchFailures(4).build();
        DnssecValidator validator = DnssecValidator.newBuilder()
                .trustAnchors(DnssecTrustAnchors.newBuilder().addAnchor(anchor).build())
                .fetcher(fetcher)
                .limits(limits)
                .clock(DnssecChainTestSupport.clock())
                .keyCache(DnssecKeyCache.noop())
                .build();
        DnssecValidationResult result = run(validator, "example.", DnsRecordType.A,
                response("example.", DnsRecordType.A, DnsResponseCode.NXDOMAIN,
                        Collections.<DnsRecord>emptyList(), Collections.<DnsRecord>emptyList()));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.LIMIT_EXCEEDED, result.reason());
        assertEquals(4, result.budget().dsMatchFailures());
    }

    /**
     * The wall-clock backstop, driven by a clock that advances two seconds every time it is read rather than by
     * anything that actually takes time.
     */
    @Test
    public void testValidationDeadlineBinds() {
        Rfc4035Zone zone = new Rfc4035Zone(new SteppingClock(DnssecRRsetFixtures.RFC4035_VALID_AT * 1000L, 2000L));
        DnssecValidationResult result = zone.run(zone.validator(zone.fetcher(
                zone.dnskeyAnswer(zone.rrsigDnskeyByKsk()))), response("ai.example.", DnsRecordType.A,
                DnsResponseCode.NOERROR, list(zone.aiA(), zone.rrsigAiA()), zone.aiNsecProof()));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.LIMIT_EXCEEDED, result.reason());
    }

    // -----------------------------------------------------------------------------------------------------------
    // The key cache

    @Test
    public void testValidatedKeysAreCachedAndReused() {
        Rfc4035Zone zone = new Rfc4035Zone();
        InMemoryFetcher fetcher = zone.fetcher(zone.dnskeyAnswer(zone.rrsigDnskeyByKsk()));
        DefaultDnssecKeyCache cache = new DefaultDnssecKeyCache(4);
        DnssecValidator validator = DnssecValidator.newBuilder()
                .trustAnchors(zone.anchors())
                .fetcher(fetcher)
                .clock(zone.clock)
                .keyCache(cache)
                .build();

        assertEquals(DnssecStatus.SECURE, zone.run(validator, zone.answer()).status());
        assertEquals(1, cache.size());
        assertEquals(2, fetcher.queries().size());

        DnssecValidationResult second = zone.run(validator, zone.answer());
        assertEquals(DnssecStatus.SECURE, second.status(), second.toString());
        // Only the DS probe this time: the DNSKEY RRset came from the cache.
        assertEquals(1, second.budget().fetches());
        assertEquals(3, fetcher.queries().size());
    }

    @Test
    public void testNoopKeyCacheRemembersNothing() {
        DnssecKeyCache cache = DnssecKeyCache.noop();
        TestZone zone = new TestZone("example.");
        cache.put(zone.name, Collections.singletonList(zone.dnskey), 3600, 0L);
        assertNull(cache.get(zone.name, 0L));
        cache.clear();
    }

    @Test
    public void testBoundedKeyCacheExpiresAndEvicts() {
        DefaultDnssecKeyCache cache = new DefaultDnssecKeyCache(2);
        TestZone first = new TestZone("one.example.");
        TestZone second = new TestZone("two.example.");
        TestZone third = new TestZone("three.example.");

        cache.put(first.name, Collections.singletonList(first.dnskey), 10, 0L);
        List<DnsDnskeyRecord> found = cache.get(first.name, 1000L);
        assertNotNull(found);
        assertEquals(1, found.size());
        assertEquals(first.keyTag, found.get(0).keyTag());
        // The cache hands over records the caller owns.
        assertEquals(1, found.get(0).refCnt());
        ReferenceCountUtil.release(found.get(0));

        assertNull(cache.get(first.name, 10_001L), "the entry should have expired");

        cache.put(first.name, Collections.singletonList(first.dnskey), 10, 0L);
        cache.put(second.name, Collections.singletonList(second.dnskey), 10, 0L);
        cache.put(third.name, Collections.singletonList(third.dnskey), 10, 0L);
        assertEquals(2, cache.size());
        assertNull(cache.get(first.name, 0L), "the least recently used zone should have been evicted");
    }

    // -----------------------------------------------------------------------------------------------------------
    // Builder

    @Test
    public void testBuilderRejectsAVerifierThatDisagreesWithTheClock() {
        DnssecSignatureVerifier verifier =
                new DnssecSignatureVerifier(DnssecChainTestSupport.clock(), DnssecLimits.defaults());
        try {
            DnssecValidator.newBuilder()
                    .fetcher(new InMemoryFetcher(executor))
                    .verifier(verifier)
                    .clock(DnssecClock.SYSTEM)
                    .build();
            throw new AssertionError("expected an IllegalStateException");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("clock"), expected.getMessage());
        }
    }

    @Test
    public void testBuilderRequiresAFetcher() {
        try {
            DnssecValidator.newBuilder().build();
            throw new AssertionError("expected an IllegalStateException");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("fetcher"), expected.getMessage());
        }
    }

    // -----------------------------------------------------------------------------------------------------------
    // Fixtures

    private <T extends DnsRecord> T keep(T record) {
        owned.add(record);
        return record;
    }

    private static byte[] hash(String name) {
        return new DnsNsec3Hasher(new DnssecBudget(DnssecLimits.defaults(), DnssecClock.SYSTEM))
                .hash(DnsName.fromString(name), DnsNsec3Hasher.HASH_ALGORITHM_SHA1, NSEC3_ITERATIONS, NSEC3_SALT);
    }

    private void putDnskey(InMemoryFetcher fetcher, TestZone zone) {
        List<DnssecRecord> keys = list((DnssecRecord) zone.dnskey);
        fetcher.put(zone.name, DnsRecordType.DNSKEY, DnsResponseCode.NOERROR,
                list(zone.dnskey, keep(zone.sign(keys))), Collections.<DnsRecord>emptyList());
    }

    private void putSignedDelegation(InMemoryFetcher fetcher, TestZone parent, TestZone child) {
        DnsDsRecord ds = keep(parent.delegationTo(child, DnssecDigestType.SHA256));
        fetcher.put(child.name, DnsRecordType.DS, DnsResponseCode.NOERROR,
                list(ds, keep(parent.sign(list((DnssecRecord) ds)))), Collections.<DnsRecord>emptyList());
    }

    /**
     * A delegation the parent publishes no {@code DS} for: the {@code NSEC} has {@code NS} set and {@code DS} and
     * {@code SOA} clear, which is what RFC 6840, Section 4.4 requires before a referral may be called unsigned.
     */
    private void putUnsignedDelegation(InMemoryFetcher fetcher, TestZone parent, String child, String next) {
        DnsNsecRecord proof = keep(nsec(child, next, NS, RRSIG, NSEC));
        fetcher.put(DnsName.fromString(child), DnsRecordType.DS, DnsResponseCode.NOERROR,
                Collections.<DnsRecord>emptyList(), list(proof, keep(parent.sign(list(proof)))));
    }

    /**
     * A name inside the zone rather than a zone cut: no {@code DS}, and no {@code NS} either, so the walk carries
     * on with the same keys instead of calling anything insecure.
     */
    private void putNoDelegation(InMemoryFetcher fetcher, TestZone zone, String name, String next, int... types) {
        DnsNsecRecord proof = keep(nsec(name, next, types));
        fetcher.put(DnsName.fromString(name), DnsRecordType.DS, DnsResponseCode.NOERROR,
                Collections.<DnsRecord>emptyList(), list(proof, keep(zone.sign(list(proof)))));
    }

    /**
     * A {@code DS} probe at a name that does not exist, which is what the walk meets on the way down to a name
     * error: the answer is a name error of its own, carrying the same proof.
     */
    private void putNameErrorDsProbe(InMemoryFetcher fetcher, TestZone zone, String name, DnsNsecRecord covering) {
        fetcher.put(DnsName.fromString(name), DnsRecordType.DS, DnsResponseCode.NXDOMAIN,
                Collections.<DnsRecord>emptyList(), list(covering, keep(zone.sign(list(covering)))));
    }

    private DnssecValidationResult validate(TestZone anchorZone, InMemoryFetcher fetcher, String qname,
                                            DnsRecordType qtype, DefaultDnsResponse response) {
        return validate(anchorZone, fetcher, qname, qtype, DnssecLimits.defaults(), response);
    }

    private DnssecValidationResult validate(TestZone anchorZone, InMemoryFetcher fetcher, String qname,
                                            DnsRecordType qtype, DnssecLimits limits,
                                            DefaultDnsResponse response) {
        DnssecValidator validator = DnssecValidator.newBuilder()
                .trustAnchors(DnssecTrustAnchors.newBuilder().addAnchor(anchorZone.anchor()).build())
                .fetcher(fetcher)
                .limits(limits)
                .clock(DnssecChainTestSupport.clock())
                .keyCache(DnssecKeyCache.noop())
                .build();
        return run(validator, qname, qtype, response);
    }

    private DnssecValidationResult run(DnssecValidator validator, String qname, DnsRecordType qtype,
                                       DefaultDnsResponse response) {
        Future<DnssecValidationResult> future;
        try {
            future = validator.validate(DnsName.fromString(qname), qtype, response, executor);
        } finally {
            response.release();
        }
        assertTrue(future.isDone(), "the validation should have finished synchronously");
        assertTrue(future.isSuccess(), String.valueOf(future.cause()));
        return future.getNow();
    }

    private DnssecValidationResult limited(DnssecLimits limits) {
        Rfc4035Zone zone = new Rfc4035Zone();
        DnssecValidator validator = DnssecValidator.newBuilder()
                .trustAnchors(zone.anchors())
                .fetcher(zone.fetcher(zone.dnskeyAnswer(zone.rrsigDnskeyByKsk())))
                .limits(limits)
                .clock(zone.clock)
                .keyCache(DnssecKeyCache.noop())
                .build();
        return zone.run(validator, zone.answer());
    }

    /**
     * A clock that moves on by a fixed step every time it is read, so that a deadline can be reached without
     * anything actually taking time.
     */
    private static final class SteppingClock implements DnssecClock {

        private final long step;
        private long now;

        SteppingClock(long startMillis, long step) {
            now = startMillis;
            this.step = step;
        }

        @Override
        public long currentTimeMillis() {
            long value = now;
            now += step;
            return value;
        }
    }

    /**
     * A zone with a wildcard at {@code *.example.} and the single {@code NSEC} that both denies {@code a.example.}
     * and, matching the wildcard with {@code DS} and {@code CNAME} clear, answers the {@code DS} probe on the way
     * down. Canonical order puts {@code *.example.} before {@code a.example.} before {@code b.example.}, which is
     * what makes one record enough.
     */
    private final class Wildcard {

        private final TestZone zone = new TestZone("example.");
        private final InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        private final DnsNsecRecord wildcardNsec = keep(nsec("*.example.", "b.example.", MX, RRSIG, NSEC));

        Wildcard() {
            putDnskey(fetcher, zone);
            fetcher.put(DnsName.fromString("a.example."), DnsRecordType.DS, DnsResponseCode.NOERROR,
                    Collections.<DnsRecord>emptyList(), proof());
        }

        List<DnsRecord> proof() {
            return list((DnsRecord) wildcardNsec, keep(zone.sign(list(wildcardNsec))));
        }

        DnssecValidationResult validate(List<DnsRecord> authority) {
            // Labels 1 against a two-label owner is what says the answer came from *.example.
            DnssecRecord answer = keep(DnssecRRsetFixtures.rawRecord(DnsName.fromString("a.example."),
                    DnsRecordType.MX, 3600,
                    DnssecRRsetFixtures.concat(DnssecRRsetFixtures.hex("000a"),
                            DnsName.fromString("mail.example.").toWireBytes())));
            return DnssecValidatorTest.this.validate(zone, fetcher, "a.example.", DnsRecordType.MX,
                    response("a.example.", DnsRecordType.MX, DnsResponseCode.NOERROR,
                            list(answer, keep(zone.sign(list(answer), 1))), authority));
        }
    }

    /**
     * The RFC 4035 appendix A zone, built from the records the RFC publishes. Every signature here is the one the
     * RFC prints; none of them was made by this test.
     */
    private final class Rfc4035Zone {

        private final DnsName example = DnsName.fromString("example.");
        private final EventExecutor loop;
        private final DnssecClock clock;

        Rfc4035Zone() {
            this(DnssecRRsetFixtures.clockAt(DnssecRRsetFixtures.RFC4035_VALID_AT));
        }

        Rfc4035Zone(DnssecClock clock) {
            loop = executor;
            this.clock = clock;
        }

        Rfc4035Zone(EventExecutor loop) {
            this.loop = loop;
            clock = DnssecRRsetFixtures.clockAt(DnssecRRsetFixtures.RFC4035_VALID_AT);
        }

        /** {@code example. DNSKEY 257 3 5}, the key-signing key, tag 9465. */
        DnsDnskeyRecord ksk() {
            return keep(DnssecRRsetFixtures.dnskey(example, 257, 3, DnssecAlgorithm.RSASHA1,
                    "AQOeX7+baTmvpVHb2CcLnL1dMRWbuscRvHXlLnXwDzvqp4tZVKp1sZMepFb8MvxhhW3y/0QZ"
                            + "syCjczGJ1qk8vJe52iOhInKROVLRwxGpMfzPRLMlGybr51bOV/1se0ODacj3DomyB4QB5gKT"
                            + "Yot/K9alk5/j8vfd4jWCWD+E1Sze0Q=="));
        }

        DnsDnskeyRecord zsk() {
            return keep(DnssecRRsetFixtures.zoneSigningKey());
        }

        int kskKeyTag() {
            return ksk().keyTag();
        }

        byte[] kskDigest() {
            return DnssecDsMatcher.digest(DnssecDigestType.SHA256, example, ksk());
        }

        DnssecTrustAnchors anchors() {
            return DnssecTrustAnchors.newBuilder()
                    .addAnchor(new DnssecTrustAnchor(example, kskKeyTag(), DnssecAlgorithm.RSASHA1,
                            DnssecDigestType.SHA256, kskDigest()))
                    .build();
        }

        /** {@code example. RRSIG DNSKEY 5 1 3600 ... 9465 example.}, the key-signing key's own signature. */
        DnsRrsigRecord rrsigDnskeyByKsk() {
            return keep(DnssecRRsetFixtures.rrsig(example, DnsRecordType.DNSKEY, DnssecAlgorithm.RSASHA1, 1, 3600,
                    DnssecRRsetFixtures.RFC4035_EXPIRATION, DnssecRRsetFixtures.RFC4035_INCEPTION, kskKeyTag(),
                    example.toWireBytes(), base64(
                            "ZxgauAuIj+k1YoVEOSlZfx41fcmKzTFHoweZxYnz99JVQZJ33wFS0Q0jcP7VXKkaElXk9nYJ"
                                    + "XevO/7nAbo88iWsMkSpSR6jWzYYKwfrBI/L9hjYmyVO9m6FjQ7uwM4dCP/bIuV/DKqOAK9NY"
                                    + "NC3AHfvCV1Tp4VKDqxqG7R5tTVM=")));
        }

        /** {@code example. RRSIG DNSKEY 5 1 3600 ... 38519 example.}, the zone-signing key's signature. */
        DnsRrsigRecord rrsigDnskeyByZsk() {
            return keep(DnssecRRsetFixtures.rrsig(example, DnsRecordType.DNSKEY, DnssecAlgorithm.RSASHA1, 1, 3600,
                    DnssecRRsetFixtures.RFC4035_EXPIRATION, DnssecRRsetFixtures.RFC4035_INCEPTION,
                    DnssecRRsetFixtures.RFC4035_ZSK_KEY_TAG, example.toWireBytes(), base64(
                            "eGL0s90glUqcOmloo/2y+bSzyEfKVOQViD9ZDNhLz/Yn9CQZlDVRJffACQDAUhXpU/oP34ri"
                                    + "bKBpysRXosczFrKqS5Oa0bzMOfXCXup9qHApeFIku28Vqfr8Nt7cigZLxjK+u0Ws/4lIRjKk"
                                    + "7z5OXogYVaFzHKillDt3HRxHIZM=")));
        }

        /** {@code ai.example. A 192.0.2.9}. */
        DnssecRecord aiA() {
            return keep(DnssecRRsetFixtures.rawRecord(DnsName.fromString("ai.example."), DnsRecordType.A, 3600,
                    new byte[] { (byte) 192, 0, 2, 9 }));
        }

        DnsRrsigRecord rrsigAiA() {
            return keep(DnssecRRsetFixtures.rrsig(DnsName.fromString("ai.example."), DnsRecordType.A, 2, 3600,
                    DnssecRRsetFixtures.RFC4035_EXPIRATION, DnssecRRsetFixtures.RFC4035_INCEPTION, "example.",
                    "pAOtzLP2MU0tDJUwHOKE5FPIIHmdYsCgTb5BERGgpnJluA9ixOyf6xxVCgrEJW0WNZSsJicd"
                            + "hBHXfDmAGKUajUUlYSAH8tS4ZnrhyymIvk3uArDu2wfT130e9UHnumaHHMpUTosKe22PblOy"
                            + "6zrTpg9FkS0XGVmYRvOTNYx2HvQ="));
        }

        /**
         * {@code ai.example. NSEC b.example. A HINFO AAAA RRSIG NSEC} and its signature. The bit map has neither
         * {@code DS} nor {@code NS} nor {@code SOA}, which is exactly what says {@code ai.example.} is an ordinary
         * name inside {@code example.} and not a zone cut.
         */
        List<DnsRecord> aiNsecProof() {
            DnsNsecRecord record = keep(nsec("ai.example.", "b.example.", A, HINFO, AAAA, RRSIG, NSEC));
            DnsRrsigRecord signature = keep(DnssecRRsetFixtures.rrsig(DnsName.fromString("ai.example."),
                    DnsRecordType.NSEC, 2, 3600, DnssecRRsetFixtures.RFC4035_EXPIRATION,
                    DnssecRRsetFixtures.RFC4035_INCEPTION, "example.",
                    "QoshyPevLcJ/xcRpEtMft1uoIrcrieVcc9pGCScIn5Glnib40T6ayVOimXwdSTZ/8ISXGj4p"
                            + "P8Sh0PlA6olZQ84L453/BUqB8BpdOGky4hsN3AGcLEv1Gr0QMvirQaFcjzOECfnGyBm+wpFL"
                            + "AhS+JOVfDI/79QtyTI0SaDWcg8U="));
            return list((DnsRecord) record, signature);
        }

        List<DnsRecord> dnskeyAnswer(DnsRrsigRecord signature) {
            return list((DnsRecord) zsk(), ksk(), signature);
        }

        DnsRrsigRecord tamper(DnsRrsigRecord rrsig) {
            byte[] rdata = new byte[rrsig.content().readableBytes()];
            rrsig.content().getBytes(rrsig.content().readerIndex(), rdata);
            rdata[rdata.length - 1] ^= (byte) 0x01;
            return new DnsRrsigRecord(rrsig.name(), DnsRecordType.RRSIG, DnsRecord.CLASS_IN, 3600, rrsig.owner(),
                    Unpooled.wrappedBuffer(rdata));
        }

        InMemoryFetcher fetcher(List<DnsRecord> dnskeyAnswer) {
            InMemoryFetcher fetcher = new InMemoryFetcher(loop);
            fetcher.put(example, DnsRecordType.DNSKEY, DnsResponseCode.NOERROR, dnskeyAnswer,
                    Collections.<DnsRecord>emptyList());
            fetcher.put(DnsName.fromString("ai.example."), DnsRecordType.DS, DnsResponseCode.NOERROR,
                    Collections.<DnsRecord>emptyList(), aiNsecProof());
            return fetcher;
        }

        DnssecValidator validator(InMemoryFetcher fetcher) {
            return DnssecValidator.newBuilder()
                    .trustAnchors(anchors())
                    .fetcher(fetcher)
                    .clock(clock)
                    .keyCache(DnssecKeyCache.noop())
                    .build();
        }

        DefaultDnsResponse answer() {
            return response("ai.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                    list(aiA(), rrsigAiA()), aiNsecProof());
        }

        DnssecValidationResult validateAiExample(List<DnsRecord> dnskeyAnswer) {
            return validate(list(aiA(), rrsigAiA()), aiNsecProof(), dnskeyAnswer);
        }

        DnssecValidationResult validate(List<DnsRecord> answers, List<DnsRecord> authorities,
                                        List<DnsRecord> dnskeyAnswer) {
            return run(response("ai.example.", DnsRecordType.A, DnsResponseCode.NOERROR, answers, authorities),
                    dnskeyAnswer);
        }

        DnssecValidationResult run(DefaultDnsResponse response, List<DnsRecord> dnskeyAnswer) {
            return run(validator(fetcher(dnskeyAnswer)), response);
        }

        DnssecValidationResult run(DnssecValidator validator, DefaultDnsResponse response) {
            return DnssecValidatorTest.this.run(validator, "ai.example.", DnsRecordType.A, response);
        }

        private byte[] base64(String value) {
            return java.util.Base64.getMimeDecoder().decode(value);
        }
    }
}
