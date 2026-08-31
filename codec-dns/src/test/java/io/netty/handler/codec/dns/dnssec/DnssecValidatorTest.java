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
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.EXPIRATION;
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.INCEPTION;
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
import static io.netty.handler.codec.dns.dnssec.DnssecChainTestSupport.ns;
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
 * signed by {@link DnssecChainTestSupport} over freshly generated ECDSA P-256 zones.
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
     * because nothing outside the zone vouches for it.
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
     * Cancelling was never honoured — the walk ran on and the verdict was published into a promise that had
     * already been failed — so the future says so rather than accepting a cancellation it will not act on.
     */
    @Test
    public void testTheReturnedFutureCannotBeCancelled() {
        Rfc4035Zone zone = new Rfc4035Zone(new DefaultEventExecutor());
        DnssecValidator validator = zone.validator(zone.fetcher(zone.dnskeyAnswer(zone.rrsigDnskeyByKsk())));
        DefaultDnsResponse response = response("ai.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                list(zone.aiA(), zone.rrsigAiA()), zone.aiNsecProof());
        Future<DnssecValidationResult> future;
        try {
            future = validator.validate(DnsName.fromString("ai.example."), DnsRecordType.A, response, zone.loop);
        } finally {
            response.release();
        }
        try {
            assertFalse(future.cancel(true));
            assertFalse(future.isCancelled());
            assertEquals(DnssecStatus.SECURE, future.awaitUninterruptibly().getNow().status());
        } finally {
            zone.loop.shutdownGracefully(0, 0, TimeUnit.SECONDS).awaitUninterruptibly();
        }
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

    /**
     * A {@code DS} RRset cannot be synthesised from a wildcard —
     * <a href="https://www.rfc-editor.org/rfc/rfc4592.html#section-4.2">RFC 4592, Section 4.2</a> — so a
     * wildcard-expanded signature over one covers a name the parent never delegated. The owner name in the message
     * is not what the signature commits to, so one such signature authenticates a delegation at any name the
     * attacker cares to put in front of it.
     */
    @Test
    public void testWildcardExpandedDsDoesNotEstablishADelegation() {
        TestZone parent = new TestZone("example.");
        TestZone rogue = new TestZone("evil.example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, parent);
        putDnskey(fetcher, rogue);

        // Signed with Labels 1 against a two-label owner, so the signature covers *.example. and not evil.example.
        DnsDsRecord ds = keep(parent.delegationTo(rogue, DnssecDigestType.SHA256));
        fetcher.put(rogue.name, DnsRecordType.DS, DnsResponseCode.NOERROR,
                list(ds, keep(parent.sign(list((DnssecRecord) ds), 1))), Collections.<DnsRecord>emptyList());

        DnssecRecord answer = keep(a("evil.example.", "192.0.2.66"));
        DnssecValidationResult result = validate(parent, fetcher, "evil.example.", DnsRecordType.A,
                response("evil.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                        list(answer, keep(rogue.sign(list(answer)))), Collections.<DnsRecord>emptyList()));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertTrue(result.message().contains("wildcard"), result.message());
    }

    // -----------------------------------------------------------------------------------------------------------
    // Parent-side data

    /**
     * A {@code DS} RRset lives in the parent zone and is signed by the parent, see
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.2">RFC 4035, Section 5.2</a> and
     * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-5">RFC 4034, Section 5</a>. So the walk for a
     * {@code DS} query stops above the cut at the name that was asked about.
     */
    @Test
    public void testDsQueryIsAuthenticatedByTheParentZone() {
        TestZone parent = new TestZone("example.");
        TestZone child = new TestZone("sub.example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, parent);

        DnsDsRecord ds = keep(parent.delegationTo(child, DnssecDigestType.SHA256));
        DnssecValidationResult result = validate(parent, fetcher, "sub.example.", DnsRecordType.DS,
                response("sub.example.", DnsRecordType.DS, DnsResponseCode.NOERROR,
                        list(ds, keep(parent.sign(list((DnssecRecord) ds)))), Collections.<DnsRecord>emptyList()));

        assertEquals(DnssecStatus.SECURE, result.status(), result.toString());
        assertEquals(parent.name, result.signerName());
        // Nothing below example. is ever looked up, because the child has no say in its own delegation.
        assertEquals(list("example. " + DnsRecordType.DNSKEY), fetcher.queries());
    }

    /**
     * The reason the walk must stop there: a validator that descends through the cut verifies the {@code DS} with
     * the child's keys, so a rogue child can publish a {@code DS} for itself naming whatever key it likes and
     * mint the parent-to-child link the whole chain exists to establish.
     */
    @Test
    public void testChildMayNotSignItsOwnDsRrset() {
        TestZone parent = new TestZone("example.");
        TestZone child = new TestZone("sub.example.");
        TestZone rogue = new TestZone("sub.example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, parent);
        putDnskey(fetcher, child);
        putSignedDelegation(fetcher, parent, child);

        // A DS for sub.example. naming a key the parent never vouched for, signed by sub.example. itself.
        DnsDsRecord forged = keep(parent.delegationTo(rogue, DnssecDigestType.SHA256));
        DnssecValidationResult result = validate(parent, fetcher, "sub.example.", DnsRecordType.DS,
                response("sub.example.", DnsRecordType.DS, DnsResponseCode.NOERROR,
                        list(forged, keep(child.sign(list((DnssecRecord) forged)))),
                        Collections.<DnsRecord>emptyList()));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.KEY_TAG_NO_MATCH, result.reason());
        assertTrue(result.message().contains("keys of example."), result.message());
    }

    // -----------------------------------------------------------------------------------------------------------
    // Referrals

    /**
     * A referral says something about the names below the delegation it carries and nothing about anything else.
     * Here the walk has already established that {@code a.example.} is an ordinary name inside the signed zone,
     * and a genuine, publicly fetchable {@code NSEC} for an unsigned delegation on a different branch is replayed
     * into the authority section. Reporting Insecure for {@code a.example.} on the strength of it is a downgrade:
     * an application reads Insecure as "unsigned" and takes whatever the attacker sends next. This is the
     * relevance class of dnsjava's <a href="https://www.cve.org/CVERecord?id=CVE-2024-25638">CVE-2024-25638</a>.
     */
    @Test
    public void testReferralForAnUnrelatedNameDoesNotDowngradeTheAnswer() {
        TestZone zone = new TestZone("example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, zone);
        putNoDelegation(fetcher, zone, "a.example.", "b.example.", A, RRSIG, NSEC);

        DnsNsecRecord elsewhere = keep(nsec("sub.example.", "zz.example.", NS, RRSIG, NSEC));
        DnssecValidationResult result = validate(zone, fetcher, "a.example.", DnsRecordType.A,
                response("a.example.", DnsRecordType.A, DnsResponseCode.NOERROR,
                        Collections.<DnsRecord>emptyList(),
                        list(keep(ns("sub.example.", "ns1.attacker.")), elsewhere,
                                keep(zone.sign(list(elsewhere))))));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertNull(result.insecureDelegation());
    }

    /**
     * The control, and the one shape that reaches a referral legitimately: a {@code DS} query is answered by the
     * parent, so the walk stops above the cut and never probes it itself. An authenticated denial of the
     * {@code DS} for the very name that was asked about is a real statement about it.
     */
    @Test
    public void testReferralAtTheNameThatWasAskedAboutIsHonoured() {
        TestZone zone = new TestZone("example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, zone);

        DnsNsecRecord unsigned = keep(nsec("sub.example.", "zz.example.", NS, RRSIG, NSEC));
        DnssecValidationResult result = validate(zone, fetcher, "sub.example.", DnsRecordType.DS,
                response("sub.example.", DnsRecordType.DS, DnsResponseCode.NOERROR,
                        Collections.<DnsRecord>emptyList(),
                        list(keep(ns("sub.example.", "ns1.sub.example.")), unsigned,
                                keep(zone.sign(list(unsigned))))));

        assertEquals(DnssecStatus.INSECURE, result.status(), result.toString());
        assertEquals(DnssecFailureReason.UNSIGNED_DELEGATION, result.reason());
        assertEquals(DnsName.fromString("sub.example."), result.insecureDelegation());
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

    /**
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.4">RFC 4035, Section 5.4</a>: an {@code NSEC}
     * proves that wildcard expansion could not have been used only when its owner name has as many labels as the
     * Labels field of the {@code RRSIG} covering it. A zone with a wildcard publishes an {@code NSEC} at
     * {@code *.example.}, whose signature therefore covers the name {@code *.example.} and not the owner name in
     * the message — so the same signature and the same RDATA verify under any owner inside the zone. Re-owning it
     * turns one genuine record into an authenticated denial for a name of the attacker's choosing.
     */
    @Test
    public void testWildcardExpandedNsecIsNotADenialOfExistenceProof() {
        TestZone zone = new TestZone("example.");
        InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        putDnskey(fetcher, zone);
        // The walk's own DS probe: bank.example. is an ordinary name in the zone, and it really does have an MX.
        putNoDelegation(fetcher, zone, "bank.example.", "www.example.", A, MX, RRSIG, NSEC);

        DnsNsecRecord wildcard = keep(nsec("*.example.", "www.example.", A, RRSIG, NSEC));
        DnsRrsigRecord signature = keep(zone.sign(list(wildcard)));
        assertEquals(1, signature.labels());

        // The forgery: the zone's own signature, verbatim, over the same RDATA under a name of the attacker's
        // choosing. The type bit map has no MX, so it answers NODATA for a name whose MX exists.
        DnsNsecRecord reOwned = keep(nsec("bank.example.", "www.example.", A, RRSIG, NSEC));
        DnssecValidationResult result = validate(zone, fetcher, "bank.example.", DnsRecordType.MX,
                response("bank.example.", DnsRecordType.MX, DnsResponseCode.NOERROR,
                        Collections.<DnsRecord>emptyList(),
                        list(reOwned, keep(reOwn(signature, "bank.example.")))));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
        assertTrue(result.message().contains("wildcard"), result.message());
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
    // Algorithm downgrade

    /**
     * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.2">RFC 6840, Section 5.2</a> treats a zone
     * this build can evaluate <em>nothing</em> of as unsigned. It does not licence treating one RRset as unsigned
     * because the {@code RRSIG} left on it happens to name an algorithm this build cannot evaluate. The zone here
     * is mid-rollover and its ECDSA key signs everything, so an answer that does not validate against it is Bogus
     * — otherwise discarding the signatures made with the algorithm the validator implements would strip DNSSEC
     * from every multi-algorithm zone.
     */
    @Test
    public void testAnswerCarryingOnlyAnUnevaluatableRrsigIsBogus() {
        RolloverZone fixture = new RolloverZone();
        DnssecRecord answer = keep(a("www.example.", "192.0.2.66"));
        DnssecValidationResult result = fixture.validate(DnsRecordType.A,
                list((DnsRecord) answer, keep(fixture.unevaluatableRrsig("www.example.", DnsRecordType.A))),
                Collections.<DnsRecord>emptyList());

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
        assertNull(result.insecureDelegation());
    }

    /**
     * The same lever on the negative path, where the reason travels a longer way: the proof records are verified
     * by {@code collectProof}, which remembers why one was rejected, and the verdict is reported with that reason.
     * A reason meaning "could not evaluate" must not become the status of a zone the chain has already proven
     * secure.
     */
    @Test
    public void testDenialCarryingOnlyAnUnevaluatableRrsigIsBogus() {
        RolloverZone fixture = new RolloverZone();
        DnsNsecRecord proof = keep(nsec("www.example.", "zz.example.", A, RRSIG, NSEC));
        DnssecValidationResult result = fixture.validate(DnsRecordType.MX, Collections.<DnsRecord>emptyList(),
                list(proof, keep(fixture.unevaluatableRrsig("www.example.", DnsRecordType.NSEC))));

        assertEquals(DnssecStatus.BOGUS, result.status(), result.toString());
        assertEquals(DnssecFailureReason.DNSSEC_BOGUS, result.reason());
        assertNull(result.insecureDelegation());
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

    /**
     * The same {@code RRSIG} under a different owner name. RFC 4035, Section 5.3.2 rebuilds the owner the
     * signature covers from the Labels field, so the owner in the message is not part of what was signed and
     * re-owning one costs an attacker nothing.
     */
    private static DnsRrsigRecord reOwn(DnsRrsigRecord rrsig, String owner) {
        return DnssecRRsetFixtures.rrsig(DnsName.fromString(owner), rrsig.typeCovered(), rrsig.algorithm(),
                rrsig.labels(), rrsig.originalTtl(), rrsig.expiration(), rrsig.inception(), rrsig.keyTag(),
                rrsig.signerName().toWireBytes(), rrsig.signature());
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
     * A zone midway through an algorithm rollover: an ECDSA key that the trust anchor vouches for and that signs
     * everything, and a second key whose algorithm this build cannot evaluate. Both are authenticated, because the
     * {@code DNSKEY} RRset is signed as a whole, so an {@code RRSIG} naming the second one gets past the RFC 6840,
     * Section 5.12 check and reaches the point where the algorithm is found unusable.
     */
    private final class RolloverZone {

        private final TestZone zone = new TestZone("example.");
        private final InMemoryFetcher fetcher = new InMemoryFetcher(executor);
        private final DnsDnskeyRecord rollover =
                keep(DnssecRRsetFixtures.dnskey(zone.name, 256, 3, DnssecAlgorithm.DSA, "AQID"));

        RolloverZone() {
            assertFalse(DnssecAlgorithm.DSA.isSupported());
            List<DnssecRecord> keys = list((DnssecRecord) zone.dnskey, rollover);
            fetcher.put(zone.name, DnsRecordType.DNSKEY, DnsResponseCode.NOERROR,
                    list(zone.dnskey, rollover, keep(zone.sign(keys))), Collections.<DnsRecord>emptyList());
            putNoDelegation(fetcher, zone, "www.example.", "zz.example.", A, RRSIG, NSEC);
        }

        /** An {@code RRSIG} naming the unevaluatable key. Its signature is never reached, so it need not be real. */
        DnsRrsigRecord unevaluatableRrsig(String owner, DnsRecordType typeCovered) {
            return DnssecRRsetFixtures.rrsig(DnsName.fromString(owner), typeCovered, DnssecAlgorithm.DSA, 2, 3600,
                    EXPIRATION, INCEPTION, rollover.keyTag(), zone.name.toWireBytes(), new byte[] { 1, 2, 3, 4 });
        }

        DnssecValidationResult validate(DnsRecordType qtype, List<DnsRecord> answer, List<DnsRecord> authority) {
            return DnssecValidatorTest.this.validate(zone, fetcher, "www.example.", qtype,
                    response("www.example.", qtype, DnsResponseCode.NOERROR, answer, authority));
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
