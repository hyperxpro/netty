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
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.handler.codec.dns.DnsResponse;
import io.netty.handler.codec.dns.DnsResponseCode;
import io.netty.handler.codec.dns.DnsSection;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.ReferenceCounted;
import io.netty.util.concurrent.EventExecutor;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;
import io.netty.util.concurrent.Promise;
import io.netty.util.internal.ObjectUtil;
import io.netty.util.internal.PlatformDependent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Decides whether a DNS response is <em>Secure</em>, <em>Insecure</em>, <em>Bogus</em> or <em>Indeterminate</em>,
 * by walking the chain of trust from a configured trust anchor down to the name that was asked about.
 *
 * <p>This is the piece that turns the rest of the package into a validating stub resolver. The lookups it needs on
 * the way down are supplied by a {@link DnssecRecordFetcher}, so that {@code codec-dns} performs no I/O of its
 * own.
 *
 * <p><strong>A failure to <em>prove</em> security is {@link DnssecStatus#INSECURE} or
 * {@link DnssecStatus#INDETERMINATE}; only a proof of <em>inconsistency</em> is {@link DnssecStatus#BOGUS}.</strong>
 * Conflating the two is how half-validators become bypasses. Reporting a forgery as Insecure hands the attacker the
 * answer, because an application reads Insecure as "this zone is simply unsigned"; reporting an unsigned zone as
 * Bogus breaks most of the DNS and gets validation switched off. So Insecure is only ever reached through an actual
 * proof — an authenticated denial of the {@code DS} RRset at a delegation, an opt-out span, or a delegation whose
 * {@code DS} records name only algorithms this build cannot evaluate (RFC 6840, Section 5.2) — and never by giving
 * up.
 *
 * <p>Exceeding any of the {@link DnssecLimits} is Bogus for the same reason. If running out of budget were
 * Insecure, anyone able to force a limit breach would have a downgrade oracle.
 *
 * <ol>
 *   <li>The response's question must be the question that was asked. A response that answers something else is
 *   rejected before anything in it is examined.</li>
 *   <li>Only {@link DnsSection#ANSWER} and {@link DnsSection#AUTHORITY} are validation input.
 *   {@link DnsSection#ADDITIONAL} is never authenticated and is never consulted, which is the shape of Unbound's
 *   <a href="https://www.cve.org/CVERecord?id=CVE-2026-42960">CVE-2026-42960</a>. Of the authority section only the
 *   {@code NSEC} and {@code NSEC3} records are authenticated, and only those the verdict rests on; a {@code SOA} or
 *   an {@code NS} that arrives there is read for the shape of the response and is never treated as authentic, so a
 *   caller must not use one for negative caching on the strength of a {@link DnssecStatus#SECURE} verdict.</li>
 *   <li>Every RRset in the answer section must be part of the chain from the question to the answer — the answer
 *   itself, or a {@code CNAME} or {@code DNAME} link on the way to it. A record that is merely present is not
 *   ignored, it is a reason to reject the response, because a verdict that covers only part of a message is a
 *   verdict an application will apply to all of it. That is dnsjava's
 *   <a href="https://www.cve.org/CVERecord?id=CVE-2024-25638">CVE-2024-25638</a>.</li>
 *   <li>An RRset is only ever verified against the keys of the zone the <em>chain walk</em> arrived at, and only
 *   if its owner name lies within that zone. The Signer's Name an {@code RRSIG} claims is never what decides which
 *   zone a record belongs to.</li>
 *   <li>A {@code DS} RRset is parent-side data, so a {@code DS} query is answered by the parent: the walk stops
 *   above the delegation at the queried name rather than descending through it. An authority section is read as a
 *   referral only when the queried name lies under the delegation it carries.</li>
 *   <li>Only a signature that covers the owner name a record arrived under authenticates that owner name. A
 *   wildcard-expanded signature covers a name above it and verifies under any owner, so it can authenticate an
 *   answer, which then needs a denial of existence with it, and nothing whose meaning is its owner name.</li>
 * </ol>
 *
 * <p>The walk is a chain of ordinary asynchronous continuations over an immutable context. Nothing deep-copies or
 * resumes partially validated message state, and no section counts are maintained alongside the lists they
 * describe — every count is derived from the list. Unbound's suspend and resume machinery, added to survive
 * KeyTrap, is where <a href="https://www.cve.org/CVERecord?id=CVE-2026-33278">CVE-2026-33278</a> (arbitrary code
 * execution from a dangling pointer left across a suspended {@code DS} sub-query) and
 * <a href="https://www.cve.org/CVERecord?id=CVE-2026-42959">CVE-2026-42959</a> (a write offset counted separately
 * from the array it indexed) came from. Java removes the memory unsafety but not the logical desync, so the answer
 * here is to bound the work hard and fail rather than to save and restore it.
 *
 * <p>One {@link DnssecBudget} is created per {@code validate} call and threaded through every path. Nothing resets
 * it, which is what Unbound's <a href="https://www.cve.org/CVERecord?id=CVE-2026-50045">CVE-2026-50045</a> got
 * wrong, and its counters are readable afterwards through {@link DnssecValidationResult#budget()}.
 *
 * <p>A validator is immutable and shareable. Each call allocates its own state, its own budget and its own trace,
 * and every continuation runs on the {@link EventExecutor} passed to
 * {@link #validate(DnsName, DnsRecordType, DnsResponse, EventExecutor)}, so validation state is never touched from
 * two threads. A {@link DnssecRecordFetcher}'s future may complete anywhere; the validator hops back before
 * looking at anything.
 *
 * <p><strong>The response may be released the instant {@code validate} returns.</strong> Everything the validation
 * needs from it is retained synchronously inside the call, before the first suspension, and released again from a
 * single hook that runs on success, on failure and on cancellation alike. {@link DnssecValidationResult} holds no
 * buffers at all, so a caller never has to release a verdict.
 *
 * <p>Nothing is published or cached until the whole chain has a verdict. The only exception is deliberate and is
 * itself a completed proof: an apex {@code DNSKEY} RRset goes into the {@link DnssecKeyCache} once a trust anchor
 * or a parent {@code DS} has matched one specific key and an {@code RRSIG} <em>made by that key</em> has validated
 * over the whole RRset.
 *
 * <p>The response must have been decoded with {@link DnssecDnsRecordDecoder}; records from the default decoder do
 * not carry the wire form of their owner names, so nothing signed over them can be reconstructed and validation
 * fails closed.
 *
 * <pre>{@code
 * DnssecValidator validator = DnssecValidator.newBuilder()
 *         .trustAnchors(DnssecTrustAnchors.iana())
 *         .fetcher(myFetcher)                       // MUST send DO=1 and CD=1
 *         .build();
 *
 * Future<DnssecValidationResult> f =
 *         validator.validate(qname, DnsRecordType.A, response, ch.eventLoop());
 * response.release();                               // safe immediately
 * }</pre>
 */
public final class DnssecValidator {

    private static final int TYPE_CNAME = DnsRecordType.CNAME.intValue();
    private static final int TYPE_DNAME = DnsRecordType.DNAME.intValue();
    private static final int TYPE_DS = DnsRecordType.DS.intValue();
    private static final int TYPE_NS = DnsRecordType.NS.intValue();
    private static final int TYPE_SOA = DnsRecordType.SOA.intValue();
    private static final int TYPE_NSEC = DnsRecordType.NSEC.intValue();
    private static final int TYPE_NSEC3 = DnsRecordType.NSEC3.intValue();

    private final DnssecTrustAnchors trustAnchors;
    private final DnssecRecordFetcher fetcher;
    private final DnssecSignatureVerifier verifier;
    private final DnssecLimits limits;
    private final DnssecKeyCache keyCache;
    private final DnssecClock clock;
    private final EventExecutor defaultExecutor;

    DnssecValidator(DnssecTrustAnchors trustAnchors, DnssecRecordFetcher fetcher, DnssecSignatureVerifier verifier,
                    DnssecLimits limits, DnssecKeyCache keyCache, DnssecClock clock, EventExecutor defaultExecutor) {
        this.trustAnchors = trustAnchors;
        this.fetcher = fetcher;
        this.verifier = verifier;
        this.limits = limits;
        this.keyCache = keyCache;
        this.clock = clock;
        this.defaultExecutor = defaultExecutor;
    }

    /**
     * Returns a builder. {@link DnssecValidatorBuilder#fetcher(DnssecRecordFetcher)} is the only required setting.
     */
    public static DnssecValidatorBuilder newBuilder() {
        return new DnssecValidatorBuilder();
    }

    /**
     * Returns the trust anchors the chain of trust starts from.
     */
    public DnssecTrustAnchors trustAnchors() {
        return trustAnchors;
    }

    /**
     * Returns how the {@code DNSKEY} and {@code DS} lookups are performed.
     */
    public DnssecRecordFetcher fetcher() {
        return fetcher;
    }

    /**
     * Returns the signature verifier, whose clock and limits are also this validator's.
     */
    public DnssecSignatureVerifier verifier() {
        return verifier;
    }

    /**
     * Returns the hardening limits.
     */
    public DnssecLimits limits() {
        return limits;
    }

    /**
     * Returns where validated {@code DNSKEY} RRsets are remembered.
     */
    public DnssecKeyCache keyCache() {
        return keyCache;
    }

    /**
     * Returns the clock signature validity and the validation deadline are judged against.
     */
    public DnssecClock clock() {
        return clock;
    }

    /**
     * Validates {@code response} on the executor configured with
     * {@link DnssecValidatorBuilder#executor(EventExecutor)}.
     *
     * @throws IllegalStateException if no executor was configured.
     */
    public Future<DnssecValidationResult> validate(DnsName qname, DnsRecordType qtype, DnsResponse response) {
        if (defaultExecutor == null) {
            throw new IllegalStateException("no executor was configured on the builder; use the four-argument "
                    + "validate(...) or set one");
        }
        return validate(qname, qtype, response, defaultExecutor);
    }

    /**
     * Validates {@code response} as the answer to {@code qname}/{@code qtype} in class {@code IN}.
     *
     * <p>Everything the validation needs is retained before this method returns, so {@code response} may be
     * released as soon as it does. The returned future completes on {@code executor} with a
     * {@link DnssecValidationResult}; it fails only if {@code executor} refused to run the validation at all, and
     * it cannot be cancelled.
     *
     * @param qname    the name that was asked about, in wire form. Not the name in the response: the two are
     *                 compared, and a response that answers a different question is rejected.
     * @param qtype    the RR type that was asked about.
     * @param response the response to validate, decoded with {@link DnssecDnsRecordDecoder}. Neither retained
     *                 beyond this call nor released nor modified.
     * @param executor the executor every continuation of this validation runs on.
     * @return a future that completes with the verdict.
     */
    public Future<DnssecValidationResult> validate(DnsName qname, DnsRecordType qtype, DnsResponse response,
                                                   EventExecutor executor) {
        ObjectUtil.checkNotNull(qname, "qname");
        ObjectUtil.checkNotNull(qtype, "qtype");
        ObjectUtil.checkNotNull(response, "response");
        ObjectUtil.checkNotNull(executor, "executor");

        Promise<DnssecValidationResult> promise = executor.newPromise();
        // There is nothing a cancellation could stop: the walk is a chain of continuations over records already in
        // hand, waiting only on fetches the caller supplied. Accepting one and carrying on regardless would leave
        // the caller holding a future that says cancelled while the verdict goes nowhere.
        promise.setUncancellable();
        // Retaining happens here, on the caller's thread, and not after a hop: otherwise the caller could release
        // the response in the window between this method returning and the hop running.
        Validation validation = new Validation(qname, qtype, response, executor, promise);
        try {
            if (executor.inEventLoop()) {
                validation.run();
            } else {
                executor.execute(validation);
            }
        } catch (Throwable t) {
            validation.abort(t);
        }
        return promise;
    }

    @Override
    public String toString() {
        return "DnssecValidator(" + trustAnchors + ", " + limits + ')';
    }

    private static DnsRRset findRRset(List<DnsRRset> rrsets, DnsName owner, DnsRecordType type) {
        for (int i = 0; i < rrsets.size(); i++) {
            DnsRRset rrset = rrsets.get(i);
            if (rrset.type().intValue() == type.intValue() && rrset.dnsClass() == DnsRecord.CLASS_IN
                    && rrset.owner().equals(owner)) {
                return rrset;
            }
        }
        return null;
    }

    /**
     * The state of one {@code validate} call. Confined to its {@link EventExecutor} from {@link #run()} onwards;
     * the constructor runs on the caller's thread and the {@code executor.execute} that follows it publishes
     * everything it wrote.
     */
    private final class Validation implements Runnable {

        private final DnsName qname;
        private final DnsRecordType qtype;
        private final EventExecutor executor;
        private final Promise<DnssecValidationResult> promise;
        private final DnssecBudget budget;
        private final DnsResponseCode responseCode;
        private final boolean truncated;

        private final List<String> trace = new ArrayList<String>();
        private final List<ReferenceCounted> retained = new ArrayList<ReferenceCounted>();
        private final Map<DnsName, List<DnsDnskeyRecord>> establishedKeys =
                new HashMap<DnsName, List<DnsDnskeyRecord>>();
        private final Set<DnsName> provenNoDelegation = new HashSet<DnsName>();
        private final Set<DnsRRset> consumedAnswers = new HashSet<DnsRRset>();

        private List<DnsRRset> answerRrsets = Collections.emptyList();
        private List<DnsRRset> authorityRrsets = Collections.emptyList();

        private DnssecFailureReason startupReason;
        private String startupMessage;

        // Both are written on the executor by complete() and read, and written, by abort() on whichever thread
        // could not hand the validation over to it. Everything else here is confined to the executor.
        private volatile ScheduledFuture<?> timeoutTask;
        private volatile boolean finished;

        private List<DnsName> chainNames = Collections.emptyList();
        private int chainIndex;
        private DnsName signingZone;
        private List<DnsDnskeyRecord> signingKeys = Collections.emptyList();
        private List<DnssecTrustAnchor> chainAnchors = Collections.emptyList();
        private DnsName currentName;

        private DnssecFailureReason proofFailureReason;
        private String proofFailureMessage;

        Validation(DnsName qname, DnsRecordType qtype, DnsResponse response, EventExecutor executor,
                   Promise<DnssecValidationResult> promise) {
            this.qname = qname;
            this.qtype = qtype;
            this.executor = executor;
            this.promise = promise;
            currentName = qname;
            budget = new DnssecBudget(limits, clock);
            responseCode = response.code();
            truncated = response.isTruncated();

            boolean retainedEverything = false;
            try {
                retainSection(response, DnsSection.ANSWER);
                retainSection(response, DnsSection.AUTHORITY);
                retainedEverything = true;
            } finally {
                if (!retainedEverything) {
                    releaseRetained();
                }
            }

            // From here on nothing is allowed to escape the constructor: a verdict is recorded instead and run()
            // reports it, so that every exit from a validation goes through the same completion path.
            try {
                if (checkRelevance(response)) {
                    answerRrsets = DnsRRset.group(response, DnsSection.ANSWER, limits);
                    authorityRrsets = DnsRRset.group(response, DnsSection.AUTHORITY, limits);
                }
            } catch (DnssecException e) {
                recordStartupFailure(reasonOf(e), e.getMessage());
            } catch (RuntimeException e) {
                recordStartupFailure(DnssecFailureReason.INTERNAL_ERROR, "grouping the response failed: " + e);
            }
        }

        @Override
        public void run() {
            try {
                if (startupReason != null) {
                    complete(startupReason, startupMessage);
                    return;
                }
                armTimeout();
                budget.checkDeadline();
                if (truncated) {
                    // Records are missing by construction, so any proof built from what arrived would be judging
                    // an incomplete message. Retrying over TCP is the caller's job; Bogus here would name the
                    // wrong culprit.
                    complete(DnssecFailureReason.DNSSEC_INDETERMINATE, "the response is truncated, so it cannot be "
                            + "validated as it stands; retry it over TCP and validate the complete answer");
                    return;
                }
                if (!isValidatable(responseCode)) {
                    complete(DnssecFailureReason.DNSSEC_INDETERMINATE, "the response code is " + responseCode
                            + ", so there is neither an answer nor a denial of existence to validate");
                    return;
                }
                resolveName(qname);
            } catch (DnssecException e) {
                complete(reasonOf(e), String.valueOf(e.getMessage()));
            } catch (Throwable t) {
                internalError(t);
            }
        }

        /**
         * Ends the validation because it could not be started, or could not be resumed, at all: in practice the
         * executor refused to run it. Everything retained is released here, since no continuation will ever run to
         * do it, and the wall-clock backstop is cancelled so that nothing is left scheduled against a validation
         * that has ended.
         */
        void abort(Throwable cause) {
            if (finished) {
                return;
            }
            finished = true;
            cancelTimeout();
            releaseRetained();
            promise.tryFailure(cause);
        }

        /**
         * Rejects a response that does not answer the question that was asked. Done before anything in the message
         * is examined, so that irrelevant records are discarded rather than validated and then ignored.
         */
        private boolean checkRelevance(DnsResponse response) {
            int count = response.count(DnsSection.QUESTION);
            if (count != 1) {
                recordStartupFailure(DnssecFailureReason.BAILIWICK_VIOLATION, "the response has " + count
                        + " question(s); exactly one is needed to tell whether it answers what was asked");
                return false;
            }
            DnsRecord question = response.recordAt(DnsSection.QUESTION, 0);
            if (question.type().intValue() != qtype.intValue()) {
                recordStartupFailure(DnssecFailureReason.BAILIWICK_VIOLATION, "the response answers a question of "
                        + "type " + question.type() + ", but " + qtype + " was asked");
                return false;
            }
            if (question.dnsClass() != DnsRecord.CLASS_IN) {
                recordStartupFailure(DnssecFailureReason.BAILIWICK_VIOLATION, "the response answers a question of "
                        + "class " + question.dnsClass() + "; this validator handles class IN only");
                return false;
            }
            DnsName asked;
            try {
                asked = DnsName.fromString(question.name());
            } catch (RuntimeException e) {
                recordStartupFailure(DnssecFailureReason.NAME_NOT_REPRESENTABLE, "the question name of the response,"
                        + " \"" + question.name() + "\", is not a name this validator can compare: " + e);
                return false;
            }
            if (!asked.equals(qname)) {
                recordStartupFailure(DnssecFailureReason.BAILIWICK_VIOLATION, "the response answers " + asked
                        + " but " + qname + " was asked");
                return false;
            }
            return true;
        }

        private boolean isValidatable(DnsResponseCode code) {
            return code.intValue() == DnsResponseCode.NOERROR.intValue()
                    || code.intValue() == DnsResponseCode.NXDOMAIN.intValue();
        }

        /**
         * Starts, or restarts after a {@code CNAME} or {@code DNAME}, the walk from the deepest trust anchor that
         * covers {@code name} down to {@code name} itself.
         */
        private void resolveName(DnsName name) {
            budget.checkDeadline();
            currentName = name;
            DnsName target = chainTarget(name);
            DnsName anchorName = trustAnchors.deepestAnchorName(target);
            if (anchorName == null) {
                complete(DnssecFailureReason.NO_TRUST_ANCHOR, "no trust anchor is configured for " + target
                        + " or any of its ancestors, so this validator has no opinion about it");
                return;
            }
            List<DnssecTrustAnchor> configured = trustAnchors.anchorsFor(target);
            long now = clock.currentTimeMillis();
            List<DnssecTrustAnchor> usable = new ArrayList<DnssecTrustAnchor>(configured.size());
            int outsideWindow = 0;
            int unsupported = 0;
            for (int i = 0; i < configured.size(); i++) {
                DnssecTrustAnchor anchor = configured.get(i);
                if (!anchor.isValidAt(now)) {
                    outsideWindow++;
                } else if (!anchor.algorithm().isSupported() || !anchor.digestType().isSupported()) {
                    unsupported++;
                } else {
                    usable.add(anchor);
                }
            }
            if (usable.isEmpty()) {
                // Deliberately not falling back to an anchor at a shallower name: configuring one for a subtree is
                // a statement about where that subtree's chain of trust starts, and quietly using the root instead
                // would produce a Secure answer through a chain the operator overrode.
                complete(DnssecFailureReason.NO_TRUST_ANCHOR, "the " + configured.size() + " trust anchor(s) at "
                        + anchorName + " are unusable (" + outsideWindow + " outside their validity window at "
                        + now + ", " + unsupported + " naming an algorithm or digest type this build cannot "
                        + "evaluate), and anchors at a shallower name are not used as a fallback");
                return;
            }
            chainAnchors = usable;
            chainNames = namesFrom(anchorName, target);
            chainIndex = 0;
            signingZone = null;
            signingKeys = Collections.emptyList();
            trace("chain for " + name + " starts at the trust anchor for " + anchorName);
            stepChain();
        }

        /**
         * The deepest name the walk has to reach before the answer can be judged: {@code name} itself, except for
         * a {@code DS} query.
         *
         * <p>A {@code DS} RRset is parent-side data. It lives in the parent zone and only the parent signs it, see
         * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.2">RFC 4035, Section 5.2</a> and
         * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-5">RFC 4034, Section 5</a>. Descending
         * through the cut at {@code name} and then verifying the answer with the child's own keys would let a
         * child publish a {@code DS} for itself naming whatever key it liked, minting the parent-to-child link
         * the chain of trust exists to establish. The root is its own parent and answers {@code . DS} itself.
         */
        private DnsName chainTarget(DnsName name) {
            return qtype.intValue() == TYPE_DS ? name.parent() : name;
        }

        /**
         * Advances the walk by one label. Each step either establishes a zone's keys or asks whether there is a
         * delegation at the next name down.
         */
        private void stepChain() {
            budget.checkDeadline();
            if (chainIndex >= chainNames.size()) {
                answerFor(currentName);
                return;
            }
            DnsName name = chainNames.get(chainIndex);
            if (chainIndex == 0) {
                establishKeys(name, chainAnchors, null);
                return;
            }
            if (provenNoDelegation.contains(name)) {
                chainIndex++;
                stepChain();
                return;
            }
            List<DnsDnskeyRecord> known = establishedKeys.get(name);
            if (known != null) {
                adoptKeys(name, known);
                return;
            }
            budget.spendDelegation();
            budget.spendFetch();
            trace("looking up DS " + name);
            fetch(name, DnsRecordType.DS, new DsListener(name));
        }

        /**
         * Obtains the apex {@code DNSKEY} RRset of {@code zone} and authenticates it, either against the trust
         * anchors or against the {@code DS} records the parent published.
         */
        private void establishKeys(DnsName zone, List<DnssecTrustAnchor> anchors, List<DnsDsRecord> dsRecords) {
            List<DnsDnskeyRecord> known = establishedKeys.get(zone);
            if (known == null) {
                known = keyCache.get(zone, clock.currentTimeMillis());
                if (known != null && known.isEmpty()) {
                    known = null;
                }
                if (known != null) {
                    // The cache hands over freshly built records; this validation owns and releases them.
                    for (int i = 0; i < known.size(); i++) {
                        retained.add(known.get(i));
                    }
                    establishedKeys.put(zone, known);
                    trace("DNSKEY " + zone + " taken from the key cache (" + known.size() + " key(s))");
                }
            }
            if (known != null) {
                adoptKeys(zone, known);
                return;
            }
            budget.spendFetch();
            trace("looking up DNSKEY " + zone);
            fetch(zone, DnsRecordType.DNSKEY, new DnskeyListener(zone, anchors, dsRecords));
        }

        private void adoptKeys(DnsName zone, List<DnsDnskeyRecord> keys) {
            signingZone = zone;
            signingKeys = keys;
            chainIndex++;
            stepChain();
        }

        private void answerFor(DnsName name) {
            budget.checkDeadline();
            DnsRRset answer = findRRset(answerRrsets, name, qtype);
            if (answer != null) {
                if (!verifyAnswerRrset(answer, "answer")) {
                    return;
                }
                if (!checkAnswerSectionAccountedFor()) {
                    return;
                }
                complete(DnssecFailureReason.NONE, "the " + name + ' ' + qtype + " RRset is authenticated by "
                        + signingZone, signingZone, null, null);
                return;
            }
            if (qtype.intValue() != TYPE_CNAME) {
                DnsRRset cname = findRRset(answerRrsets, name, DnsRecordType.CNAME);
                if (cname != null) {
                    followCname(name, cname);
                    return;
                }
            }
            // A DNAME redirects a query of any type, RFC 6672, Section 3.4.1, so this one is not gated on QTYPE.
            DnsRRset dname = findDname(name);
            if (dname != null) {
                followDname(name, dname);
                return;
            }
            negativeAnswer(name);
        }

        private void followCname(DnsName name, DnsRRset cname) {
            if (!verifyAnswerRrset(cname, "CNAME")) {
                return;
            }
            DnsName target = singleNameRdata(cname);
            if (target == null) {
                return;
            }
            budget.spendCnameLink();
            trace("CNAME " + name + " -> " + target);
            resolveName(target);
        }

        private void followDname(DnsName name, DnsRRset dname) {
            if (!verifyAnswerRrset(dname, "DNAME")) {
                return;
            }
            DnsName target = singleNameRdata(dname);
            if (target == null) {
                return;
            }
            DnsName synthesized = synthesizeFromDname(name, dname.owner(), target);
            if (synthesized == null) {
                return;
            }
            // RFC 6672, Section 5.3.3: the CNAME a server synthesises alongside a DNAME carries no signature of its
            // own, because it was never in the zone. It is accounted for so that the answer section is fully
            // explained, and then ignored in favour of the name derived here.
            DnsRRset serverSynthesized = findRRset(answerRrsets, name, DnsRecordType.CNAME);
            if (serverSynthesized != null) {
                consumedAnswers.add(serverSynthesized);
            }
            budget.spendCnameLink();
            trace("DNAME " + dname.owner() + " -> " + target + " rewrites " + name + " to " + synthesized);
            resolveName(synthesized);
        }

        /**
         * Verifies one answer-section RRset against the keys of the zone the walk arrived at, and, if it turns out
         * to be a wildcard expansion, insists on the denial of existence that has to accompany one.
         *
         * @return {@code true} if it is authentic; {@code false} if the validation has been completed with a
         *         failure.
         */
        private boolean verifyAnswerRrset(DnsRRset rrset, String what) {
            consumedAnswers.add(rrset);
            if (rrset.dnsClass() != DnsRecord.CLASS_IN) {
                complete(DnssecFailureReason.DNSSEC_BOGUS, "the " + what + " RRset " + rrset.owner() + ' '
                        + rrset.type() + " is class " + rrset.dnsClass() + "; this validator handles class IN only");
                return false;
            }
            if (!rrset.owner().equalsOrIsSubDomainOf(signingZone)) {
                complete(DnssecFailureReason.BAILIWICK_VIOLATION, "the " + what + " RRset " + rrset.owner() + ' '
                        + rrset.type() + " lies outside " + signingZone + ", the zone the chain of trust arrived "
                        + "at, so no key this validator trusts can have signed it");
                return false;
            }
            DnssecVerificationResult result = verifier.verify(rrset, signingKeys, budget);
            if (!result.isSecure()) {
                complete(notADowngrade(result.reason()), "the " + what + " RRset " + rrset.owner() + ' '
                        + rrset.type() + " did not validate against the keys of " + signingZone + ": "
                        + result.message());
                return false;
            }
            trace(what + ' ' + rrset.owner() + ' ' + rrset.type() + " verified: " + result.message());
            return !result.isWildcardExpanded() || checkWildcardProof(rrset, result);
        }

        /**
         * RFC 4035, Section 5.3.4: a wildcard-expanded answer is authentic only together with a proof that the
         * queried name does not exist. Without it a valid wildcard signature can be replayed over a name the zone
         * answers explicitly, substituting one authentic answer for another.
         */
        private boolean checkWildcardProof(DnsRRset rrset, DnssecVerificationResult result) {
            List<DnsRecord> proof = collectProof(authorityRrsets, signingZone, signingKeys);
            if (proof == null) {
                return false;
            }
            DnssecDenialOfExistence.Result denial = new DnssecDenialOfExistence(signingZone, budget)
                    .proveWildcardAnswer(rrset.owner(), result.signedOwner(), proof);
            if (denial.status() == DnssecStatus.SECURE) {
                trace("the wildcard expansion of " + result.signedOwner() + " onto " + rrset.owner()
                        + " is covered by a denial of existence for " + rrset.owner());
                return true;
            }
            if (denial.status() == DnssecStatus.INSECURE) {
                complete(denial.reason(), "the answer for " + rrset.owner() + " was expanded from the wildcard "
                        + result.signedOwner() + " and the proof that no closer match exists is not authenticated: "
                        + denial.reason());
                return false;
            }
            complete(proofFailureReason != null ? proofFailureReason : DnssecFailureReason.WILDCARD_PROOF_MISSING,
                    "the answer for " + rrset.owner() + " was expanded from the wildcard " + result.signedOwner()
                            + " but no authenticated proof that " + rrset.owner() + " does not exist accompanies "
                            + "it, so the answer cannot be distinguished from a replay over a name the zone "
                            + "defines" + describeProofFailure());
            return false;
        }

        /**
         * Rejects a response whose answer section holds an RRset that is not part of the chain from the question to
         * the answer. Validating the parts that happen to be relevant and staying silent about the rest is
         * CVE-2024-25638: the caller applies the verdict to the whole message.
         */
        private boolean checkAnswerSectionAccountedFor() {
            for (int i = 0; i < answerRrsets.size(); i++) {
                DnsRRset rrset = answerRrsets.get(i);
                if (!consumedAnswers.contains(rrset)) {
                    complete(DnssecFailureReason.BAILIWICK_VIOLATION, "the answer section also holds "
                            + rrset.owner() + ' ' + rrset.type() + ", which is no part of the chain from " + qname
                            + ' ' + qtype + " to the answer; a verdict that covered only the rest of the section "
                            + "would still be applied to it");
                    return false;
                }
            }
            return true;
        }

        private void negativeAnswer(DnsName name) {
            // Before anything else: a response with no answer for QNAME has no business carrying answer-section
            // records at all, and one that does gets the same treatment as a positive answer with an intruder in
            // it rather than a pass because the verdict happened to come from the authority section.
            if (!checkAnswerSectionAccountedFor()) {
                return;
            }
            DnsRRset referral = findReferral(name);
            List<DnsRecord> proof = collectProof(authorityRrsets, signingZone, signingKeys);
            if (proof == null) {
                return;
            }
            DnssecDenialOfExistence denial = new DnssecDenialOfExistence(signingZone, budget);
            if (referral != null) {
                handleReferral(name, referral, denial, proof);
                return;
            }
            DnssecDenialOfExistence.Result result;
            String what;
            if (responseCode.intValue() == DnsResponseCode.NXDOMAIN.intValue()) {
                what = "the name error for " + name;
                result = denial.proveNameError(name, proof);
            } else {
                what = "the absence of " + name + ' ' + qtype;
                result = denial.proveNoData(name, qtype, proof);
            }
            if (result.status() == DnssecStatus.SECURE) {
                complete(DnssecFailureReason.NONE, what + " is proven by " + signingZone, signingZone, null, null);
            } else if (result.status() == DnssecStatus.INSECURE) {
                complete(result.reason(), what + " is not authenticated: " + result.reason());
            } else {
                complete(proofFailureReason != null ? proofFailureReason : result.reason(),
                        what + " is not proven: " + result.reason() + describeProofFailure());
            }
        }

        /**
         * A referral is a response with no answer whose authority section delegates to a child zone. It is not an
         * answer, but proving the delegation unsigned is a real verdict about everything below it.
         */
        private void handleReferral(DnsName name, DnsRRset referral, DnssecDenialOfExistence denial,
                                    List<DnsRecord> proof) {
            DnsName child = referral.owner();
            DnssecDenialOfExistence.Result unsigned = denial.proveUnsignedDelegation(child, proof);
            if (unsigned.status() == DnssecStatus.INSECURE) {
                complete(unsigned.reason(), "the referral of " + name + " to " + child + " is proven to lead to an "
                        + "unsigned zone", null, child, null);
                return;
            }
            DnsRRset ds = findRRset(authorityRrsets, child, DnsRecordType.DS);
            if (ds != null && authenticatesItsOwnerName(verifier.verify(ds, signingKeys, budget))) {
                complete(DnssecFailureReason.DNSSEC_INDETERMINATE, "the response is a referral to the signed zone "
                        + child + " rather than an answer for " + name + ' ' + qtype);
                return;
            }
            complete(proofFailureReason != null ? proofFailureReason : unsigned.reason(), "the referral of " + name
                    + " to " + child + " carries neither an authenticated DS RRset nor an authenticated proof that "
                    + "there is none" + describeProofFailure());
        }

        /**
         * Returns the {@code NS} RRset of a referral, that is one owned by a strict subdomain of the zone the walk
         * arrived at and by an ancestor-or-equal of {@code name}, in a response that carries no {@code SOA} of its
         * own.
         *
         * <p>The second half is the load-bearing one. A delegation {@code name} does not lie under is a statement
         * about another branch of the zone and says nothing at all about this query, so honouring one lets a
         * genuine, publicly fetchable referral for an unsigned sibling, replayed into this response, downgrade a
         * name the walk has just proven is inside the signed zone. That is the relevance class of dnsjava's
         * <a href="https://www.cve.org/CVERecord?id=CVE-2024-25638">CVE-2024-25638</a>.
         */
        private DnsRRset findReferral(DnsName name) {
            DnsRRset referral = null;
            for (int i = 0; i < authorityRrsets.size(); i++) {
                DnsRRset rrset = authorityRrsets.get(i);
                if (rrset.type().intValue() == TYPE_SOA) {
                    return null;
                }
                if (rrset.type().intValue() == TYPE_NS && signingZone != null
                        && rrset.owner().isStrictSubDomainOf(signingZone)
                        && name.equalsOrIsSubDomainOf(rrset.owner())) {
                    referral = rrset;
                }
            }
            return referral;
        }

        // Denial-of-existence input

        /**
         * Verifies the {@code NSEC} and {@code NSEC3} RRsets of a section and returns their records.
         *
         * <p>{@link DnssecDenialOfExistence} does not check signatures, so this has to happen first: feeding it
         * records straight off the wire would let an attacker supply whatever proof suited them. Anything that does
         * not verify is left out, and why it did not is remembered so that the eventual failure names the real
         * cause rather than "no proof".
         *
         * @return the authenticated records, or {@code null} if the validation has been completed with a failure.
         */
        private List<DnsRecord> collectProof(List<DnsRRset> rrsets, DnsName zone, List<DnsDnskeyRecord> keys) {
            proofFailureReason = null;
            proofFailureMessage = null;
            List<DnsRecord> proof = new ArrayList<DnsRecord>();
            for (int i = 0; i < rrsets.size(); i++) {
                DnsRRset rrset = rrsets.get(i);
                int type = rrset.type().intValue();
                if (type != TYPE_NSEC && type != TYPE_NSEC3) {
                    continue;
                }
                if (!rrset.owner().equalsOrIsSubDomainOf(zone)) {
                    complete(DnssecFailureReason.BAILIWICK_VIOLATION, "the authority section offers " + rrset.owner()
                            + ' ' + rrset.type() + " as proof, which lies outside " + zone + " and so cannot have "
                            + "been signed by any key this validator trusts");
                    return null;
                }
                DnssecVerificationResult result = verifier.verify(rrset, keys, budget);
                if (!result.isSecure()) {
                    rejectProofRecord(rrset, notADowngrade(result.reason()), result.message());
                } else if (result.isWildcardExpanded()) {
                    rejectProofRecord(rrset, DnssecFailureReason.DNSSEC_BOGUS, "its signature covers the wildcard "
                            + result.signedOwner() + " and so verifies under any owner name, which is no proof "
                            + "about this one (RFC 4035, Section 5.4)");
                } else {
                    proof.addAll(rrset.records());
                }
            }
            return proof;
        }

        /**
         * Leaves a record out of the proof and remembers why, so that the eventual failure names the real cause
         * rather than "no proof". The first rejection is the one kept: it is the one nearest the record the
         * verdict would have rested on.
         */
        private void rejectProofRecord(DnsRRset rrset, DnssecFailureReason reason, String message) {
            if (proofFailureReason == null) {
                proofFailureReason = reason;
                proofFailureMessage = rrset.owner() + " " + rrset.type() + ": " + message;
            }
        }

        private String describeProofFailure() {
            return proofFailureMessage == null ? "" : " (a proof record was rejected: " + proofFailureMessage + ')';
        }

        private void fetch(DnsName name, DnsRecordType type, FetchListener listener) {
            Future<DnssecFetchResult> future;
            try {
                future = fetcher.fetch(name, type);
            } catch (Throwable t) {
                complete(DnssecFailureReason.FETCH_FAILED, "the lookup of " + name + ' ' + type + " threw " + t,
                        null, null, t);
                return;
            }
            if (future == null) {
                complete(DnssecFailureReason.FETCH_FAILED, "the fetcher returned no future for " + name + ' ' + type);
                return;
            }
            future.addListener(listener);
        }

        /**
         * Hops back onto the validation's executor and hands the result to {@link #onResult(DnssecFetchResult)},
         * which is the only place a subclass has to think about. Ownership of the result ends here: it is released
         * once, on every path, including when the validation has already finished.
         */
        private abstract class FetchListener implements GenericFutureListener<Future<DnssecFetchResult>>, Runnable {

            private Future<DnssecFetchResult> future;

            @Override
            public void operationComplete(Future<DnssecFetchResult> future) {
                this.future = future;
                if (executor.inEventLoop()) {
                    run();
                    return;
                }
                try {
                    executor.execute(this);
                } catch (Throwable t) {
                    if (future.isSuccess()) {
                        ReferenceCountUtil.safeRelease(future.getNow());
                    }
                    abort(t);
                }
            }

            @Override
            public void run() {
                Future<DnssecFetchResult> completed = future;
                DnssecFetchResult result = completed.isSuccess() ? completed.getNow() : null;
                try {
                    if (finished) {
                        return;
                    }
                    budget.checkDeadline();
                    if (result == null) {
                        Throwable cause = completed.cause();
                        complete(DnssecFailureReason.FETCH_FAILED, describe() + " did not answer: "
                                + (cause != null ? String.valueOf(cause) : "the fetcher completed with no result"),
                                null, null, cause);
                        return;
                    }
                    onResult(result);
                } catch (DnssecException e) {
                    complete(reasonOf(e), String.valueOf(e.getMessage()));
                } catch (Throwable t) {
                    internalError(t);
                } finally {
                    if (result != null) {
                        result.release();
                    }
                }
            }

            abstract void onResult(DnssecFetchResult result);

            abstract String describe();
        }

        /**
         * Turns a {@code DNSKEY} response into the zone's trusted key set.
         *
         * <p>This is where <a href="https://www.cve.org/CVERecord?id=CVE-2025-25188">CVE-2025-25188</a> is
         * refused, twice over. A trust anchor, and equally a parent {@code DS} record, authenticates exactly
         * <em>one</em> key. The RRset becomes trusted only once an {@code RRSIG} <em>made by that key</em> has
         * validated over the whole of it, which is what lets the rest of the set be trusted with it. Offering the
         * verifier only the matched keys is what enforces that: an {@code RRSIG} made by any other key in the
         * response has no candidate to verify against.
         */
        private final class DnskeyListener extends FetchListener {

            private final DnsName zone;
            private final List<DnssecTrustAnchor> anchors;
            private final List<DnsDsRecord> dsRecords;

            DnskeyListener(DnsName zone, List<DnssecTrustAnchor> anchors, List<DnsDsRecord> dsRecords) {
                this.zone = zone;
                this.anchors = anchors;
                this.dsRecords = dsRecords;
            }

            @Override
            String describe() {
                return "the DNSKEY lookup of " + zone;
            }

            @Override
            void onResult(DnssecFetchResult result) {
                List<DnsRRset> answers = DnsRRset.group(result.message(), DnsSection.ANSWER, limits);
                DnsRRset keySet = findRRset(answers, zone, DnsRecordType.DNSKEY);
                if (keySet == null) {
                    complete(DnssecFailureReason.DNSKEY_MISSING, "the DNSKEY lookup of " + zone
                            + " returned no DNSKEY RRset owned by " + zone);
                    return;
                }
                List<DnsDnskeyRecord> candidates = asKeys(keySet);
                if (candidates == null) {
                    return;
                }
                List<DnsDnskeyRecord> matched = anchors != null ? matchAnchors(anchors, candidates)
                        : DnssecDsMatcher.matchingKeys(dsRecords, candidates, budget);
                if (matched.isEmpty()) {
                    complete(DnssecFailureReason.DS_MISMATCH, anchors != null
                            ? "no DNSKEY of " + zone + " matches any of the " + anchors.size()
                                    + " usable trust anchor(s) configured for it"
                            : "no DNSKEY of " + zone + " matches any of the " + dsRecords.size()
                                    + " usable DS record(s) its parent publishes");
                    return;
                }
                // Only the vouched-for keys are offered, so only a signature made by one of them can succeed.
                DnssecVerificationResult verification = verifier.verify(keySet, matched, budget);
                if (!verification.isSecure()) {
                    complete(verification.reason(), "the DNSKEY RRset of " + zone + " is not signed by any of the "
                            + matched.size() + " key(s) " + (anchors != null ? "the trust anchors" : "the parent DS "
                            + "RRset") + " vouches for, so the rest of the set is not vouched for either: "
                            + verification.message());
                    return;
                }
                List<DnsDnskeyRecord> keys = new ArrayList<DnsDnskeyRecord>(candidates.size());
                for (int i = 0; i < candidates.size(); i++) {
                    DnsDnskeyRecord key = candidates.get(i);
                    // Retained before the result that carried it is released at the end of this callback.
                    retained.add(key.retain());
                    keys.add(key);
                }
                establishedKeys.put(zone, keys);
                keyCache.put(zone, keys, cacheTtlSeconds(keys, verification), clock.currentTimeMillis());
                trace("DNSKEY " + zone + " established: " + keys.size() + " key(s), vouched for by DNSKEY "
                        + verification.key().keyTag() + " and self-signed by it");
                adoptKeys(zone, keys);
            }
        }

        /**
         * Turns a {@code DS} response into either a descent into the child zone or a proof that there is nothing to
         * descend into.
         */
        private final class DsListener extends FetchListener {

            private final DnsName child;

            DsListener(DnsName child) {
                this.child = child;
            }

            @Override
            String describe() {
                return "the DS lookup of " + child;
            }

            @Override
            void onResult(DnssecFetchResult result) {
                List<DnsRRset> answers = DnsRRset.group(result.message(), DnsSection.ANSWER, limits);
                DnsRRset dsSet = findRRset(answers, child, DnsRecordType.DS);
                if (dsSet != null) {
                    descend(dsSet);
                    return;
                }
                List<DnsRRset> authorities = DnsRRset.group(result.message(), DnsSection.AUTHORITY, limits);
                List<DnsRecord> proof = collectProof(authorities, signingZone, signingKeys);
                if (proof == null) {
                    return;
                }
                DnssecDenialOfExistence denial = new DnssecDenialOfExistence(signingZone, budget);
                DnssecDenialOfExistence.Result unsigned = denial.proveUnsignedDelegation(child, proof);
                if (unsigned.status() == DnssecStatus.INSECURE) {
                    complete(unsigned.reason(), child + " is a delegation for which " + signingZone
                            + " publishes no DS, so it and everything below it is unsigned", null, child, null);
                    return;
                }
                // No DS and no delegation either: the name is simply inside the current zone, so the walk carries
                // on with the same keys. proveNoData(x, DS, ...) says only that the DS RRset does not exist, which
                // is exactly the question here; whether a delegation is unsigned was the test above.
                DnssecDenialOfExistence.Result absent =
                        result.responseCode().intValue() == DnsResponseCode.NXDOMAIN.intValue()
                                ? denial.proveNameError(child, proof)
                                : denial.proveNoData(child, DnsRecordType.DS, proof);
                if (absent.status() == DnssecStatus.SECURE) {
                    provenNoDelegation.add(child);
                    trace(child + " is not a zone cut: " + signingZone + " provably publishes no DS for it");
                    chainIndex++;
                    stepChain();
                    return;
                }
                if (absent.status() == DnssecStatus.INSECURE) {
                    complete(absent.reason(), "the absence of a DS RRset for " + child + " is not authenticated: "
                            + absent.reason(), null, child, null);
                    return;
                }
                // Last: the name may simply not exist, which is also a proof that there is no delegation at it,
                // since a delegation is a name that exists. This is the case a wildcard creates: every label of
                // QNAME is probed on the way down, and a wildcard-covered label has no record of its own for a
                // DS denial to match, so nothing above can conclude anything about it.
                DnssecDenialOfExistence.Result nonexistent = proveAbsent(denial, child, proof);
                if (nonexistent != null && nonexistent.status() == DnssecStatus.SECURE) {
                    provenNoDelegation.add(child);
                    trace(child + " provably does not exist, so it is not a zone cut");
                    chainIndex++;
                    stepChain();
                    return;
                }
                if (nonexistent != null && nonexistent.status() == DnssecStatus.INSECURE) {
                    complete(nonexistent.reason(), "whether " + child + " exists, and so whether it is an unsigned "
                            + "delegation, rests on an opt-out span and is not authenticated", null, child, null);
                    return;
                }
                complete(proofFailureReason != null ? proofFailureReason : absent.reason(), "the DS lookup of "
                        + child + " returned neither a DS RRset nor an authenticated proof that there is none: "
                        + absent.reason() + describeProofFailure());
            }

            private void descend(DnsRRset dsSet) {
                if (!dsSet.owner().equalsOrIsSubDomainOf(signingZone)) {
                    complete(DnssecFailureReason.BAILIWICK_VIOLATION, "the DS RRset offered for " + child
                            + " lies outside " + signingZone + ", the zone that would have to have signed it");
                    return;
                }
                DnssecVerificationResult verification = verifier.verify(dsSet, signingKeys, budget);
                if (!verification.isSecure()) {
                    complete(notADowngrade(verification.reason()), "the DS RRset of " + child + " did not validate "
                            + "against the keys of " + signingZone + ": " + verification.message());
                    return;
                }
                if (verification.isWildcardExpanded()) {
                    // RFC 4592, Section 4.2 says a wildcard never synthesises a delegation, so there is no
                    // legitimate reading of this at all; and the signature would authenticate the same RDATA under
                    // any child name, which is the whole delegation handed over.
                    complete(DnssecFailureReason.DNSSEC_BOGUS, "the DS RRset offered for " + child + " is covered "
                            + "by a signature over the wildcard " + verification.signedOwner() + " rather than "
                            + "over " + child + ", so it delegates nothing");
                    return;
                }
                List<DnsDsRecord> dsRecords = asDs(dsSet);
                if (dsRecords == null) {
                    return;
                }
                List<DnsDsRecord> usable = DnssecDsMatcher.usable(dsRecords, limits);
                if (usable.isEmpty()) {
                    // RFC 6840, Section 5.2: a delegation whose DS records name only algorithms or digest types the
                    // validator cannot evaluate is treated as unsigned. This is a proof, not a shrug: the parent
                    // said what it said and we can read it, we simply cannot follow it.
                    complete(unsupportedDsReason(dsRecords), "every one of the " + dsRecords.size() + " DS record(s)"
                            + " for " + child + " names a DNSKEY algorithm or digest type this build cannot "
                            + "evaluate, so RFC 6840, Section 5.2 treats the delegation as unsigned", null, child,
                            null);
                    return;
                }
                for (int i = 0; i < usable.size(); i++) {
                    // Retained because establishKeys may suspend before the digests are computed, by which time the
                    // response these came from has been released.
                    retained.add(usable.get(i).retain());
                }
                trace("DS " + child + " verified: " + usable.size() + " usable of " + dsRecords.size());
                establishKeys(child, null, usable);
            }
        }

        /**
         * Returns the keys a trust anchor vouches for. An anchor names one key by tag, algorithm and digest, and
         * matching it is the same work matching a {@code DS} is, so it is charged to the budget the same way.
         */
        private List<DnsDnskeyRecord> matchAnchors(List<DnssecTrustAnchor> anchors, List<DnsDnskeyRecord> keys) {
            List<DnsDnskeyRecord> matched = new ArrayList<DnsDnskeyRecord>(1);
            for (int i = 0; i < keys.size(); i++) {
                DnsDnskeyRecord key = keys.get(i);
                if (key == null || !key.isZoneKey() || key.isRevoked()) {
                    // RFC 4034, Section 2.1.1 and RFC 5011, Section 2.1.
                    continue;
                }
                int keyTag;
                try {
                    keyTag = key.keyTag();
                } catch (DnssecException ignored) {
                    continue;
                }
                for (int j = 0; j < anchors.size(); j++) {
                    DnssecTrustAnchor anchor = anchors.get(j);
                    if (anchor.keyTag() != keyTag
                            || anchor.algorithm().intValue() != key.algorithm().intValue()) {
                        continue;
                    }
                    byte[] actual;
                    try {
                        actual = DnssecDsMatcher.digest(anchor.digestType(), key.owner(), key);
                    } catch (DnssecException ignored) {
                        continue;
                    }
                    byte[] expected = anchor.digest();
                    if (expected.length == actual.length
                            && PlatformDependent.equalsConstantTime(expected, 0, actual, 0, actual.length) != 0) {
                        matched.add(key);
                        break;
                    }
                    budget.spendDsMatchFailure();
                }
            }
            return matched;
        }

        /**
         * Returns whether {@code name} provably does not exist.
         *
         * <p>{@link DnssecDenialOfExistence#proveWildcardAnswer(DnsName, DnsName, List)} is what says so: its
         * content is "the queried name is covered by the denial chain, and its closest encloser is the one
         * claimed". The closest encloser is not known here, so each ancestor from the parent up to the zone is
         * offered in turn, which is bounded by the label count of a name and hence by
         * {@link DnssecLimits#maxDelegationDepth()}.
         *
         * <p>This cannot be turned into a way of hiding a real delegation. A delegation exists, so the zone's
         * denial chain has a record matching it, and both denial forms refuse to call a name absent when
         * something matches it. Forging one is not available either: the records were verified before they got
         * here.
         *
         * @return the verdict, or {@code null} if no ancestor could even be tried.
         */
        private DnssecDenialOfExistence.Result proveAbsent(DnssecDenialOfExistence denial, DnsName name,
                                                           List<DnsRecord> proof) {
            DnssecDenialOfExistence.Result last = null;
            DnsName encloser = name.parent();
            for (;;) {
                DnsName wildcard;
                try {
                    wildcard = encloser.toWildcard();
                } catch (IllegalArgumentException ignored) {
                    return last;
                }
                DnssecDenialOfExistence.Result result = denial.proveWildcardAnswer(name, wildcard, proof);
                if (result.status() == DnssecStatus.SECURE || result.status() == DnssecStatus.INSECURE) {
                    return result;
                }
                last = result;
                if (encloser.isRoot() || encloser.equals(signingZone)) {
                    return last;
                }
                encloser = encloser.parent();
            }
        }

        private DnssecFailureReason unsupportedDsReason(List<DnsDsRecord> dsRecords) {
            for (int i = 0; i < dsRecords.size(); i++) {
                if (!dsRecords.get(i).algorithm().isSupported()) {
                    return DnssecFailureReason.UNSUPPORTED_DNSKEY_ALGORITHM;
                }
            }
            return DnssecFailureReason.UNSUPPORTED_DS_DIGEST_TYPE;
        }

        private List<DnsDnskeyRecord> asKeys(DnsRRset rrset) {
            List<DnssecRecord> records = rrset.records();
            List<DnsDnskeyRecord> keys = new ArrayList<DnsDnskeyRecord>(records.size());
            for (int i = 0; i < records.size(); i++) {
                DnssecRecord record = records.get(i);
                if (!(record instanceof DnsDnskeyRecord)) {
                    complete(DnssecFailureReason.NAME_NOT_REPRESENTABLE, "a DNSKEY of " + rrset.owner()
                            + " arrived as a " + record.getClass().getName() + " whose RDATA has not been parsed; "
                            + "decode with DnssecDnsRecordDecoder");
                    return null;
                }
                keys.add((DnsDnskeyRecord) record);
            }
            return keys;
        }

        private List<DnsDsRecord> asDs(DnsRRset rrset) {
            List<DnssecRecord> records = rrset.records();
            List<DnsDsRecord> dsRecords = new ArrayList<DnsDsRecord>(records.size());
            for (int i = 0; i < records.size(); i++) {
                DnssecRecord record = records.get(i);
                if (!(record instanceof DnsDsRecord)) {
                    complete(DnssecFailureReason.NAME_NOT_REPRESENTABLE, "a DS of " + rrset.owner()
                            + " arrived as a " + record.getClass().getName() + " whose RDATA has not been parsed; "
                            + "decode with DnssecDnsRecordDecoder");
                    return null;
                }
                dsRecords.add((DnsDsRecord) record);
            }
            return dsRecords;
        }

        /**
         * RFC 4035, Section 5.3.3: cached data must not outlive the signature that authenticated it.
         */
        private long cacheTtlSeconds(List<DnsDnskeyRecord> keys, DnssecVerificationResult verification) {
            long ttl = Long.MAX_VALUE;
            for (int i = 0; i < keys.size(); i++) {
                ttl = Math.min(ttl, keys.get(i).timeToLive());
            }
            // RFC 1982 serial arithmetic: the difference of two 32-bit times, not of two widened longs.
            int expiration = (int) verification.signature().expiration();
            int now = (int) (clock.currentTimeMillis() / 1000L);
            long remaining = expiration - now;
            return Math.min(ttl, remaining);
        }

        /**
         * Returns the {@code DNAME} whose owner is the closest strict ancestor of {@code name}, or {@code null}.
         */
        private DnsRRset findDname(DnsName name) {
            DnsRRset best = null;
            for (int i = 0; i < answerRrsets.size(); i++) {
                DnsRRset rrset = answerRrsets.get(i);
                if (rrset.type().intValue() != TYPE_DNAME || rrset.dnsClass() != DnsRecord.CLASS_IN
                        || !name.isStrictSubDomainOf(rrset.owner())) {
                    continue;
                }
                if (best == null || rrset.owner().labelCount() > best.owner().labelCount()) {
                    best = rrset;
                }
            }
            return best;
        }

        /**
         * Reads the single wire-format domain name that makes up a {@code CNAME} or {@code DNAME} RDATA.
         *
         * @return the name, or {@code null} if the validation has been completed with a failure.
         */
        private DnsName singleNameRdata(DnsRRset rrset) {
            if (rrset.records().size() != 1) {
                complete(DnssecFailureReason.CNAME_CHAIN_INVALID, "the " + rrset.type() + " RRset at "
                        + rrset.owner() + " has " + rrset.records().size() + " records; RFC 1034, Section 3.6.2 "
                        + "allows exactly one");
                return null;
            }
            ByteBuf content = rrset.records().get(0).content();
            int offset = content.readerIndex();
            int end = content.writerIndex();
            try {
                if (DnsName.encodedLength(content, offset, end) != content.readableBytes()) {
                    complete(DnssecFailureReason.DNSSEC_BOGUS, "the " + rrset.type() + " RDATA at " + rrset.owner()
                            + " has octets after the domain name it is made of");
                    return null;
                }
                return DnsName.decode(content, offset, end);
            } catch (RuntimeException e) {
                complete(DnssecFailureReason.COMPRESSED_RDATA, "the " + rrset.type() + " RDATA at " + rrset.owner()
                        + " is not a domain name this validator can read: " + e);
                return null;
            }
        }

        /**
         * RFC 6672, Section 3.4.1: the labels of {@code name} above the {@code DNAME} owner are moved onto the
         * {@code DNAME} target.
         *
         * @return the rewritten name, or {@code null} if the validation has been completed with a failure.
         */
        private DnsName synthesizeFromDname(DnsName name, DnsName owner, DnsName target) {
            byte[] wire = name.toWireBytes();
            byte[] ownerWire = owner.toWireBytes();
            byte[] targetWire = target.toWireBytes();
            int prefix = wire.length - ownerWire.length;
            byte[] rewritten = new byte[prefix + targetWire.length];
            System.arraycopy(wire, 0, rewritten, 0, prefix);
            System.arraycopy(targetWire, 0, rewritten, prefix, targetWire.length);
            if (rewritten.length > DnsName.MAX_NAME_LENGTH) {
                complete(DnssecFailureReason.CNAME_CHAIN_INVALID, "rewriting " + name + " through the DNAME at "
                        + owner + " would produce a name of " + rewritten.length + " octets, more than the "
                        + DnsName.MAX_NAME_LENGTH + " a domain name may have");
                return null;
            }
            ByteBuf buffer = Unpooled.wrappedBuffer(rewritten);
            try {
                return DnsName.decode(buffer, 0, rewritten.length);
            } catch (RuntimeException e) {
                complete(DnssecFailureReason.CNAME_CHAIN_INVALID, "rewriting " + name + " through the DNAME at "
                        + owner + " did not produce a usable name: " + e);
                return null;
            } finally {
                buffer.release();
            }
        }

        private List<DnsName> namesFrom(DnsName anchor, DnsName target) {
            int from = anchor.labelCount();
            int to = target.labelCount();
            List<DnsName> names = new ArrayList<DnsName>(to - from + 1);
            for (int i = from; i <= to; i++) {
                names.add(target.stripLeftmostLabels(to - i));
            }
            return names;
        }

        private void armTimeout() {
            long remaining = budget.remainingMillis();
            if (remaining <= 0) {
                return;
            }
            try {
                timeoutTask = executor.schedule(new Runnable() {

                    @Override
                    public void run() {
                        complete(DnssecFailureReason.LIMIT_EXCEEDED, "the validation did not finish within the "
                                + limits.validationTimeoutMillis() + "ms it is allowed");
                    }
                }, remaining, TimeUnit.MILLISECONDS);
            } catch (UnsupportedOperationException e) {
                traceNoBackstop();
            } catch (RejectedExecutionException e) {
                traceNoBackstop();
            }
        }

        private void cancelTimeout() {
            ScheduledFuture<?> task = timeoutTask;
            if (task != null) {
                timeoutTask = null;
                task.cancel(false);
            }
        }

        private void traceNoBackstop() {
            trace("this executor cannot schedule, so the " + limits.validationTimeoutMillis()
                    + "ms wall-clock backstop is not armed; the deadline is still checked at every step");
        }

        private void retainSection(DnsResponse response, DnsSection section) {
            int count = response.count(section);
            for (int i = 0; i < count; i++) {
                DnsRecord record = response.recordAt(section, i);
                if (record instanceof ReferenceCounted) {
                    retained.add(((ReferenceCounted) record).retain());
                }
            }
        }

        private void releaseRetained() {
            for (int i = 0; i < retained.size(); i++) {
                ReferenceCountUtil.safeRelease(retained.get(i));
            }
            retained.clear();
        }

        private void recordStartupFailure(DnssecFailureReason reason, String message) {
            if (startupReason == null) {
                startupReason = reason;
                startupMessage = message;
            }
        }

        private void trace(String step) {
            trace.add(step);
        }

        private void internalError(Throwable cause) {
            complete(DnssecFailureReason.INTERNAL_ERROR, "the validation failed unexpectedly: " + cause, null, null,
                    cause);
        }

        private void complete(DnssecFailureReason reason, String message) {
            complete(reason, message, null, null, null);
        }

        /**
         * The single exit. Everything retained is released here, before the result is published, so that a caller
         * receiving the verdict never holds anything that has to be freed.
         */
        private void complete(DnssecFailureReason reason, String message, DnsName signer, DnsName insecureAt,
                              Throwable cause) {
            if (finished) {
                return;
            }
            finished = true;
            cancelTimeout();
            trace(reason.impliedStatus() + ": " + message);
            releaseRetained();
            promise.trySuccess(new DnssecValidationResult(reason, message, signer, insecureAt, cause,
                    new ArrayList<String>(trace), budget));
        }
    }

    /**
     * The reason to report for an exception that escaped to a catch block instead of being handled where it was
     * raised.
     *
     * <p>Every route out of here is a Bogus one, {@link #notADowngrade} included. An escaped exception is a
     * failure to evaluate on a path that was not expected to fail at all, and an exception handler that
     * downgrades is one an attacker only has to make throw. In particular a
     * {@link DnssecUnsupportedAlgorithmException} does not become
     * {@link DnssecFailureReason#UNSUPPORTED_DNSKEY_ALGORITHM} here: the zone-level judgement that legitimately
     * reaches Insecure is made in {@link DnssecSignatureVerifier}, which has the zone's whole key set to make it
     * with, and by {@link DnssecDenialOfExistence}, which reaches it through a proof.
     */
    private static DnssecFailureReason reasonOf(DnssecException e) {
        if (e instanceof DnssecLimitExceededException) {
            return DnssecFailureReason.LIMIT_EXCEEDED;
        }
        if (e instanceof DnssecCanonicalizationException) {
            return notADowngrade(((DnssecCanonicalizationException) e).reason());
        }
        return DnssecFailureReason.DNSSEC_BOGUS;
    }

    /**
     * Replaces a reason implying {@link DnssecStatus#INSECURE} with {@link DnssecFailureReason#DNSSEC_BOGUS}.
     *
     * <p>Applied wherever a failure to <em>evaluate</em> must not become a verdict of <em>unsigned</em>: material
     * that sits inside a zone the chain of trust has already established, and the reason reported for an escaped
     * exception. Inside a provably signed zone an Insecure reason is not a licence to treat the data as unsigned —
     * the delegation is secure, so an RRset that does not validate against the zone's keys is Bogus — and anything
     * else would let whoever can make one RRset unevaluatable strip DNSSEC from the zone it sits in.
     */
    private static DnssecFailureReason notADowngrade(DnssecFailureReason reason) {
        return reason.impliedStatus() == DnssecStatus.INSECURE ? DnssecFailureReason.DNSSEC_BOGUS : reason;
    }

    /**
     * Returns {@code true} if a verification authenticated the owner name the record arrived under rather than a
     * wildcard above it.
     *
     * <p><a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.4">RFC 4035, Section 5.4</a>: a record
     * proves that wildcard expansion could not have been used only when its owner name has as many labels as the
     * Labels field of the {@code RRSIG} covering it. Below that the signature covers {@code *.} followed by the
     * tail of the owner name, so the same record and the same signature verify under <em>any</em> owner name
     * inside the zone. That is what a wildcard is for in an answer, which is why an answer is instead required to
     * come with a denial of existence for the queried name. Everywhere else the owner name <em>is</em> the
     * meaning: a denial of existence would have its {@code matches()} and {@code covers()} read a name the zone
     * never signed, and a {@code DS} would delegate a name
     * <a href="https://www.rfc-editor.org/rfc/rfc4592.html#section-4.2">RFC 4592, Section 4.2</a> says a wildcard
     * never synthesises.
     */
    private static boolean authenticatesItsOwnerName(DnssecVerificationResult result) {
        return result.isSecure() && !result.isWildcardExpanded();
    }
}
