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

import io.netty.handler.codec.dns.DefaultDnsResponse;
import io.netty.handler.codec.dns.DnsMessage;
import io.netty.handler.codec.dns.DnsOpCode;
import io.netty.handler.codec.dns.DnsRecord;
import io.netty.handler.codec.dns.DnsResponse;
import io.netty.handler.codec.dns.DnsResponseCode;
import io.netty.handler.codec.dns.DnsSection;
import io.netty.util.AbstractReferenceCounted;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.internal.ObjectUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * What a {@link DnssecRecordFetcher} answered with: a response code and the records of the sections a validator is
 * allowed to look at.
 *
 * <h3>Only two sections, and deliberately no AD bit</h3>
 *
 * <p>Only {@link DnsSection#ANSWER} and {@link DnsSection#AUTHORITY} are carried.
 * {@link DnsSection#ADDITIONAL} is dropped at construction rather than filtered out later: it is not authenticated
 * data, and letting records that arrived there reach a validator is the shape of Unbound's
 * <a href="https://www.cve.org/CVERecord?id=CVE-2026-42960">CVE-2026-42960</a> and of
 * <a href="https://www.cve.org/CVERecord?id=CVE-2025-11411">CVE-2025-11411</a>. Discarding them up front means
 * there is no code path along which they could be consulted by accident. The {@code OPT} pseudo-record lives in
 * the additional section, so it goes with them; nothing here needs it.</p>
 *
 * <p>There is no accessor for the {@code AD} bit, and that is not an oversight. {@code AD} is the upstream
 * resolver's opinion, and a validator that has any use for it is not validating — it is believing. Exposing it
 * would only invite someone to short-circuit the chain walk with it.</p>
 *
 * <h3>Reference counting</h3>
 *
 * <p>The records are retained by the factory methods, so the caller may release the response it decoded as soon as
 * the result exists. The {@link DnssecValidator} takes ownership of every result a fetch completes with and
 * releases it exactly once, including when the validation has already finished by then.</p>
 */
public final class DnssecFetchResult extends AbstractReferenceCounted {

    private final DnsResponse message;
    private final List<DnsRecord> answers;
    private final List<DnsRecord> authorities;

    private DnssecFetchResult(DnsResponse message) {
        this.message = message;
        answers = Collections.unmodifiableList(recordsOf(message, DnsSection.ANSWER));
        authorities = Collections.unmodifiableList(recordsOf(message, DnsSection.AUTHORITY));
    }

    /**
     * Retains the {@link DnsSection#ANSWER} and {@link DnsSection#AUTHORITY} records of {@code response} and wraps
     * them, leaving {@code response} itself untouched and releasable straight away.
     *
     * @param response a response decoded with {@link DnssecDnsRecordDecoder}. Not retained, not released, not
     *                 modified.
     * @return a result the caller owns and must release.
     */
    public static DnssecFetchResult fromResponse(DnsResponse response) {
        ObjectUtil.checkNotNull(response, "response");
        DefaultDnsResponse copy = new DefaultDnsResponse(response.id(), response.opCode(), response.code());
        boolean success = false;
        try {
            copySection(response, copy, DnsSection.ANSWER);
            copySection(response, copy, DnsSection.AUTHORITY);
            DnssecFetchResult result = new DnssecFetchResult(copy);
            success = true;
            return result;
        } finally {
            if (!success) {
                copy.release();
            }
        }
    }

    /**
     * Retains {@code answers} and {@code authorities} and wraps them, for a fetcher that has the records in hand
     * without a {@link DnsResponse} around them.
     *
     * @param responseCode the {@code RCODE} the server gave, which decides whether a validator looks for an answer
     *                     or for a denial of existence.
     * @param answers      the answer-section records. Retained, not released.
     * @param authorities  the authority-section records. Retained, not released.
     * @return a result the caller owns and must release.
     */
    public static DnssecFetchResult of(DnsResponseCode responseCode, List<? extends DnsRecord> answers,
                                       List<? extends DnsRecord> authorities) {
        ObjectUtil.checkNotNull(responseCode, "responseCode");
        ObjectUtil.checkNotNull(answers, "answers");
        ObjectUtil.checkNotNull(authorities, "authorities");
        DefaultDnsResponse copy = new DefaultDnsResponse(0, DnsOpCode.QUERY, responseCode);
        boolean success = false;
        try {
            addAll(copy, DnsSection.ANSWER, answers);
            addAll(copy, DnsSection.AUTHORITY, authorities);
            DnssecFetchResult result = new DnssecFetchResult(copy);
            success = true;
            return result;
        } finally {
            if (!success) {
                copy.release();
            }
        }
    }

    /**
     * Returns the {@code RCODE} the server gave. {@link DnsResponseCode#NOERROR} and
     * {@link DnsResponseCode#NXDOMAIN} are the two a validator can reason about; anything else leaves it with
     * nothing to validate.
     */
    public DnsResponseCode responseCode() {
        return message.code();
    }

    /**
     * Returns the answer-section records, in the order they arrived. Unmodifiable, never {@code null}, and owned by
     * this result rather than by the caller.
     */
    public List<DnsRecord> answers() {
        return answers;
    }

    /**
     * Returns the authority-section records, in the order they arrived. Unmodifiable, never {@code null}, and owned
     * by this result rather than by the caller.
     */
    public List<DnsRecord> authorities() {
        return authorities;
    }

    @Override
    public DnssecFetchResult retain() {
        super.retain();
        return this;
    }

    @Override
    public DnssecFetchResult retain(int increment) {
        super.retain(increment);
        return this;
    }

    @Override
    public DnssecFetchResult touch() {
        super.touch();
        return this;
    }

    @Override
    public DnssecFetchResult touch(Object hint) {
        message.touch(hint);
        return this;
    }

    @Override
    public String toString() {
        return "DnssecFetchResult(" + responseCode() + ", " + answers.size() + " answer(s), "
                + authorities.size() + " authority record(s))";
    }

    /**
     * Returns the records as a {@link DnsMessage}, so that {@link DnsRRset#group(DnsMessage, DnsSection,
     * DnssecLimits)} can be applied to them. The message holds the same record instances the accessors return and
     * owns their reference counts.
     */
    DnsMessage message() {
        return message;
    }

    @Override
    protected void deallocate() {
        message.release();
    }

    private static void copySection(DnsResponse from, DnsResponse to, DnsSection section) {
        int count = from.count(section);
        for (int i = 0; i < count; i++) {
            DnsRecord record = from.recordAt(section, i);
            to.addRecord(section, ReferenceCountUtil.retain(record));
        }
    }

    private static void addAll(DnsResponse to, DnsSection section, List<? extends DnsRecord> records) {
        for (int i = 0; i < records.size(); i++) {
            DnsRecord record = ObjectUtil.checkNotNull(records.get(i), "records[" + i + ']');
            to.addRecord(section, ReferenceCountUtil.retain(record));
        }
    }

    private static List<DnsRecord> recordsOf(DnsMessage message, DnsSection section) {
        int count = message.count(section);
        List<DnsRecord> records = new ArrayList<DnsRecord>(count);
        for (int i = 0; i < count; i++) {
            records.add(message.<DnsRecord>recordAt(section, i));
        }
        return records;
    }
}
