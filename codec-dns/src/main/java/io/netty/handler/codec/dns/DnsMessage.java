/*
 * Copyright 2015 The Netty Project
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

import io.netty.util.ReferenceCounted;

/**
 * The superclass which contains core information concerning a {@link DnsQuery} and a {@link DnsResponse}.
 */
public interface DnsMessage extends ReferenceCounted {

    /**
     * Returns the {@code ID} of this DNS message.
     */
    int id();

    /**
     * Sets the {@code ID} of this DNS message.
     */
    DnsMessage setId(int id);

    /**
     * Returns the {@code opCode} of this DNS message.
     */
    DnsOpCode opCode();

    /**
     * Sets the {@code opCode} of this DNS message.
     */
    DnsMessage setOpCode(DnsOpCode opCode);

    /**
     * Returns the {@code RD} (recursion desired} field of this DNS message.
     */
    boolean isRecursionDesired();

    /**
     * Sets the {@code RD} (recursion desired} field of this DNS message.
     */
    DnsMessage setRecursionDesired(boolean recursionDesired);

    /**
     * Returns the {@code Z} (reserved for future use) field of this DNS message.
     * <p>
     * Despite the name, only the most significant of these three bits is still reserved. RFC 4035 assigned the
     * other two to {@code AD} and {@code CD}; prefer {@link #isAuthenticData()} and {@link #isCheckingDisabled()}
     * over decoding them out of this value by hand.
     */
    int z();

    /**
     * Sets the {@code Z} (reserved for future use) field of this DNS message.
     */
    DnsMessage setZ(int z);

    /**
     * Returns the {@code AD} (authentic data) bit of this DNS message.
     * <p>
     * On a <em>response</em>, a security-aware name server sets this bit to assert that it considers everything
     * in the answer and authority sections to be authentic, per
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-3.2.3">RFC 4035, section 3.2.3</a>. On a
     * <em>query</em> it instead signals that the requester understands and is interested in the value of the
     * {@code AD} bit in the response, per
     * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.7">RFC 6840, section 5.7</a>.
     * <p>
     * <strong>The {@code AD} bit is not itself authenticated.</strong> It is an unsigned header bit, so an
     * on-path attacker can set it at will. Do not rely on it unless the data was obtained from a trusted
     * security-aware recursive name server over a secure channel — see
     * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-4.9.3">RFC 4035, section 4.9.3</a>, which
     * states that a security-aware stub resolver {@code MUST NOT} place any reliance on it otherwise.
     */
    default boolean isAuthenticData() {
        return (z() & 0x2) != 0;
    }

    /**
     * Sets the {@code AD} (authentic data) bit of this DNS message. See {@link #isAuthenticData()}.
     */
    default DnsMessage setAuthenticData(boolean authenticData) {
        return setZ(authenticData ? z() | 0x2 : z() & ~0x2);
    }

    /**
     * Returns the {@code CD} (checking disabled) bit of this DNS message.
     * <p>
     * A requester sets this bit to ask that the server not suppress data that fails DNSSEC validation, so that
     * the requester can validate for itself. A resolver that performs its own validation {@code SHOULD} set it
     * on every upstream query, per
     * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.9">RFC 6840, section 5.9</a> — without it
     * an upstream validator filters out exactly the records needed to reach an independent verdict.
     */
    default boolean isCheckingDisabled() {
        return (z() & 0x1) != 0;
    }

    /**
     * Sets the {@code CD} (checking disabled) bit of this DNS message. See {@link #isCheckingDisabled()}.
     */
    default DnsMessage setCheckingDisabled(boolean checkingDisabled) {
        return setZ(checkingDisabled ? z() | 0x1 : z() & ~0x1);
    }

    /**
     * Returns the number of records in the specified {@code section} of this DNS message.
     */
    int count(DnsSection section);

    /**
     * Returns the number of records in this DNS message.
     */
    int count();

    /**
     * Returns the first record in the specified {@code section} of this DNS message.
     * When the specified {@code section} is {@link DnsSection#QUESTION}, the type of the returned record is
     * always {@link DnsQuestion}.
     *
     * @return {@code null} if this message doesn't have any records in the specified {@code section}
     */
    <T extends DnsRecord> T recordAt(DnsSection section);

    /**
     * Returns the record at the specified {@code index} of the specified {@code section} of this DNS message.
     * When the specified {@code section} is {@link DnsSection#QUESTION}, the type of the returned record is
     * always {@link DnsQuestion}.
     *
     * @throws IndexOutOfBoundsException if the specified {@code index} is out of bounds
     */
    <T extends DnsRecord> T recordAt(DnsSection section, int index);

    /**
     * Sets the specified {@code section} of this DNS message to the specified {@code record},
     * making it a single-record section. When the specified {@code section} is {@link DnsSection#QUESTION},
     * the specified {@code record} must be a {@link DnsQuestion}.
     */
    DnsMessage setRecord(DnsSection section, DnsRecord record);

    /**
     * Sets the specified {@code record} at the specified {@code index} of the specified {@code section}
     * of this DNS message. When the specified {@code section} is {@link DnsSection#QUESTION},
     * the specified {@code record} must be a {@link DnsQuestion}.
     *
     * @return the old record
     * @throws IndexOutOfBoundsException if the specified {@code index} is out of bounds
     */
    <T extends DnsRecord> T setRecord(DnsSection section, int index, DnsRecord record);

    /**
     * Adds the specified {@code record} at the end of the specified {@code section} of this DNS message.
     * When the specified {@code section} is {@link DnsSection#QUESTION}, the specified {@code record}
     * must be a {@link DnsQuestion}.
     */
    DnsMessage addRecord(DnsSection section, DnsRecord record);

    /**
     * Adds the specified {@code record} at the specified {@code index} of the specified {@code section}
     * of this DNS message. When the specified {@code section} is {@link DnsSection#QUESTION}, the specified
     * {@code record} must be a {@link DnsQuestion}.
     *
     * @throws IndexOutOfBoundsException if the specified {@code index} is out of bounds
     */
    DnsMessage addRecord(DnsSection section, int index, DnsRecord record);

    /**
     * Removes the record at the specified {@code index} of the specified {@code section} from this DNS message.
     * When the specified {@code section} is {@link DnsSection#QUESTION}, the type of the returned record is
     * always {@link DnsQuestion}.
     *
     * @return the removed record
     */
    <T extends DnsRecord> T removeRecord(DnsSection section, int index);

    /**
     * Removes all the records in the specified {@code section} of this DNS message.
     */
    DnsMessage clear(DnsSection section);

    /**
     * Removes all the records in this DNS message.
     */
    DnsMessage clear();

    @Override
    DnsMessage touch();

    @Override
    DnsMessage touch(Object hint);

    @Override
    DnsMessage retain();

    @Override
    DnsMessage retain(int increment);
}
