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

import io.netty.util.internal.ObjectUtil;

/**
 * Raised when a record cannot be put into the canonical form of
 * <a href="https://www.rfc-editor.org/rfc/rfc4034.html#section-6.2">RFC 4034, Section 6.2</a>, so that no signature
 * over it can be checked.
 *
 * <p>There are two ways that happens, and {@link #reason()} says which:</p>
 * <ul>
 *   <li>{@link DnssecFailureReason#COMPRESSED_RDATA} — the {@code RDATA} holds a domain name written as a
 *   compression pointer, or as a reserved label type, or truncated. Canonical form requires every name "fully
 *   expanded (no DNS name compression)", and the pointer can only be resolved against the message the record was
 *   read from, which is not available here. Expanding it after the fact would also be unsafe: two different wire
 *   encodings would map onto one signed preimage, which is a signature-reuse primitive.</li>
 *   <li>{@link DnssecFailureReason#NAME_NOT_REPRESENTABLE} — the record does not carry its owner name in wire form,
 *   because it is not a {@link DnssecRecord}. {@link io.netty.handler.codec.dns.DnsRecord#name()} is not a
 *   substitute: it has been through a UTF-8 decode and {@code IDN.toASCII}, so a label holding the octets
 *   {@code C3 A9} comes back as {@code xn--9ca} and the signed octets are gone.</li>
 * </ul>
 *
 * <p>Both reasons imply {@link DnssecStatus#BOGUS}. That is deliberate and is the conservative choice: the record
 * is being offered as authenticated data, and a validator that cannot reconstruct what was signed has no basis for
 * saying it is anything.</p>
 *
 * <p>Like every other failure in this package this is a {@link io.netty.handler.codec.DecoderException}, so a
 * validator that catches {@code DecoderException} catches this alongside the
 * {@link io.netty.handler.codec.CorruptedFrameException}s the record parsers raise.</p>
 */
public final class DnssecCanonicalizationException extends DnssecException {

    private static final long serialVersionUID = -1794426612508397043L;

    private final DnssecFailureReason reason;

    /**
     * Creates a new instance.
     *
     * @param reason  why the record cannot be canonicalised.
     * @param message the detail message.
     */
    public DnssecCanonicalizationException(DnssecFailureReason reason, String message) {
        super(message);
        this.reason = ObjectUtil.checkNotNull(reason, "reason");
    }

    /**
     * Returns the machine-readable reason canonicalisation failed, which a validator can report as its verdict
     * without having to parse {@link #getMessage()}.
     */
    public DnssecFailureReason reason() {
        return reason;
    }
}
