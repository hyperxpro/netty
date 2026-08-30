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

import io.netty.handler.codec.DecoderException;

/**
 * Base class for every failure raised while turning DNSSEC wire data into JDK cryptographic objects.
 *
 * <p>Callers are expected to distinguish the two subclasses, because
 * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.2">RFC 4035, Section 5.2</a> gives them very
 * different security outcomes:</p>
 * <ul>
 *   <li>{@link DnssecUnsupportedAlgorithmException} means "we cannot evaluate this", which normally makes the
 *   answer <em>Insecure</em> rather than <em>Bogus</em>;</li>
 *   <li>{@link DnssecMalformedDataException} means the data itself is broken, which is a hard failure.</li>
 * </ul>
 *
 * <p><strong>A validator must not use this type as its catch-all.</strong> Only failures in the cryptographic
 * material are reported here. Failures in the <em>wire framing</em> of a DNSSEC record, such as a compression
 * pointer that does not point backwards, an out-of-order {@code NSEC} type-bitmap window or a base32hex label with
 * non-zero trailing bits, are reported as {@link io.netty.handler.codec.CorruptedFrameException}, consistent with
 * every other decoder in this module. Both extend {@link io.netty.handler.codec.DecoderException}, so a validator
 * that means "this record cannot be trusted" must catch {@link io.netty.handler.codec.DecoderException}. Catching
 * {@code DnssecException} instead would let a malformed type bitmap escape the validation path and surface as an
 * unrelated decode failure rather than as a <em>Bogus</em> verdict.</p>
 */
public class DnssecException extends DecoderException {

    private static final long serialVersionUID = 6015323968835870923L;

    /**
     * Creates a new instance.
     *
     * @param message the detail message.
     */
    public DnssecException(String message) {
        super(message);
    }

    /**
     * Creates a new instance.
     *
     * @param message the detail message.
     * @param cause   the underlying cause.
     */
    public DnssecException(String message, Throwable cause) {
        super(message, cause);
    }
}
