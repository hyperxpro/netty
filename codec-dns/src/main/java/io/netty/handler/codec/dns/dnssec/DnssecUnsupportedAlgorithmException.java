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

/**
 * Raised when DNSSEC material cannot be evaluated by this build or this JVM, although nothing about it is known to
 * be wrong. There are three ways that happens: this implementation does not support the algorithm or digest type,
 * the running JDK does not offer it, or the JDK's provider declines to build an otherwise well-formed key.
 *
 * <p>The last case is real rather than theoretical: {@code SunRsaSign} refuses an RSA exponent that is not smaller
 * than the modulus, and refuses an exponent longer than 64 bits once the modulus exceeds 3072 bits, while
 * <a href="https://www.rfc-editor.org/rfc/rfc3110.html#section-2">RFC 3110, Section 2</a> permits exponents of up
 * to 4096 bits. Such a key is legal and simply unusable here.
 *
 * <p>This is <em>not</em> a data error, and the distinction matters: <em>Bogus</em> should mean the validator holds
 * proof of an inconsistency, and a limitation of the local runtime is no such proof. A validator that cannot
 * evaluate any of the algorithms offered by a zone must treat that zone as <em>Insecure</em> rather than
 * <em>Bogus</em>, per
 * <a href="https://www.rfc-editor.org/rfc/rfc4035.html#section-5.2">RFC 4035, Section 5.2</a> and
 * <a href="https://www.rfc-editor.org/rfc/rfc6840.html#section-5.3">RFC 6840, Section 5.3</a>.
 *
 * <p>Callers should surface this at warning level. It is not logged where it is raised, because that code runs once
 * per record on attacker-supplied input and an unbounded log statement there is a flooding vector; the message
 * names the algorithm and the provider's own diagnostic is kept as the cause, so a caller has everything an
 * operator needs to see which key was skipped and why.
 */
public final class DnssecUnsupportedAlgorithmException extends DnssecException {

    private static final long serialVersionUID = -6229479124348064548L;

    /**
     * Creates a new instance.
     *
     * @param message the detail message.
     */
    public DnssecUnsupportedAlgorithmException(String message) {
        super(message);
    }

    /**
     * Creates a new instance.
     *
     * @param message the detail message.
     * @param cause   the underlying cause.
     */
    public DnssecUnsupportedAlgorithmException(String message, Throwable cause) {
        super(message, cause);
    }
}
