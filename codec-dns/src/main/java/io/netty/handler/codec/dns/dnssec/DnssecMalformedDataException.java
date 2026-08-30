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
 * Raised when DNSSEC wire data is structurally invalid: a {@code DNSKEY} public key that does not match the encoding
 * its algorithm mandates, an elliptic-curve point that is not on the curve, or an {@code RRSIG} signature whose
 * length cannot be reconciled with the key that is supposed to have produced it.
 *
 * <p>Unlike {@link DnssecUnsupportedAlgorithmException} this is a hard failure: the data is wrong, not merely
 * unrecognised, so a validator must not downgrade to <em>Insecure</em> because of it.</p>
 */
public final class DnssecMalformedDataException extends DnssecException {

    private static final long serialVersionUID = 2846318248901237045L;

    /**
     * Creates a new instance.
     *
     * @param message the detail message.
     */
    public DnssecMalformedDataException(String message) {
        super(message);
    }

    /**
     * Creates a new instance.
     *
     * @param message the detail message.
     * @param cause   the underlying cause.
     */
    public DnssecMalformedDataException(String message, Throwable cause) {
        super(message, cause);
    }
}
