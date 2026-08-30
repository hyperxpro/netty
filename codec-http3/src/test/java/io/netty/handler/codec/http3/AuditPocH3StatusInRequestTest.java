/*
 * Copyright 2025 The Netty Project
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
package io.netty.handler.codec.http3;

import org.junit.jupiter.api.Test;

import static io.netty.handler.codec.http3.Http3Headers.PseudoHeaderName.AUTHORITY;
import static io.netty.handler.codec.http3.Http3Headers.PseudoHeaderName.METHOD;
import static io.netty.handler.codec.http3.Http3Headers.PseudoHeaderName.PATH;
import static io.netty.handler.codec.http3.Http3Headers.PseudoHeaderName.SCHEME;
import static io.netty.handler.codec.http3.Http3Headers.PseudoHeaderName.STATUS;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * AUDIT PoC - Finding #9 (CONFORMANCE).
 *
 * {@link Http3HeadersSink#validate} sets {@code request = pseudoHeader.isRequestOnly()} on EVERY pseudo-header,
 * so the request/response disposition reflects only the LAST pseudo-header seen. {@code finish()} for a request
 * checks that mandatory request pseudo-headers are PRESENT but never checks that response-only pseudo-headers
 * (e.g. {@code :status}) are ABSENT. Hence a request carrying {@code :status} is wrongly accepted whenever
 * {@code :status} is not the last pseudo-header - an order-dependent malformed-header acceptance.
 *
 * RFC 9114 Section 4.3 / 4.3.1: pseudo-header fields defined for responses MUST NOT appear in requests; a
 * message with such a field MUST be treated as malformed, independent of field order.
 */
public class AuditPocH3StatusInRequestTest {

    /** BUG: ':status' first, then the mandatory request pseudo-headers -> wrongly ACCEPTED. */
    @Test
    public void requestWithStatusPseudoHeaderIsAcceptedWhenStatusNotLast() {
        Http3HeadersSink sink = new Http3HeadersSink(new DefaultHttp3Headers(), 512, true, false);

        // Response-only pseudo-header first ...
        sink.accept(STATUS.value(), "200");
        // ... followed by a complete, valid GET request pseudo-header set. The LAST pseudo-header is
        // ':authority' (request-only), so the sink ends up classified as a request and the stray ':status'
        // is never rejected.
        sink.accept(METHOD.value(), "GET");
        sink.accept(SCHEME.value(), "https");
        sink.accept(PATH.value(), "/");
        sink.accept(AUTHORITY.value(), "example.com");

        try {
            sink.finish();
            System.out.println("[Finding #9] request containing :status was ACCEPTED (no exception) - BUG confirmed");
        } catch (Exception e) {
            fail("Expected the buggy sink to ACCEPT the request with :status, but it threw: " + e);
        }
    }

    /** CONTROL: the very same field set with ':status' LAST IS rejected - proving order-dependence. */
    @Test
    public void sameRequestWithStatusLastIsRejected() {
        Http3HeadersSink sink = new Http3HeadersSink(new DefaultHttp3Headers(), 512, true, false);

        sink.accept(METHOD.value(), "GET");
        sink.accept(SCHEME.value(), "https");
        sink.accept(PATH.value(), "/");
        sink.accept(AUTHORITY.value(), "example.com");
        // ':status' last -> sink classified as a response -> the extra request pseudo-headers trip the
        // response mandatory-header check and it correctly throws.
        sink.accept(STATUS.value(), "200");

        Http3HeadersValidationException ex = assertThrows(Http3HeadersValidationException.class, sink::finish);
        System.out.println("[Finding #9] control (status last) correctly REJECTED: " + ex.getMessage());
        assertTrue(true);
    }
}
