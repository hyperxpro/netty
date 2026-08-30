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
package io.netty.handler.codec.http;

import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.CharsetUtil;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RedCell audit PoC for Finding #5.
 *
 * <p>The "chunked must be the last Transfer-Encoding" validator in
 * {@code HttpObjectDecoder} only inspects the value of the LAST {@code Transfer-Encoding}
 * header <em>line</em>, while {@link HttpUtil#isTransferEncodingChunked(HttpMessage)} frames
 * the body as chunked if ANY line contains {@code chunked}. Two separate lines
 * {@code Transfer-Encoding: chunked} then {@code Transfer-Encoding: gzip} therefore produce an
 * effective coding list of {@code chunked, gzip} (final coding = gzip), which RFC 9112 §6.1/§6.3
 * says the server MUST reject (400 + close). Netty instead accepts it and frames the body as
 * chunked - a classic TE.TE request-smuggling primitive.
 */
public class AuditPocTransferEncodingTest {

    /**
     * THE BUG: two separate TE lines (chunked, then a short non-chunked coding) are wrongly accepted
     * as chunked, and the chunked framing surfaces a smuggled second request.
     */
    @Test
    public void multiLineChunkedThenGzipIsWronglyAcceptedAsChunked() {
        String requestStr =
                "POST / HTTP/1.1\r\n" +
                "Host: x\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "Transfer-Encoding: gzip\r\n" +
                "\r\n" +
                "0\r\n" +
                "\r\n" +
                "GET /smuggled HTTP/1.1\r\n" +
                "Host: x\r\n" +
                "\r\n";

        EmbeddedChannel channel = new EmbeddedChannel(new HttpRequestDecoder());
        assertTrue(channel.writeInbound(Unpooled.copiedBuffer(requestStr, CharsetUtil.US_ASCII)));

        HttpRequest first = channel.readInbound();
        assertNotNull(first);
        // Spec violation: accepted (no failure) and framed as chunked.
        assertFalse(first.decoderResult().isFailure(),
                "BUG: multi-line 'chunked' + 'gzip' was accepted instead of rejected (RFC 9112 6.1/6.3)");
        assertTrue(HttpUtil.isTransferEncodingChunked(first), "BUG: body framed as chunked");
        assertEquals("/", first.uri());
        System.out.printf("[AuditPoc#5] two-line 'TE: chunked' + 'TE: gzip' -> decoderResult=%s,"
                        + " isTransferEncodingChunked=%b, firstUri=%s (ACCEPTED as chunked = BUG)%n",
                first.decoderResult(), HttpUtil.isTransferEncodingChunked(first), first.uri());

        // Because the body was framed as chunked, "0\r\n\r\n" terminated it and the trailing bytes were
        // parsed as a SECOND request. Drain everything and look for the smuggled GET.
        HttpRequest smuggled = null;
        for (Object msg = channel.readInbound(); msg != null; msg = channel.readInbound()) {
            if (msg instanceof HttpRequest) {
                smuggled = (HttpRequest) msg;
            }
            ReferenceCountUtil.release(msg);
        }
        assertNotNull(smuggled, "BUG: chunked framing surfaced a smuggled second request");
        assertEquals("/smuggled", smuggled.uri());
        System.out.printf("[AuditPoc#5]   -> chunked body consumed the '0 CRLF CRLF' last-chunk; "
                + "SMUGGLED second request decoded: %s %s%n", smuggled.method(), smuggled.uri());

        channel.finishAndReleaseAll();
    }

    /**
     * THE BUG, variant: the gate is {@code vLen > 7}, so any last line whose value is &lt;= 7 chars
     * (e.g. "deflate" == 7) also slips through even though it is not chunked.
     */
    @Test
    public void multiLineChunkedThenDeflateIsWronglyAcceptedAsChunked() {
        String requestStr =
                "POST / HTTP/1.1\r\n" +
                "Host: x\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "Transfer-Encoding: deflate\r\n" +
                "\r\n" +
                "0\r\n\r\n";

        EmbeddedChannel channel = new EmbeddedChannel(new HttpRequestDecoder());
        assertTrue(channel.writeInbound(Unpooled.copiedBuffer(requestStr, CharsetUtil.US_ASCII)));

        HttpRequest first = channel.readInbound();
        assertNotNull(first);
        assertFalse(first.decoderResult().isFailure(),
                "BUG: 'chunked' + 'deflate' (7-char last coding) was accepted instead of rejected");
        assertTrue(HttpUtil.isTransferEncodingChunked(first));
        channel.finishAndReleaseAll();
    }

    /**
     * CONTROL (already handled correctly): a SINGLE line "chunked, gzip" is rejected, because the
     * validator sees the whole comma list as the last line value (len 13 &gt; 7) and the region match fails.
     */
    @Test
    public void singleLineChunkedThenGzipIsCorrectlyRejected() {
        String requestStr =
                "POST / HTTP/1.1\r\n" +
                "Host: x\r\n" +
                "Transfer-Encoding: chunked, gzip\r\n" +
                "\r\n" +
                "0\r\n\r\n";

        EmbeddedChannel channel = new EmbeddedChannel(new HttpRequestDecoder());
        assertTrue(channel.writeInbound(Unpooled.copiedBuffer(requestStr, CharsetUtil.US_ASCII)));

        HttpRequest req = channel.readInbound();
        assertNotNull(req);
        assertTrue(req.decoderResult().isFailure(), "single-line 'chunked, gzip' must be rejected");
        assertInstanceOf(IllegalArgumentException.class, req.decoderResult().cause());
        System.out.printf("[AuditPoc#5] CONTROL single-line 'TE: chunked, gzip' -> decoderResult=%s,"
                        + " cause=%s (REJECTED = guard works)%n",
                req.decoderResult(), req.decoderResult().cause().getClass().getSimpleName());
        assertFalse(channel.finish());
    }

    /**
     * CONTROL (already handled correctly): Content-Length + Transfer-Encoding: chunked is rejected
     * with {@link ContentLengthNotAllowedException}.
     */
    @Test
    public void contentLengthPlusChunkedIsCorrectlyRejected() {
        String requestStr =
                "POST / HTTP/1.1\r\n" +
                "Host: x\r\n" +
                "Content-Length: 5\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "0\r\n\r\n";

        EmbeddedChannel channel = new EmbeddedChannel(new HttpRequestDecoder());
        assertTrue(channel.writeInbound(Unpooled.copiedBuffer(requestStr, CharsetUtil.US_ASCII)));

        HttpRequest req = channel.readInbound();
        assertNotNull(req);
        assertTrue(req.decoderResult().isFailure(), "CL + TE chunked must be rejected");
        assertInstanceOf(ContentLengthNotAllowedException.class, req.decoderResult().cause());
        assertFalse(channel.finish());
    }
}
