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

import io.netty.handler.codec.dns.DnsName;

import java.util.List;

/**
 * The {@link DnssecKeyCache} returned by {@link DnssecKeyCache#noop()}: it remembers nothing, so no trust is
 * carried from one validation to the next.
 */
final class NoopDnssecKeyCache implements DnssecKeyCache {

    static final NoopDnssecKeyCache INSTANCE = new NoopDnssecKeyCache();

    private NoopDnssecKeyCache() {
    }

    @Override
    public List<DnsDnskeyRecord> get(DnsName zone, long currentTimeMillis) {
        return null;
    }

    @Override
    public void put(DnsName zone, List<DnsDnskeyRecord> keys, long ttlSeconds, long currentTimeMillis) {
        // Deliberately nothing.
    }

    @Override
    public void clear() {
        // Deliberately nothing.
    }

    @Override
    public String toString() {
        return "DnssecKeyCache.noop()";
    }
}
