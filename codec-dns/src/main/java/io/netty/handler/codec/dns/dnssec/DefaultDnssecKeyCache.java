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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.dns.DnsName;
import io.netty.handler.codec.dns.DnsRecordType;
import io.netty.util.internal.ObjectUtil;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A {@link DnssecKeyCache} that holds at most a fixed number of zones, evicting the least recently used one, and
 * that drops an entry once its TTL has run out.
 *
 * <p>Both bounds are load-bearing rather than tidiness. The zone names a validation looks up are chosen by whoever
 * sent the query, so an unbounded map keyed by zone is a memory-exhaustion primitive; and a key set that outlived
 * its TTL is a key set the zone may have rolled away from, which turns a rollover into a stretch of Bogus answers
 * that no operator can explain.</p>
 *
 * <p>The stored form is a copy of each {@code DNSKEY} record's {@code RDATA} octets, so this cache holds nothing
 * reference-counted and never has to release anything. {@link #get(DnsName, long)} builds fresh records over
 * copies of those octets, which the caller owns; see {@link DnssecKeyCache} for why it is done that way.</p>
 *
 * <p>Thread-safe. Every operation takes one lock over the whole map, which is sound for a structure this small:
 * an entry is a handful of keys and the map holds {@link #maxZones()} of them.</p>
 */
public final class DefaultDnssecKeyCache implements DnssecKeyCache {

    /**
     * The number of zones {@link #DefaultDnssecKeyCache()} keeps. Enough for the root, a handful of top-level
     * domains and the zones under them that one application talks to.
     */
    public static final int DEFAULT_MAX_ZONES = 64;

    private final int maxZones;
    private final Map<DnsName, CachedKeySet> entries;

    /**
     * Creates a cache holding {@link #DEFAULT_MAX_ZONES} zones.
     */
    public DefaultDnssecKeyCache() {
        this(DEFAULT_MAX_ZONES);
    }

    /**
     * Creates a cache holding {@code maxZones} zones.
     *
     * @param maxZones the greatest number of zones to remember, at least {@code 1}.
     */
    public DefaultDnssecKeyCache(int maxZones) {
        this.maxZones = ObjectUtil.checkPositive(maxZones, "maxZones");
        entries = new LinkedHashMap<DnsName, CachedKeySet>(16, 0.75f, true) {

            private static final long serialVersionUID = 4229126486889894765L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<DnsName, CachedKeySet> eldest) {
                return size() > DefaultDnssecKeyCache.this.maxZones;
            }
        };
    }

    /**
     * Returns the greatest number of zones this cache remembers.
     */
    public int maxZones() {
        return maxZones;
    }

    /**
     * Returns how many zones are currently remembered, including any whose TTL has run out but which have not been
     * looked up since. Intended for tests and for metrics.
     */
    public int size() {
        synchronized (entries) {
            return entries.size();
        }
    }

    @Override
    public List<DnsDnskeyRecord> get(DnsName zone, long currentTimeMillis) {
        ObjectUtil.checkNotNull(zone, "zone");
        CachedKeySet entry;
        synchronized (entries) {
            entry = entries.get(zone);
            if (entry == null) {
                return null;
            }
            if (currentTimeMillis - entry.expiresAtMillis >= 0) {
                entries.remove(zone);
                return null;
            }
        }
        // Built outside the lock: a CachedKeySet is immutable once published, and record construction allocates.
        List<DnsDnskeyRecord> keys = new ArrayList<DnsDnskeyRecord>(entry.keys.length);
        for (int i = 0; i < entry.keys.length; i++) {
            keys.add(entry.keys[i].toRecord(zone));
        }
        return keys;
    }

    @Override
    public void put(DnsName zone, List<DnsDnskeyRecord> keys, long ttlSeconds, long currentTimeMillis) {
        ObjectUtil.checkNotNull(zone, "zone");
        ObjectUtil.checkNotNull(keys, "keys");
        if (keys.isEmpty() || ttlSeconds <= 0) {
            return;
        }
        CachedKey[] cached = new CachedKey[keys.size()];
        for (int i = 0; i < cached.length; i++) {
            DnsDnskeyRecord key = ObjectUtil.checkNotNull(keys.get(i), "keys[" + i + ']');
            ByteBuf content = key.content();
            byte[] rdata = new byte[content.readableBytes()];
            content.getBytes(content.readerIndex(), rdata);
            cached[i] = new CachedKey(key.name(), key.dnsClass(), key.timeToLive(), rdata);
        }
        // Guards against a TTL large enough to wrap the deadline into the past.
        long expiresAt = currentTimeMillis + ttlSeconds * 1000L;
        CachedKeySet entry = new CachedKeySet(expiresAt < currentTimeMillis ? Long.MAX_VALUE : expiresAt, cached);
        synchronized (entries) {
            entries.put(zone, entry);
        }
    }

    @Override
    public void clear() {
        synchronized (entries) {
            entries.clear();
        }
    }

    @Override
    public String toString() {
        return "DefaultDnssecKeyCache(" + size() + '/' + maxZones + " zone(s))";
    }

    private static final class CachedKeySet {

        final long expiresAtMillis;
        final CachedKey[] keys;

        CachedKeySet(long expiresAtMillis, CachedKey[] keys) {
            this.expiresAtMillis = expiresAtMillis;
            this.keys = keys;
        }
    }

    private static final class CachedKey {

        private final String name;
        private final int dnsClass;
        private final long timeToLive;
        private final byte[] rdata;

        CachedKey(String name, int dnsClass, long timeToLive, byte[] rdata) {
            this.name = name;
            this.dnsClass = dnsClass;
            this.timeToLive = timeToLive;
            this.rdata = rdata;
        }

        /**
         * Builds a record over a copy of the stored octets. The copy is what keeps a caller that writes into
         * {@link DnsDnskeyRecord#content()} from rewriting every future answer this cache gives.
         */
        DnsDnskeyRecord toRecord(DnsName owner) {
            return new DnsDnskeyRecord(name, DnsRecordType.DNSKEY, dnsClass, timeToLive, owner,
                    Unpooled.wrappedBuffer(rdata.clone()));
        }
    }
}
