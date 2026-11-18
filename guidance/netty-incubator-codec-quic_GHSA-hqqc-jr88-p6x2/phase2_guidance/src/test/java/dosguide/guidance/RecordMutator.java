package dosguide.guidance;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

/**
 * Mutation operators shared by {@link V1Guidance} and {@link PkgRisk1Guidance} (not a Guidance itself).
 *
 * <p>Input format (as decoded by the frozen harness QuicCodecFuzzTest.serveInitialPackets): a sequence of
 * records {@code [len byte][len bytes]}; each record's bytes are the destination connection id (DCID) of one
 * client Initial packet. Record parsing here mirrors the harness exactly.</p>
 *
 * <p>Operators: byte-level (flip/set/insert/delete), dictionary tokens from the attack path, record-level
 * (fresh/replace/splice/length), repetition (repeat a run k times, double the whole input) and the
 * hash-preserving "carry" clone derived from {@code java.nio.ByteBuffer#hashCode}
 * ({@code h = 31*h + get(i)} iterating from the last byte down, i.e. byte j has weight 31^j): moving +31 at
 * byte j and -1 at byte j+1 (or the opposite) leaves the hash unchanged. The operator applies to whatever
 * record the search selected; no concrete key or key set is embedded.</p>
 */
final class RecordMutator {

    /**
     * Single-byte dictionary tokens from the attack path: Quic.MAX_CONN_ID_LEN (20) and the server's default
     * localConnIdLength (20), RFC 9000 minimum client Initial DCID length (8), 10, an empty id (0), the
     * ByteBuffer.hashCode multiplier (31) and signed-byte boundaries used by ByteBuffer.get (0x7f, 0x80, 0xff).
     */
    static final byte[] DICT = {20, 8, 10, 0, 31, 0x7f, (byte) 0x80, (byte) 0xff, 1};

    private final Random rnd;
    private final int maxLen;
    private final int targetBytes;
    /** preferred DCID lengths for fresh records (method-specific). */
    private final int[] preferredLens;
    private final boolean shortenOp;

    String lastOp = "";

    RecordMutator(Random rnd, int maxLen, int targetBytes, int[] preferredLens, boolean shortenOp) {
        this.rnd = rnd;
        this.maxLen = maxLen;
        this.targetBytes = targetBytes;
        this.preferredLens = preferredLens;
        this.shortenOp = shortenOp;
    }

    // ------------------------------------------------------------------ records

    static List<byte[]> parse(byte[] data) {
        List<byte[]> out = new ArrayList<>();
        int off = 0;
        while (off < data.length) {
            int len = Math.min(data[off] & 0xff, data.length - off - 1);
            out.add(Arrays.copyOfRange(data, off + 1, off + 1 + len));
            off += 1 + len;
        }
        return out;
    }

    byte[] encode(List<byte[]> recs) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (byte[] r : recs) {
            if (bos.size() + 1 + r.length > maxLen) {
                break;
            }
            bos.write(r.length);
            bos.write(r, 0, r.length);
        }
        byte[] b = bos.toByteArray();
        if (b.length == 0 && !recs.isEmpty()) {
            b = cap(concatRecord(recs.get(0)));
        }
        return b;
    }

    private static byte[] concatRecord(byte[] r) {
        byte[] b = new byte[r.length + 1];
        b[0] = (byte) r.length;
        System.arraycopy(r, 0, b, 1, r.length);
        return b;
    }

    byte[] cap(byte[] b) {
        return b.length > maxLen ? Arrays.copyOf(b, maxLen) : b;
    }

    int freshLen() {
        double p = rnd.nextDouble();
        if (p < 0.65) {
            return preferredLens[rnd.nextInt(preferredLens.length)];
        } else if (p < 0.95) {
            return 8 + rnd.nextInt(13); // 8..20
        }
        return rnd.nextInt(8);
    }

    byte[] freshRecord() {
        byte[] r = new byte[freshLen()];
        rnd.nextBytes(r);
        return r;
    }

    byte[] seed() {
        List<byte[]> recs = new ArrayList<>();
        int n = 2 + rnd.nextInt(3);
        for (int i = 0; i < n; i++) {
            recs.add(freshRecord());
        }
        return cap(encode(recs));
    }

    // ------------------------------------------------------------------ hash-preserving carry

    /** Applies 1..3 hash-preserving carries to a copy of r; returns null if none is applicable. */
    byte[] carry(byte[] r) {
        if (r.length < 2) {
            return null;
        }
        byte[] c = r.clone();
        int steps = 1 + rnd.nextInt(3);
        int applied = 0;
        for (int tries = 0; tries < 24 && applied < steps; tries++) {
            int j = rnd.nextInt(c.length - 1);
            boolean up = rnd.nextBoolean();
            int a = c[j];
            int b = c[j + 1];
            if (up && a + 31 <= 127 && b - 1 >= -128) {
                c[j] = (byte) (a + 31);
                c[j + 1] = (byte) (b - 1);
                applied++;
            } else if (!up && a - 31 >= -128 && b + 1 <= 127) {
                c[j] = (byte) (a - 31);
                c[j + 1] = (byte) (b + 1);
                applied++;
            }
        }
        return applied == 0 ? null : c;
    }

    /** Random walk of k distinct hash-preserving clones starting from r. */
    List<byte[]> carryWalk(byte[] r, int k, Set<Key> seen) {
        List<byte[]> out = new ArrayList<>(Math.min(k, 1 << 16));
        byte[] cur = r;
        int misses = 0;
        while (out.size() < k && misses < 64) {
            byte[] next = carry(cur);
            if (next == null) {
                break;
            }
            cur = next;
            if (seen.add(new Key(next))) {
                out.add(next);
                misses = 0;
            } else {
                misses++;
            }
        }
        return out;
    }

    private Set<Key> seenOf(List<byte[]> recs) {
        Set<Key> s = new HashSet<>(recs.size() * 2 + 16);
        for (byte[] r : recs) {
            s.add(new Key(r));
        }
        return s;
    }

    /**
     * Number of repetitions: small, or log-uniform up to doubling the current input (so sizes grow
     * geometrically, one doubling per step, and can reach maxLen in a few steps).
     */
    int chooseK(int unitBytes, int curLen) {
        unitBytes = Math.max(1, unitBytes);
        int room = Math.max(0, maxLen - curLen);
        int kRoom = Math.max(1, room / unitBytes);
        int kDouble = Math.max(16, curLen / unitBytes);
        int kMax = Math.max(1, Math.min(kRoom, kDouble));
        int k;
        if (rnd.nextDouble() < 0.5) {
            k = 2 + rnd.nextInt(15);
        } else {
            double lg = Math.log(Math.max(2, kMax)) * rnd.nextDouble();
            k = (int) Math.max(2, Math.exp(lg));
        }
        return Math.max(1, Math.min(k, kMax));
    }

    /**
     * Flat-signal growth: appends fresh random records until the input doubles (at least 64 bytes), keeping the
     * existing records (and whatever structure they have) intact; the result is cut at {@code limit}.
     */
    byte[] appendFresh(byte[] in, int limit) {
        List<byte[]> recs = parse(in);
        int goal = Math.min(limit, Math.max(in.length * 2, in.length + 64));
        int size = in.length;
        while (size < goal) {
            byte[] r = freshRecord();
            recs.add(r);
            size += 1 + r.length;
        }
        lastOp = "appendFresh(" + size + ")";
        byte[] out = encode(recs);
        return out.length > limit ? Arrays.copyOf(out, limit) : out;
    }

    /**
     * Structure-preserving growth: every record gets a hash-preserving carry clone (doubling), or, above
     * {@code gentleAbove} bytes, only a random quarter of the records (x1.25), so each hash class grows in
     * proportion and the input density is kept.
     */
    byte[] growWithCarry(byte[] in, int gentleAbove) {
        List<byte[]> recs = parse(in);
        Set<Key> seen = seenOf(recs);
        boolean gentle = in.length >= gentleAbove;
        int budget = maxLen - in.length;
        List<byte[]> add = new ArrayList<>();
        for (byte[] r : recs) {
            if (gentle && rnd.nextInt(4) != 0) {
                continue;
            }
            if (budget < 1 + r.length) {
                break;
            }
            List<byte[]> c = carryWalk(r, 1, seen);
            if (c.isEmpty()) {
                continue;
            }
            add.add(c.get(0));
            budget -= 1 + r.length;
        }
        recs.addAll(add);
        lastOp = "growWithCarry(+" + add.size() + (gentle ? ",x1.25" : ",x2") + ")";
        return encode(recs);
    }

    // ------------------------------------------------------------------ operators

    /**
     * One random operator. Growth of ordinary parents is bounded by {@code max(parent length, targetBytes)}
     * (a scheduling rule, so that inputs beyond the target size come from the structure-preserving dense
     * frontier); the dense frontier ({@link #growDense}) grows up to maxLen.
     */
    byte[] mutate(byte[] in, byte[] other, boolean bounded) {
        byte[] out = mutate(in, other);
        int limit = Math.max(in.length, Math.min(maxLen, targetBytes));
        if (bounded && out.length > limit) {
            out = Arrays.copyOf(out, limit);
        }
        return out;
    }

    byte[] mutate(byte[] in, byte[] other) {
        int op = rnd.nextInt(shortenOp ? 17 : 16);
        byte[] out;
        switch (op) {
            case 0: out = bitFlip(in); break;
            case 1: out = setRandomByte(in); break;
            case 2: out = dictOverwrite(in); break;
            case 3: out = dictInsert(in); break;
            case 4: out = insertRandomBytes(in); break;
            case 5: out = deleteBytes(in); break;
            case 6: out = replaceRecordFresh(in); break;
            case 7: out = insertRecordFresh(in); break;
            case 8: out = setRecordLength(in); break;
            case 9: out = splice(in, other); break;
            case 10: out = repeatRun(in); break;
            case 11: out = doubleWhole(in); break;
            case 12:
            case 13: out = repeatRecordWithCarry(in); break;
            case 14: out = doubleWithCarry(in); break;
            case 15: out = carryInPlace(in); break;
            default: out = shortenRecords(in); break;
        }
        if (out == null || out.length == 0) {
            out = seed();
            lastOp = lastOp + "+reseed";
        }
        return cap(out);
    }

    /** Structure-preserving growth of a high-signal input (dense frontier). */
    byte[] growDense(byte[] in) {
        byte[] out = rnd.nextDouble() < 0.8 ? growWithCarry(in, targetBytes) : repeatRecordWithCarry(in);
        if (out == null || out.length == 0) {
            out = seed();
        }
        return cap(out);
    }

    byte[] bitFlip(byte[] in) {
        lastOp = "bitFlip";
        if (in.length == 0) {
            return in;
        }
        byte[] b = in.clone();
        int n = 1 + rnd.nextInt(4);
        for (int i = 0; i < n; i++) {
            int p = rnd.nextInt(b.length);
            b[p] ^= (byte) (1 << rnd.nextInt(8));
        }
        return b;
    }

    byte[] setRandomByte(byte[] in) {
        lastOp = "setByte";
        if (in.length == 0) {
            return in;
        }
        byte[] b = in.clone();
        b[rnd.nextInt(b.length)] = (byte) rnd.nextInt(256);
        return b;
    }

    byte[] dictOverwrite(byte[] in) {
        lastOp = "dictOverwrite";
        if (in.length == 0) {
            return in;
        }
        byte[] b = in.clone();
        b[rnd.nextInt(b.length)] = DICT[rnd.nextInt(DICT.length)];
        return b;
    }

    byte[] dictInsert(byte[] in) {
        lastOp = "dictInsert";
        int p = rnd.nextInt(in.length + 1);
        byte[] b = new byte[in.length + 1];
        System.arraycopy(in, 0, b, 0, p);
        b[p] = DICT[rnd.nextInt(DICT.length)];
        System.arraycopy(in, p, b, p + 1, in.length - p);
        return b;
    }

    byte[] insertRandomBytes(byte[] in) {
        lastOp = "insertBytes";
        int n = 1 + rnd.nextInt(8);
        int p = rnd.nextInt(in.length + 1);
        byte[] b = new byte[in.length + n];
        System.arraycopy(in, 0, b, 0, p);
        for (int i = 0; i < n; i++) {
            b[p + i] = (byte) rnd.nextInt(256);
        }
        System.arraycopy(in, p, b, p + n, in.length - p);
        return b;
    }

    byte[] deleteBytes(byte[] in) {
        lastOp = "deleteBytes";
        if (in.length < 2) {
            return in;
        }
        int n = 1 + rnd.nextInt(Math.min(8, in.length - 1));
        int p = rnd.nextInt(in.length - n + 1);
        byte[] b = new byte[in.length - n];
        System.arraycopy(in, 0, b, 0, p);
        System.arraycopy(in, p + n, b, p, in.length - p - n);
        return b;
    }

    byte[] replaceRecordFresh(byte[] in) {
        lastOp = "replaceRecord";
        List<byte[]> recs = parse(in);
        if (recs.isEmpty()) {
            recs.add(freshRecord());
        } else {
            recs.set(rnd.nextInt(recs.size()), freshRecord());
        }
        return encode(recs);
    }

    byte[] insertRecordFresh(byte[] in) {
        lastOp = "insertRecord";
        List<byte[]> recs = parse(in);
        recs.add(rnd.nextInt(recs.size() + 1), freshRecord());
        return encode(recs);
    }

    byte[] setRecordLength(byte[] in) {
        lastOp = "recordLength";
        List<byte[]> recs = parse(in);
        if (recs.isEmpty()) {
            return in;
        }
        int i = rnd.nextInt(recs.size());
        int len = rnd.nextBoolean() ? (DICT[rnd.nextInt(DICT.length)] & 0xff) : freshLen();
        len = Math.min(len, 255);
        byte[] r = recs.get(i);
        byte[] n = Arrays.copyOf(r, len);
        for (int j = r.length; j < len; j++) {
            n[j] = (byte) rnd.nextInt(256);
        }
        recs.set(i, n);
        return encode(recs);
    }

    byte[] splice(byte[] in, byte[] other) {
        lastOp = "splice";
        if (other == null || other.length == 0) {
            return insertRecordFresh(in);
        }
        List<byte[]> a = parse(in);
        List<byte[]> b = parse(other);
        if (b.isEmpty()) {
            return in;
        }
        int from = rnd.nextInt(b.size());
        int to = from + 1 + rnd.nextInt(Math.min(64, b.size() - from));
        a.addAll(rnd.nextInt(a.size() + 1), b.subList(from, to));
        return encode(a);
    }

    byte[] repeatRun(byte[] in) {
        lastOp = "repeatRun";
        List<byte[]> recs = parse(in);
        if (recs.isEmpty()) {
            return in;
        }
        int from = rnd.nextInt(recs.size());
        int to = from + 1 + rnd.nextInt(Math.min(8, recs.size() - from));
        List<byte[]> run = new ArrayList<>(recs.subList(from, to));
        int unit = 0;
        for (byte[] r : run) {
            unit += 1 + r.length;
        }
        int k = chooseK(unit, in.length);
        List<byte[]> rep = new ArrayList<>(run.size() * k);
        for (int i = 0; i < k; i++) {
            rep.addAll(run);
        }
        recs.addAll(to, rep);
        lastOp = "repeatRun(k=" + k + ")";
        return encode(recs);
    }

    byte[] doubleWhole(byte[] in) {
        lastOp = "doubleWhole";
        int n = Math.min(in.length, Math.max(0, maxLen - in.length));
        byte[] b = Arrays.copyOf(in, in.length + n);
        System.arraycopy(in, 0, b, in.length, n);
        return b;
    }

    byte[] repeatRecordWithCarry(byte[] in) {
        List<byte[]> recs = parse(in);
        if (recs.isEmpty()) {
            recs.add(freshRecord());
        }
        int i = rnd.nextInt(recs.size());
        byte[] base = recs.get(i);
        if (base.length < 2) {
            base = freshRecord();
            recs.set(i, base);
            if (base.length < 2) {
                lastOp = "repeatRecordWithCarry(skip)";
                return encode(recs);
            }
        }
        int k = chooseK(1 + base.length, in.length);
        List<byte[]> clones = carryWalk(base, k, seenOf(recs));
        recs.addAll(i + 1, clones);
        lastOp = "repeatRecordWithCarry(k=" + clones.size() + ",len=" + base.length + ")";
        return encode(recs);
    }

    byte[] doubleWithCarry(byte[] in) {
        List<byte[]> recs = parse(in);
        Set<Key> seen = seenOf(recs);
        int budget = maxLen - in.length;
        List<byte[]> add = new ArrayList<>(recs.size());
        for (byte[] r : recs) {
            if (budget < 1 + r.length) {
                break;
            }
            List<byte[]> c = carryWalk(r, 1, seen);
            if (c.isEmpty()) {
                continue;
            }
            add.add(c.get(0));
            budget -= 1 + r.length;
        }
        recs.addAll(add);
        lastOp = "doubleWithCarry(+" + add.size() + ")";
        return encode(recs);
    }

    byte[] carryInPlace(byte[] in) {
        List<byte[]> recs = parse(in);
        if (recs.isEmpty()) {
            return in;
        }
        int n = 1 + rnd.nextInt(Math.min(16, recs.size()));
        for (int t = 0; t < n; t++) {
            int i = rnd.nextInt(recs.size());
            byte[] c = carry(recs.get(i));
            if (c != null) {
                recs.set(i, c);
            }
        }
        lastOp = "carryInPlace";
        return encode(recs);
    }

    /** PkgRisk1 only: truncate records toward the densest RFC-valid DCID lengths (8..10 bytes). */
    byte[] shortenRecords(byte[] in) {
        List<byte[]> recs = parse(in);
        if (recs.isEmpty()) {
            return in;
        }
        int len = 8 + rnd.nextInt(3);
        int from = rnd.nextInt(recs.size());
        int to = rnd.nextBoolean() ? recs.size() : from + 1;
        for (int i = from; i < to; i++) {
            byte[] r = recs.get(i);
            if (r.length > len) {
                recs.set(i, Arrays.copyOf(r, len));
            }
        }
        lastOp = "shortenRecords(" + len + ")";
        return encode(recs);
    }

    /** Byte-array key with a seeded 64-bit mixing hash (ByteBuffer/Arrays hashCode would collide here). */
    static final class Key {
        private static final long SEED = 0x9E3779B97F4A7C15L ^ System.nanoTime();
        final byte[] b;
        final int h;

        Key(byte[] b) {
            this.b = b;
            long x = SEED;
            for (byte v : b) {
                x ^= (v & 0xff);
                x *= 0x100000001B3L;
                x ^= x >>> 29;
            }
            x ^= b.length;
            x *= 0xBF58476D1CE4E5B9L;
            x ^= x >>> 31;
            this.h = (int) (x ^ (x >>> 32));
        }

        @Override
        public int hashCode() {
            return h;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Key && Arrays.equals(b, ((Key) o).b);
        }
    }
}
