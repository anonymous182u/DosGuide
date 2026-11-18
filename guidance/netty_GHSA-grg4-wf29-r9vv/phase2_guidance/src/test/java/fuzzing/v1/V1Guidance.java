package fuzzing.v1;

import dosguide.validate.SignalSource;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.compression.Bzip2Encoder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Guidance for target V1 only: Bzip2Decoder unbounded multi-block decompression bomb (CWE-409).
 *
 * <p>Input model: the harness method {@code fuzzBzip2DecoderDecode(InputStream)} reads raw bytes, so
 * {@link #getInput()} returns the bzip2 stream bytes directly ([R25]/[R31]).</p>
 *
 * <p>Signals (all measured by the V1 java agent inside Bzip2BlockDecompressor, which Bzip2Decoder#decode
 * drives; never computed from the input):</p>
 * <ul>
 *   <li>{@code retainedBytes}: decoded bytes of CRC-valid blocks, i.e. bytes held in the decoder's out list</li>
 *   <li>{@code decodedBytes}: all bytes returned by Bzip2BlockDecompressor#read()</li>
 *   <li>{@code bwtBytes}: sum of Bzip2BlockDecompressor#blockLength() over blocks reaching the output stage</li>
 * </ul>
 *
 * <p>Mutation: a decoded genome (block-size digit + (byte, runLength) plaintext records) re-encoded with
 * Netty's own {@link Bzip2Encoder} (valid CRCs), plus byte-level ops, chunk repetition and a dictionary of
 * bzip2 literals from Bzip2Constants/Bzip2Decoder. The Guidance never decides failures and writes no failure
 * files ([R6]); it only saves its corpus.</p>
 */
public class V1Guidance implements Guidance, SignalSource {

    /** Single syntactic tokens from Bzip2Constants / Bzip2Decoder (magic numbers, block-size digit). */
    private static final byte[][] DICT = {
        {'B', 'Z', 'h'},                                   // MAGIC_NUMBER
        {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, // block size digit
        {0x31, 0x41, 0x59, 0x26, 0x53, 0x59},              // BLOCK_HEADER_MAGIC_1/2
        {0x17, 0x72, 0x45, 0x38, 0x50, (byte) 0x90},       // END_OF_STREAM_MAGIC_1/2
    };

    private static final int MAX_RECORDS = 4096;
    private static final long MAX_RUN = 1L << 34;

    /** Decoded representation: plaintext = concatenation of runs (value repeated len times). */
    static final class Genome {
        int level;
        final List<long[]> recs = new ArrayList<>();

        Genome copy() {
            Genome g = new Genome();
            g.level = level;
            for (long[] r : recs) {
                g.recs.add(new long[] {r[0], r[1]});
            }
            return g;
        }

        long plainBytes() {
            long s = 0;
            for (long[] r : recs) {
                s += r[1];
            }
            return s;
        }
    }

    static final class Entry {
        final int id;
        final byte[] data;
        final Genome genome;
        final long retained;
        final long decoded;
        final long bwt;
        final long valid;
        final long reached;

        Entry(int id, byte[] data, Genome genome, long retained, long decoded, long bwt, long valid, long reached) {
            this.id = id;
            this.data = data;
            this.genome = genome;
            this.retained = retained;
            this.decoded = decoded;
            this.bwt = bwt;
            this.valid = valid;
            this.reached = reached;
        }

        /** Method-specific: kept blocks per decode() call dominate, then kept bytes, then raw decoding. */
        double score() {
            return retained + valid * 1_000_000.0 + decoded / 16.0 + bwt / 64.0 + reached * 1000.0;
        }
    }

    private static final class Candidate {
        byte[] data;
        Genome genome;
        int parent = -1;
        String ops = "";
    }

    private final String label;
    private final File corpusDir;
    private final long maxDurationMs;
    private final PrintStream log;
    private final int maxInput;
    private final long encodeBudgetMs;
    private final Random rnd;
    private final long startMs = System.currentTimeMillis();

    private final List<Entry> corpus = new ArrayList<>();
    private final Deque<Candidate> seeds = new ArrayDeque<>();
    private final Set<Long> statePairs = new HashSet<>();
    private final byte[] chunk = new byte[1 << 20];

    private Candidate current;
    private Map<String, Double> lastSignals = zeroSignals();
    private int nextId;

    // best-so-far (retention), volatile for the logger thread
    private volatile long bestRetained;
    private volatile long bestValid;
    private volatile long bestDecoded;
    private volatile long bestBwt;
    private volatile double bestRatio;
    private volatile int maxLen;
    private volatile long execs;
    private volatile long failures;
    private volatile long timeouts;
    private volatile long invalids;
    private volatile long encodeMsTotal;
    private volatile long lastRetained;
    private volatile int lastLen;
    private volatile int corpusSize;

    private final ScheduledExecutorService logger;

    public V1Guidance(String label, File outputDir, long maxDurationMs, PrintStream log) {
        this.label = label;
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.maxDurationMs = maxDurationMs;
        this.log = log != null ? log : System.err;
        this.maxInput = Math.max(1, Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240));
        this.encodeBudgetMs = Long.getLong("v1.encodeBudgetMs", 15000L);
        long seed = Long.getLong("v1.seed", System.nanoTime());
        this.rnd = new Random(seed);
        for (int i = 0; i < 4; i++) {
            Candidate c = new Candidate();
            c.genome = randomGenome();
            c.ops = "seed";
            seeds.add(c);
        }
        logger = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "V1Guidance-log");
            t.setDaemon(true);
            return t;
        });
        logger.scheduleAtFixedRate(this::logStats, 1, 1, TimeUnit.SECONDS);
        this.log.println("{\"event\":\"start\",\"target\":\"V1\",\"label\":\"" + label + "\",\"maxInput\":" + maxInput
                + ",\"seed\":" + seed + ",\"agentInstrumented\":" + V1Counters.instrumentedMethods
                + ",\"corpus\":\"" + corpusDir.getPath().replace("\\", "/") + "\"}");
    }

    private static Map<String, Double> zeroSignals() {
        Map<String, Double> m = new LinkedHashMap<>();
        m.put("retainedBytes", 0.0);
        m.put("decodedBytes", 0.0);
        m.put("bwtBytes", 0.0);
        return m;
    }

    // ------------------------------------------------------------------ Guidance

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        if (seeds.isEmpty() && corpus.isEmpty()) {
            Candidate s = new Candidate();
            s.genome = randomGenome();
            s.ops = "seed";
            seeds.add(s);
        }
        Candidate c = seeds.isEmpty() ? mutate() : seeds.poll();
        if (c.data == null) {
            c.data = c.genome != null ? encode(c.genome) : new byte[] {'B', 'Z', 'h'};
        }
        if (c.data.length > maxInput) {
            c.data = Arrays.copyOf(c.data, maxInput);
        }
        current = c;
        V1Counters.reset(); // reset after encoding, right before the execution
        return new ByteArrayInputStream(c.data);
    }

    @Override
    public boolean hasInput() {
        return maxDurationMs <= 0 || System.currentTimeMillis() - startMs < maxDurationMs;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        long retained = V1Counters.retainedBytes;
        long decoded = V1Counters.decodedBytes;
        long bwt = V1Counters.bwtBytes;
        long valid = V1Counters.validBlocks;
        long reached = V1Counters.blocksReached;
        Map<String, Double> m = new LinkedHashMap<>();
        m.put("retainedBytes", (double) retained);
        m.put("decodedBytes", (double) decoded);
        m.put("bwtBytes", (double) bwt);
        lastSignals = m;
        execs++;
        lastRetained = retained;
        Candidate c = current;
        if (c == null) {
            return;
        }
        int len = c.data.length;
        lastLen = len;
        if (result == Result.FAILURE) {
            failures++;
        } else if (result == Result.TIMEOUT) {
            timeouts++;
        } else if (result == Result.INVALID) {
            invalids++;
        }

        // ---- retention (signals measured inside the sink; length growth as the flat-signal fallback)
        String reason = null;
        double ratio = len > 0 ? (double) retained / len : 0;
        long pairKey = (Math.min(reached, 1_000_000L) << 21) | Math.min(valid, 1_000_000L);
        if (retained > bestRetained) {
            reason = "retainedBytes";
        } else if (valid > bestValid) {
            reason = "validBlocks";
        } else if (retained > 0 && ratio > bestRatio * 1.01) {
            reason = "retainedPerInputByte";
        } else if (decoded > bestDecoded) {
            reason = "decodedBytes";
        } else if (bwt > bestBwt) {
            reason = "bwtBytes";
        } else if (!statePairs.contains(pairKey)) {
            reason = "newBlockStatePair";
        } else if (len > maxLen) {
            reason = "inputGrowth";
        }
        if (len > maxLen) {
            maxLen = len;
        }
        if (reason != null && result != Result.FAILURE && result != Result.TIMEOUT) {
            bestRetained = Math.max(bestRetained, retained);
            bestValid = Math.max(bestValid, valid);
            bestDecoded = Math.max(bestDecoded, decoded);
            bestBwt = Math.max(bestBwt, bwt);
            if (retained > 0) {
                bestRatio = Math.max(bestRatio, ratio);
            }
            statePairs.add(pairKey);
            Entry e = new Entry(nextId++, c.data, c.genome, retained, decoded, bwt, valid, reached);
            corpus.add(e);
            evictIfNeeded();
            corpusSize = corpus.size();
            save(e, c, result, reason);
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        return e -> { };
    }

    @Override
    public Map<String, Double> lastSignals() {
        return lastSignals;
    }

    // ------------------------------------------------------------------ corpus

    private void evictIfNeeded() {
        if (corpus.size() <= 4096) {
            return;
        }
        int worst = -1;
        double ws = Double.MAX_VALUE;
        for (int i = 0; i < corpus.size(); i++) {
            double s = corpus.get(i).score();
            if (s < ws) {
                ws = s;
                worst = i;
            }
        }
        if (worst >= 0) {
            corpus.remove(worst);
        }
    }

    private Entry pickParent() {
        int n = corpus.size();
        double p = rnd.nextDouble();
        if (p < 0.55) { // tournament on the measured-signal score
            Entry best = corpus.get(rnd.nextInt(n));
            for (int i = 0; i < 3; i++) {
                Entry o = corpus.get(rnd.nextInt(n));
                if (o.score() > best.score()) {
                    best = o;
                }
            }
            return best;
        } else if (p < 0.75) {
            return corpus.get(n - 1 - rnd.nextInt(Math.min(n, 4)));
        }
        return corpus.get(rnd.nextInt(n));
    }

    private void save(Entry e, Candidate c, Result result, String reason) {
        String base = String.format("id_%06d", e.id);
        try (OutputStream os = new FileOutputStream(new File(corpusDir, base + ".bin"))) {
            os.write(e.data);
        } catch (IOException ignored) {
            // corpus saving is best-effort
        }
        StringBuilder sb = new StringBuilder();
        sb.append("{\"target\":\"V1\",\"label\":\"").append(label).append("\",\"id\":").append(e.id)
          .append(",\"file\":\"").append(base).append(".bin\",\"length\":").append(e.data.length)
          .append(",\"parent\":").append(c.parent)
          .append(",\"ops\":\"").append(c.ops).append("\",\"reason\":\"").append(reason)
          .append("\",\"result\":\"").append(result)
          .append("\",\"signals\":{\"retainedBytes\":").append(e.retained)
          .append(",\"decodedBytes\":").append(e.decoded).append(",\"bwtBytes\":").append(e.bwt)
          .append(",\"validBlocks\":").append(e.valid).append(",\"blocksReached\":").append(e.reached).append('}');
        if (e.genome != null) {
            sb.append(",\"genome\":{\"level\":").append(e.genome.level).append(",\"records\":")
              .append(e.genome.recs.size()).append(",\"plainBytes\":").append(e.genome.plainBytes()).append('}');
        }
        sb.append(",\"timeMs\":").append(System.currentTimeMillis() - startMs).append("}\n");
        try (OutputStream os = new FileOutputStream(new File(corpusDir, base + ".json"))) {
            os.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // best-effort
        }
    }

    private void logStats() {
        log.println("{\"t\":" + (System.currentTimeMillis() - startMs) + ",\"target\":\"V1\",\"execs\":" + execs
                + ",\"corpus\":" + corpusSize + ",\"bestRetainedBytes\":" + bestRetained
                + ",\"bestValidBlocks\":" + bestValid + ",\"bestDecodedBytes\":" + bestDecoded
                + ",\"bestBwtBytes\":" + bestBwt + ",\"lastRetainedBytes\":" + lastRetained
                + ",\"lastLen\":" + lastLen + ",\"maxLen\":" + maxLen + ",\"failures\":" + failures
                + ",\"timeouts\":" + timeouts + ",\"invalid\":" + invalids + ",\"encodeMs\":" + encodeMsTotal
                + ",\"agentInstrumented\":" + V1Counters.instrumentedMethods + "}");
    }

    // ------------------------------------------------------------------ mutation

    private Genome randomGenome() {
        Genome g = new Genome();
        g.level = 1 + rnd.nextInt(9);
        int n = 2 + rnd.nextInt(24);
        int alphabet = 1 + rnd.nextInt(8);
        int baseByte = rnd.nextInt(256);
        for (int i = 0; i < n; i++) {
            g.recs.add(new long[] {(baseByte + rnd.nextInt(alphabet)) & 0xff, 1 + rnd.nextInt(16)});
        }
        return g;
    }

    private Candidate mutate() {
        Entry parent = pickParent();
        Candidate c = new Candidate();
        c.parent = parent.id;
        boolean growthPhase = maxLen < Math.min(maxInput, 1024);
        double rawP = growthPhase ? 0.45 : 0.3;
        if (parent.genome != null && rnd.nextDouble() >= rawP) {
            Genome g = parent.genome.copy();
            StringBuilder ops = new StringBuilder("G");
            int k = 1 + rnd.nextInt(3);
            for (int i = 0; i < k; i++) {
                ops.append(':').append(mutateGenome(g));
            }
            c.genome = g;
            c.ops = ops.toString();
            c.data = encode(g);
        } else {
            byte[] d = parent.data.clone();
            StringBuilder ops = new StringBuilder("R");
            int k = 1 + rnd.nextInt(3);
            for (int i = 0; i < k; i++) {
                String[] op = new String[1];
                d = mutateRaw(d, op, growthPhase);
                ops.append(':').append(op[0]);
            }
            c.data = d;
            c.ops = ops.toString();
        }
        return c;
    }

    private long randomLen() {
        switch (rnd.nextInt(4)) {
            case 0: return 1 + rnd.nextInt(8);
            case 1: return 1 + rnd.nextInt(300);
            case 2: return 1 + rnd.nextInt(1 << 16);
            default: return 1L << rnd.nextInt(27);
        }
    }

    private String mutateGenome(Genome g) {
        List<long[]> r = g.recs;
        if (r.isEmpty()) {
            r.add(new long[] {rnd.nextInt(256), randomLen()});
            return "insert";
        }
        int i = rnd.nextInt(r.size());
        switch (rnd.nextInt(11)) {
            case 0:
                r.get(i)[0] = rnd.nextInt(256);
                return "byte";
            case 1: {
                long[] x = r.get(i);
                long l = x[1];
                switch (rnd.nextInt(5)) {
                    case 0: l += 1 + rnd.nextInt(8); break;
                    case 1: l -= 1 + rnd.nextInt(8); break;
                    case 2: l *= 2; break;
                    case 3: l /= 2; break;
                    default: l = randomLen(); break;
                }
                x[1] = Math.max(1, Math.min(MAX_RUN, l));
                return "len";
            }
            case 2:
                if (r.size() < MAX_RECORDS) {
                    r.add(rnd.nextInt(r.size() + 1), new long[] {rnd.nextInt(256), randomLen()});
                }
                return "insert";
            case 3:
                if (r.size() > 1) {
                    r.remove(i);
                }
                return "delete";
            case 4: {
                int j = rnd.nextInt(r.size());
                long[] t = r.get(i);
                r.set(i, r.get(j));
                r.set(j, t);
                return "swap";
            }
            case 5: { // repetition of a record slice k times
                int len = 1 + rnd.nextInt(Math.min(16, r.size() - i));
                int room = (MAX_RECORDS - r.size()) / len;
                if (room < 1) {
                    return "repeat0";
                }
                int k = 1 + rnd.nextInt(Math.min(room, 1 << rnd.nextInt(10)));
                List<long[]> slice = new ArrayList<>();
                for (int s = i; s < i + len; s++) {
                    slice.add(r.get(s));
                }
                List<long[]> add = new ArrayList<>();
                for (int q = 0; q < k; q++) {
                    for (long[] x : slice) {
                        add.add(new long[] {x[0], x[1]});
                    }
                }
                r.addAll(i + len, add);
                return "repeat" + k;
            }
            case 6: { // double the whole record list
                if (r.size() * 2 <= MAX_RECORDS) {
                    List<long[]> add = new ArrayList<>();
                    for (long[] x : r) {
                        add.add(new long[] {x[0], x[1]});
                    }
                    r.addAll(add);
                }
                return "double";
            }
            case 7: { // multiply every run length
                int m = 1 << (1 + rnd.nextInt(4));
                for (long[] x : r) {
                    x[1] = Math.max(1, Math.min(MAX_RUN, x[1] * m));
                }
                return "mul" + m;
            }
            case 8:
                g.level = 1 + rnd.nextInt(9);
                return "level";
            case 9: { // splice with another genome
                Entry o = corpus.get(rnd.nextInt(corpus.size()));
                if (o.genome != null && !o.genome.recs.isEmpty()) {
                    int from = rnd.nextInt(o.genome.recs.size());
                    int cut = rnd.nextInt(r.size() + 1);
                    while (r.size() > cut) {
                        r.remove(r.size() - 1);
                    }
                    for (int s = from; s < o.genome.recs.size() && r.size() < MAX_RECORDS; s++) {
                        long[] x = o.genome.recs.get(s);
                        r.add(new long[] {x[0], x[1]});
                    }
                    if (r.isEmpty()) {
                        r.add(new long[] {rnd.nextInt(256), randomLen()});
                    }
                }
                return "splice";
            }
            default: { // merge neighbouring records into one run
                if (i + 1 < r.size()) {
                    long[] a = r.get(i);
                    long[] b = r.remove(i + 1);
                    a[1] = Math.min(MAX_RUN, a[1] + b[1]);
                }
                return "merge";
            }
        }
    }

    private byte[] mutateRaw(byte[] d, String[] op, boolean growthPhase) {
        int n = d.length;
        if (n == 0) {
            op[0] = "dictInsert";
            return Arrays.copyOf(DICT[0], Math.min(maxInput, DICT[0].length));
        }
        int choice = rnd.nextInt(growthPhase ? 12 : 10);
        if (choice >= 10) {
            choice = rnd.nextBoolean() ? 4 : 5; // favour repetition/doubling while inputs are still short
        }
        byte[] out;
        switch (choice) {
            case 0: {
                int p = rnd.nextInt(n);
                d[p] ^= (byte) (1 << rnd.nextInt(8));
                op[0] = "bitflip";
                out = d;
                break;
            }
            case 1:
                d[rnd.nextInt(n)] = (byte) rnd.nextInt(256);
                op[0] = "setbyte";
                out = d;
                break;
            case 2: {
                int p = rnd.nextInt(n + 1);
                int k = 1 + rnd.nextInt(8);
                byte[] ins = new byte[k];
                rnd.nextBytes(ins);
                out = insert(d, p, ins);
                op[0] = "insert";
                break;
            }
            case 3: {
                if (n < 2) {
                    op[0] = "delete0";
                    out = d;
                    break;
                }
                int p = rnd.nextInt(n);
                int k = 1 + rnd.nextInt(Math.min(16, n - p));
                out = new byte[n - k];
                System.arraycopy(d, 0, out, 0, p);
                System.arraycopy(d, p + k, out, p, n - p - k);
                op[0] = "delete";
                break;
            }
            case 4: { // repeat a chunk k times in place
                int p = rnd.nextInt(n);
                int len = 1 + rnd.nextInt(Math.min(n - p, 1 + rnd.nextInt(256)));
                int room = (maxInput - n) / len;
                if (room < 1) {
                    op[0] = "repeat0";
                    out = d;
                    break;
                }
                int k = 1 + rnd.nextInt(Math.min(room, 1 << rnd.nextInt(14)));
                byte[] rep = new byte[len * k];
                for (int q = 0; q < k; q++) {
                    System.arraycopy(d, p, rep, q * len, len);
                }
                out = insert(d, p + len, rep);
                op[0] = "repeat" + k;
                break;
            }
            case 5: { // double the whole input
                out = new byte[Math.min(maxInput, n * 2)];
                for (int q = 0; q < out.length; q++) {
                    out[q] = d[q % n];
                }
                op[0] = "double";
                break;
            }
            case 6: {
                byte[] t = DICT[rnd.nextInt(DICT.length)];
                out = insert(d, rnd.nextInt(n + 1), t);
                op[0] = "dictInsert";
                break;
            }
            case 7: {
                byte[] t = DICT[rnd.nextInt(DICT.length)];
                int p = rnd.nextInt(n);
                for (int q = 0; q < t.length && p + q < n; q++) {
                    d[p + q] = t[q];
                }
                op[0] = "dictOverwrite";
                out = d;
                break;
            }
            case 8: {
                Entry o = corpus.get(rnd.nextInt(corpus.size()));
                int cut = rnd.nextInt(n + 1);
                int from = o.data.length > 0 ? rnd.nextInt(o.data.length) : 0;
                out = new byte[cut + o.data.length - from];
                System.arraycopy(d, 0, out, 0, cut);
                System.arraycopy(o.data, from, out, cut, o.data.length - from);
                op[0] = "splice";
                break;
            }
            default: {
                int p = rnd.nextInt(n);
                d[p] = (byte) (d[p] + (rnd.nextBoolean() ? 1 : -1) * (1 + rnd.nextInt(16)));
                op[0] = "arith";
                out = d;
                break;
            }
        }
        if (out.length > maxInput) {
            out = Arrays.copyOf(out, maxInput);
        }
        return out;
    }

    private static byte[] insert(byte[] d, int p, byte[] ins) {
        byte[] out = new byte[d.length + ins.length];
        System.arraycopy(d, 0, out, 0, p);
        System.arraycopy(ins, 0, out, p, ins.length);
        System.arraycopy(d, p, out, p + ins.length, d.length - p);
        return out;
    }

    // ------------------------------------------------------------------ encoder ([R45c])

    /**
     * Streams the genome's plaintext through Netty's own Bzip2Encoder (CRCs and Huffman tables computed by the
     * library). Stops once the compressed output reaches the input size limit or the encode time budget.
     */
    private byte[] encode(Genome g) {
        long t0 = System.currentTimeMillis();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        EmbeddedChannel ch = new EmbeddedChannel(new Bzip2Encoder(Math.max(1, Math.min(9, g.level))));
        try {
            int pos = 0;
            outer:
            for (long[] r : g.recs) {
                long rem = r[1];
                byte b = (byte) r[0];
                while (rem > 0) {
                    int k = (int) Math.min(rem, chunk.length - pos);
                    Arrays.fill(chunk, pos, pos + k, b);
                    pos += k;
                    rem -= k;
                    if (pos == chunk.length) {
                        ch.writeOutbound(Unpooled.wrappedBuffer(chunk, 0, pos));
                        pos = 0;
                        drain(ch, bos);
                        if (bos.size() >= maxInput || System.currentTimeMillis() - t0 > encodeBudgetMs) {
                            break outer;
                        }
                    }
                }
            }
            if (pos > 0) {
                ch.writeOutbound(Unpooled.wrappedBuffer(chunk, 0, pos));
            }
            ch.finish();
            drain(ch, bos);
        } catch (Throwable t) {
            // fall back to whatever was produced
        } finally {
            ch.finishAndReleaseAll();
            encodeMsTotal += System.currentTimeMillis() - t0;
        }
        byte[] out = bos.toByteArray();
        if (out.length == 0) {
            out = new byte[] {'B', 'Z', 'h'};
        }
        return out.length > maxInput ? Arrays.copyOf(out, maxInput) : out;
    }

    private static void drain(EmbeddedChannel ch, ByteArrayOutputStream bos) {
        for (;;) {
            Object o = ch.readOutbound();
            if (o == null) {
                return;
            }
            ByteBuf b = (ByteBuf) o;
            try {
                byte[] tmp = new byte[b.readableBytes()];
                b.readBytes(tmp);
                bos.write(tmp, 0, tmp.length);
            } finally {
                b.release();
            }
        }
    }
}
