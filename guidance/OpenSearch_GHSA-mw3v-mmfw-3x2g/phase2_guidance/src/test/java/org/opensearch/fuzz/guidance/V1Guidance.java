package org.opensearch.fuzz.guidance;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
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

import dosguide.validate.SignalSource;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import org.opensearch.fuzz.agent.V1Counters;

/**
 * Guidance for V1 only: recursion depth of Lucene's classic QueryParser
 * (Clause -> Query -> Clause per nesting level), measured beneath
 * QueryStringQueryParser#parse when the target runs through
 * QueryParserFuzzTest#fuzzQueryStringQueryBuilderToQuery(InputStream).
 *
 * Input model: raw bytes. The harness decodes them as UTF-8.
 * Signals (agent hooks in {@link V1Counters}, reset in getInput(), read in handleResult()):
 *   maxClauseDepth : peak number of simultaneously active QueryParser#Clause frames
 *   parserVisits   : number of QueryParser#Clause and #Query invocations
 * This Guidance never decides that an execution failed and writes no failure files. It only
 * keeps a corpus, which it saves with metadata.
 */
public class V1Guidance implements Guidance, SignalSource {

    public static final String TARGET_ID = "V1";

    /**
     * Single syntactic tokens of the classic QueryParser grammar (operators, delimiters, keywords,
     * escape characters) and field names from the harness mapping. Each entry is one token; none of
     * them is an assembled input.
     */
    private static final String[] DICTIONARY = {
        "(", ")", "+", "-", "!", "AND", "OR", "NOT", "&&", "||", ":", "^", "~", "\"", "*", "?",
        "[", "]", "{", "}", "TO", "/", "\\", " ", "\t", "\n",
        "f1", "f2", "f3", "f3_alias", "f4", "f_multi", "f_multi.raw", "f_object.sub1", "f_nested.nest1",
        "f_int", "f_long", "f_date", "f_bool", "f_ip", "_exists_", "*:"
    };
    private static final byte[][] DICT_BYTES;
    static {
        DICT_BYTES = new byte[DICTIONARY.length][];
        for (int i = 0; i < DICTIONARY.length; i++) {
            DICT_BYTES[i] = DICTIONARY[i].getBytes(StandardCharsets.UTF_8);
        }
    }

    /** Small, benign seeds (no nesting beyond one group). */
    private static final String[] SEEDS = {
        "a", "f1:a", "a AND b", "(a)", "+a -b", "\"a b\"", "f2:a*", "a^2", "a~1", "f_int:[1 TO 2]"
    };

    private static final int MAX_CORPUS = 4096;

    private static final class Entry {
        final int id;
        final byte[] data;
        final int depth;
        final long visits;
        Entry(int id, byte[] data, int depth, long visits) {
            this.id = id;
            this.data = data;
            this.depth = depth;
            this.visits = visits;
        }
        /** Measured depth per input byte (one '(' byte should give one Clause frame). */
        double density() {
            return data.length == 0 ? 0.0 : (double) depth / data.length;
        }
        double priority() {
            return depth * (1.0 + density());
        }
    }

    private final int maxInputSize;
    private final long maxDurationMs;
    private final long startMs;
    private final File outDir;
    private final File corpusDir;
    private final File logFile;
    private final PrintStream log;
    private final Random rnd;

    private final List<Entry> corpus = new ArrayList<>();
    private final Deque<byte[]> seedQueue = new ArrayDeque<>();
    private final Set<Integer> seenDepths = new HashSet<>();

    private byte[] current = new byte[0];
    private Entry currentParent;
    private String currentOp = "seed";
    private Map<String, Double> lastSignals;

    private volatile long executions;
    private volatile long keptCount;
    private volatile int bestDepth;
    private volatile long bestVisits;
    private volatile int longestKept;
    private volatile int longestGenerated;
    private volatile long resultSuccess, resultInvalid, resultFailure, resultTimeout;
    private int nextId;

    private final ScheduledExecutorService logger;

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Math.max(1, Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 131072));
        this.maxDurationMs = maxDurationMs;
        this.startMs = System.currentTimeMillis();
        this.outDir = outputDir;
        this.corpusDir = new File(outputDir, "corpus");
        File logDir = new File(outputDir, "logs");
        this.corpusDir.mkdirs();
        logDir.mkdirs();
        this.logFile = new File(logDir, "V1-stats.jsonl");
        this.log = log == null ? System.out : log;
        long seed = Long.getLong("v1.seed", System.nanoTime());
        this.rnd = new Random(seed);
        for (String s : SEEDS) {
            seedQueue.add(cap(s.getBytes(StandardCharsets.UTF_8)));
        }
        Map<String, Double> zero = new LinkedHashMap<>();
        zero.put("maxClauseDepth", 0.0);
        zero.put("parserVisits", 0.0);
        this.lastSignals = Collections.unmodifiableMap(zero);

        this.logger = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "V1Guidance-logger");
            t.setDaemon(true);
            return t;
        });
        this.logger.scheduleAtFixedRate(this::logStats, 1, 1, TimeUnit.SECONDS);
        this.log.println("{\"target\":\"V1\",\"event\":\"start\",\"maxInputSize\":" + maxInputSize
            + ",\"maxDurationMs\":" + maxDurationMs + ",\"rngSeed\":" + seed
            + ",\"outDir\":\"" + esc(outputDir.getPath()) + "\"}");
    }

    // ------------------------------------------------------------------ Guidance API

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        if (!seedQueue.isEmpty()) {
            current = seedQueue.poll();
            currentParent = null;
            currentOp = "seed";
        } else if (corpus.isEmpty()) {
            current = cap(DICT_BYTES[rnd.nextInt(DICT_BYTES.length)].clone());
            currentParent = null;
            currentOp = "dict-fresh";
        } else {
            currentParent = pickParent();
            StringBuilder ops = new StringBuilder();
            byte[] d = currentParent.data;
            int n = 1 + rnd.nextInt(3);
            for (int i = 0; i < n; i++) {
                d = mutate(d, currentParent, ops);
            }
            current = cap(d);
            currentOp = ops.toString();
        }
        if (current.length > longestGenerated) {
            longestGenerated = current.length;
        }
        V1Counters.reset();
        return new ByteArrayInputStream(current);
    }

    @Override
    public boolean hasInput() {
        return maxDurationMs <= 0 || System.currentTimeMillis() - startMs < maxDurationMs;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        int depth = V1Counters.maxClauseDepth();
        long visits = V1Counters.parserVisits();
        Map<String, Double> m = new LinkedHashMap<>();
        m.put("maxClauseDepth", (double) depth);
        m.put("parserVisits", (double) visits);
        lastSignals = Collections.unmodifiableMap(m);
        executions++;
        switch (result) {
            case SUCCESS: resultSuccess++; break;
            case INVALID: resultInvalid++; break;
            case FAILURE: resultFailure++; break;
            case TIMEOUT: resultTimeout++; break;
            default: break;
        }

        int parentDepth = currentParent == null ? 0 : currentParent.depth;
        String reason = null;
        if (currentParent == null) {
            reason = "seed";
        } else if (depth > bestDepth) {
            reason = "depth";
        } else if (visits > bestVisits && depth >= parentDepth) {
            reason = "visits";
        } else if (current.length > longestKept && depth >= parentDepth) {
            reason = "growth";
        } else if (!seenDepths.contains(depth)) {
            reason = "new-depth-value";
        }
        if (reason != null) {
            keep(current, depth, visits, reason, result, error);
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // No JQF tracing is used; measurement comes from the custom V1MeasureAgent.
        return e -> { };
    }

    @Override
    public Map<String, Double> lastSignals() {
        return lastSignals;
    }

    // ------------------------------------------------------------------ retention

    private void keep(byte[] data, int depth, long visits, String reason, Result result, Throwable error) {
        Entry e = new Entry(nextId++, data, depth, visits);
        corpus.add(e);
        keptCount++;
        seenDepths.add(depth);
        if (depth > bestDepth) {
            bestDepth = depth;
        }
        if (visits > bestVisits) {
            bestVisits = visits;
        }
        if (data.length > longestKept) {
            longestKept = data.length;
        }
        if (corpus.size() > MAX_CORPUS) {
            evict();
        }
        save(e, reason, result, error);
    }

    private void evict() {
        int worst = -1;
        double worstP = Double.MAX_VALUE;
        for (int i = 0; i < corpus.size(); i++) {
            Entry c = corpus.get(i);
            if (c.depth == bestDepth || c.data.length == longestKept) {
                continue;
            }
            double p = c.priority();
            if (p < worstP) {
                worstP = p;
                worst = i;
            }
        }
        if (worst >= 0) {
            corpus.remove(worst);
        }
    }

    private void save(Entry e, String reason, Result result, Throwable error) {
        String base = String.format("id_%06d", e.id);
        try {
            Files.write(new File(corpusDir, base + ".bin").toPath(), e.data);
            String meta = "{\"target\":\"V1\",\"test_class\":\"org.opensearch.fuzz.tests.QueryParserFuzzTest\""
                + ",\"method\":\"fuzzQueryStringQueryBuilderToQuery\""
                + ",\"id\":" + e.id
                + ",\"file\":\"" + base + ".bin\""
                + ",\"length\":" + e.data.length
                + ",\"maxClauseDepth\":" + e.depth
                + ",\"parserVisits\":" + e.visits
                + ",\"reason\":\"" + reason + "\""
                + ",\"jqfResult\":\"" + result + "\""
                + ",\"throwable\":" + (error == null ? "null" : "\"" + esc(error.getClass().getName()) + "\"")
                + ",\"parent\":" + (currentParent == null ? -1 : currentParent.id)
                + ",\"ops\":\"" + esc(currentOp) + "\""
                + ",\"elapsedMs\":" + (System.currentTimeMillis() - startMs)
                + "}";
            Files.write(new File(corpusDir, base + ".json").toPath(), meta.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            log.println("{\"target\":\"V1\",\"event\":\"save-error\",\"msg\":\"" + esc(ex.toString()) + "\"}");
        }
    }

    // ------------------------------------------------------------------ prioritization

    private Entry pickParent() {
        double r = rnd.nextDouble();
        if (r < 0.55) {
            // Tournament on measured depth, weighted by measured depth per byte (method-specific rule).
            Entry best = null;
            for (int i = 0; i < 4; i++) {
                Entry c = corpus.get(rnd.nextInt(corpus.size()));
                if (best == null || c.priority() > best.priority()) {
                    best = c;
                }
            }
            return best;
        } else if (r < 0.75) {
            // Length frontier: keeps the search growing while the depth is flat.
            Entry best = corpus.get(0);
            for (Entry c : corpus) {
                if (c.data.length > best.data.length || (c.data.length == best.data.length && c.depth > best.depth)) {
                    best = c;
                }
            }
            return best;
        } else if (r < 0.85) {
            Entry best = corpus.get(0);
            for (Entry c : corpus) {
                if (c.depth > best.depth) {
                    best = c;
                }
            }
            return best;
        }
        return corpus.get(rnd.nextInt(corpus.size()));
    }

    // ------------------------------------------------------------------ mutation

    private byte[] mutate(byte[] d, Entry parent, StringBuilder ops) {
        // Dense parents (high measured depth per byte) get repetition more often.
        double repP = parent.density() > 0.2 ? 0.5 : 0.25;
        double r = rnd.nextDouble();
        if (r < repP) {
            ops.append("repeat;");
            return repeatChunk(d);
        }
        r = rnd.nextDouble();
        if (r < 0.10) {
            ops.append("double;");
            return doubleWhole(d);
        } else if (r < 0.30) {
            ops.append("dict-insert;");
            return insert(d, d.length == 0 ? 0 : rnd.nextInt(d.length + 1), DICT_BYTES[rnd.nextInt(DICT_BYTES.length)]);
        } else if (r < 0.40) {
            ops.append("dict-overwrite;");
            return overwrite(d, DICT_BYTES[rnd.nextInt(DICT_BYTES.length)]);
        } else if (r < 0.52) {
            ops.append("flip;");
            if (d.length == 0) {
                return insert(d, 0, new byte[] {randomByte()});
            }
            byte[] c = d.clone();
            int p = rnd.nextInt(c.length);
            c[p] = (byte) (c[p] ^ (1 << rnd.nextInt(8)));
            return c;
        } else if (r < 0.64) {
            ops.append("set-byte;");
            if (d.length == 0) {
                return insert(d, 0, new byte[] {randomByte()});
            }
            byte[] c = d.clone();
            c[rnd.nextInt(c.length)] = randomByte();
            return c;
        } else if (r < 0.76) {
            ops.append("insert-byte;");
            return insert(d, d.length == 0 ? 0 : rnd.nextInt(d.length + 1), new byte[] {randomByte()});
        } else if (r < 0.88) {
            ops.append("delete;");
            if (d.length <= 1) {
                return d;
            }
            int s = rnd.nextInt(d.length);
            int l = 1 + rnd.nextInt(Math.min(d.length - s, 1 + rnd.nextInt(16)));
            byte[] c = new byte[d.length - l];
            System.arraycopy(d, 0, c, 0, s);
            System.arraycopy(d, s + l, c, s, d.length - s - l);
            return c;
        } else {
            ops.append("splice;");
            Entry o = corpus.get(rnd.nextInt(corpus.size()));
            int a = d.length == 0 ? 0 : rnd.nextInt(d.length + 1);
            int b = o.data.length == 0 ? 0 : rnd.nextInt(o.data.length + 1);
            byte[] c = new byte[a + (o.data.length - b)];
            System.arraycopy(d, 0, c, 0, a);
            System.arraycopy(o.data, b, c, a, o.data.length - b);
            return cap(c);
        }
    }

    /**
     * Repetition operator: copy a chunk (random, or starting at a grammar boundary byte) and repeat it
     * k times in place. k is either 1 (doubling the region), the number that fills the size limit,
     * or log-uniform in between.
     */
    private byte[] repeatChunk(byte[] d) {
        if (d.length == 0) {
            return DICT_BYTES[rnd.nextInt(DICT_BYTES.length)].clone();
        }
        int start;
        if (rnd.nextBoolean()) {
            List<Integer> boundaries = new ArrayList<>();
            for (int i = 0; i < d.length; i++) {
                byte b = d[i];
                if (b == '(' || b == ')' || b == ' ' || b == ':' || b == '"' || b == '[' || b == '{'
                    || b == '+' || b == '-' || b == '!') {
                    boundaries.add(i);
                }
            }
            start = boundaries.isEmpty() ? rnd.nextInt(d.length) : boundaries.get(rnd.nextInt(boundaries.size()));
        } else {
            start = rnd.nextInt(d.length);
        }
        int maxLen = Math.min(d.length - start, 1 + rnd.nextInt(64));
        int l = 1 + rnd.nextInt(Math.max(1, maxLen));
        l = Math.min(l, d.length - start);
        int room = maxInputSize - d.length;
        if (room < l) {
            return d;
        }
        int maxK = room / l;
        int k;
        double r = rnd.nextDouble();
        if (r < 0.25) {
            k = maxK;
        } else if (r < 0.55) {
            k = 1;
        } else {
            double logMax = Math.log(maxK + 1.0);
            k = Math.max(1, Math.min(maxK, (int) Math.exp(rnd.nextDouble() * logMax)));
        }
        byte[] out = new byte[d.length + k * l];
        int p = 0;
        System.arraycopy(d, 0, out, p, start + l);
        p += start + l;
        for (int i = 0; i < k; i++) {
            System.arraycopy(d, start, out, p, l);
            p += l;
        }
        System.arraycopy(d, start + l, out, p, d.length - start - l);
        return out;
    }

    private byte[] doubleWhole(byte[] d) {
        if (d.length == 0) {
            return d;
        }
        int n = Math.min(maxInputSize, d.length * 2);
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = d[i % d.length];
        }
        return out;
    }

    private byte[] insert(byte[] d, int pos, byte[] ins) {
        byte[] c = new byte[d.length + ins.length];
        System.arraycopy(d, 0, c, 0, pos);
        System.arraycopy(ins, 0, c, pos, ins.length);
        System.arraycopy(d, pos, c, pos + ins.length, d.length - pos);
        return cap(c);
    }

    private byte[] overwrite(byte[] d, byte[] tok) {
        if (d.length == 0) {
            return cap(tok.clone());
        }
        byte[] c = d.clone();
        int pos = rnd.nextInt(d.length);
        for (int i = 0; i < tok.length && pos + i < c.length; i++) {
            c[pos + i] = tok[i];
        }
        return c;
    }

    private byte randomByte() {
        if (rnd.nextInt(8) == 0) {
            return (byte) rnd.nextInt(256);
        }
        return (byte) (0x20 + rnd.nextInt(0x5f));
    }

    private byte[] cap(byte[] d) {
        return d.length <= maxInputSize ? d : Arrays.copyOf(d, maxInputSize);
    }

    // ------------------------------------------------------------------ logging

    private void logStats() {
        String line = "{\"target\":\"V1\",\"t_ms\":" + (System.currentTimeMillis() - startMs)
            + ",\"execs\":" + executions
            + ",\"corpus\":" + keptCount
            + ",\"bestMaxClauseDepth\":" + bestDepth
            + ",\"bestParserVisits\":" + bestVisits
            + ",\"longestKept\":" + longestKept
            + ",\"longestGenerated\":" + longestGenerated
            + ",\"results\":{\"SUCCESS\":" + resultSuccess + ",\"INVALID\":" + resultInvalid
            + ",\"FAILURE\":" + resultFailure + ",\"TIMEOUT\":" + resultTimeout + "}}";
        log.println(line);
        try (FileOutputStream fos = new FileOutputStream(logFile, true)) {
            fos.write((line + "\n").getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // logging must never disturb fuzzing
        }
    }

    public File getOutputDirectory() {
        return outDir;
    }

    private static String esc(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') {
                b.append('\\').append(c);
            } else if (c < 0x20) {
                b.append(String.format("\\u%04x", (int) c));
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }
}
