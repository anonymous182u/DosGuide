package dosguide.guidance;

import dosguide.agent.DoSCounters;
import dosguide.validate.SignalSource;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * V1 — HashDoS on QuicheQuicCodec.connectionIdToChannel (CWE-407), fuzz method
 * QuicCodecFuzzTest#fuzzQuicServerCodecChannelRead.
 *
 * <p>Signals (measured by the custom agent, read in handleResult):</p>
 * <ul>
 *   <li>v1TreeVisits — HashMap$TreeNode#find nodes visited while QuicheQuicCodec#getChannel runs</li>
 *   <li>v1MaxPerLookup — largest number of such visits in one getChannel call (V1-specific priority)</li>
 *   <li>v1KeyEquals — ByteBuffer#equals calls inside getChannel (list bins before treeification)</li>
 *   <li>channelsAdded — QuicheQuicCodec#addChannel calls (attack-path progress while flat)</li>
 * </ul>
 * <p>Method-specific: fresh records prefer 20-byte DCIDs (QuicServerCodecBuilder default localConnIdLength
 * = Quic.MAX_CONN_ID_LEN) and parents are ranked by visits per lookup after total visits.</p>
 */
public final class V1Guidance implements Guidance, SignalSource {

    static final String TARGET = "V1";
    static final int TARGET_BYTES = 413000;
    private static final int CORPUS_CAP = 400;

    private final int maxLen;
    private final int targetBytes;
    private final long deadline;
    private final PrintStream log;
    private final File corpusDir;
    private final File metaDir;
    private final File outDir;
    private final Random rnd;
    private final RecordMutator mut;

    private final List<Entry> corpus = new ArrayList<>();
    private final ArrayDeque<byte[]> seeds = new ArrayDeque<>();
    private final Map<Integer, Integer> levelLongest = new HashMap<>();

    private byte[] current;
    private String currentOp = "";
    private int currentParent = -1;
    private boolean currentIsSeed;
    private long startNs;

    private long bestTreeVisits = -1;
    private long bestMaxPerLookup = -1;
    private long bestKeyEquals = -1;
    private long bestChannels = -1;

    private volatile long execs;
    private volatile long invalid;
    private volatile long failures;
    private volatile int longest;
    private volatile long lastExecMs;
    private volatile Map<String, Double> last = Collections.emptyMap();
    private int nextId;
    private final long startMs = System.currentTimeMillis();
    private final ScheduledExecutorService logger;

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxLen = GuidanceSupport.maxInputSize();
        this.targetBytes = Math.min(TARGET_BYTES, maxLen);
        long dur = GuidanceSupport.resolveDuration(maxDurationMs);
        this.deadline = dur > 0 ? System.currentTimeMillis() + dur : Long.MAX_VALUE;
        this.log = log != null ? log : System.out;
        this.outDir = new File(outputDir, TARGET);
        this.corpusDir = new File(outDir, "corpus");
        this.metaDir = new File(outDir, "meta");
        corpusDir.mkdirs();
        metaDir.mkdirs();
        this.rnd = new Random(Long.getLong("dosguide.seed", System.nanoTime()));
        this.mut = new RecordMutator(rnd, maxLen, targetBytes, new int[] {20}, false);
        for (int i = 0; i < 3; i++) {
            seeds.add(mut.seed());
        }
        this.logger = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "V1Guidance-log");
            t.setDaemon(true);
            return t;
        });
        logger.scheduleAtFixedRate(this::logStats, 1, 1, TimeUnit.SECONDS);
        this.log.println("{\"event\":\"start\",\"target\":\"V1\",\"maxLen\":" + maxLen
                + ",\"targetBytes\":" + targetBytes + ",\"agentActive\":" + DoSCounters.agentActive
                + ",\"transformed\":\"" + GuidanceSupport.esc(DoSCounters.transformedNames) + "\""
                + ",\"out\":\"" + GuidanceSupport.esc(outDir.getPath()) + "\"}");
    }

    private static final class Entry {
        final int id;
        final byte[] data;
        final long treeVisits;
        final long maxPerLookup;

        Entry(int id, byte[] data, long treeVisits, long maxPerLookup) {
            this.id = id;
            this.data = data;
            this.treeVisits = treeVisits;
            this.maxPerLookup = maxPerLookup;
        }
    }

    private static final Comparator<Entry> BY_SCORE = (a, b) -> {
        int c = Long.compare(b.treeVisits, a.treeVisits);
        if (c != 0) {
            return c;
        }
        c = Long.compare(b.maxPerLookup, a.maxPerLookup);
        if (c != 0) {
            return c;
        }
        return Integer.compare(b.data.length, a.data.length);
    };

    // ------------------------------------------------------------------ Guidance

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        currentIsSeed = false;
        currentParent = -1;
        if (!seeds.isEmpty()) {
            current = seeds.poll();
            currentOp = "seed";
            currentIsSeed = true;
        } else if (corpus.isEmpty()) {
            current = mut.seed();
            currentOp = "seed";
            currentIsSeed = true;
        } else {
            Entry longestEntry = longestEntry();
            Entry top = topEntry();
            double r = rnd.nextDouble();
            boolean belowTarget = longestEntry.data.length < targetBytes;
            double denseP = belowTarget ? 0.10 : 0.25;
            if (belowTarget && r < 0.30) {
                // flat-signal frontier (R46): grow the longest input toward targetBytes, structure kept
                current = mut.appendFresh(longestEntry.data, targetBytes);
                currentParent = longestEntry.id;
                currentOp = "growFlat:" + mut.lastOp;
            } else if (top.treeVisits > 0 && r < 0.30 + denseP) {
                // dense frontier: grow the highest-signal input preserving each record's hash class
                current = mut.growDense(top.data);
                currentParent = top.id;
                currentOp = "growDense:" + mut.lastOp;
            } else {
                Entry p = pickParent();
                Entry other = corpus.get(rnd.nextInt(corpus.size()));
                byte[] c = mut.mutate(p.data, other.data, true);
                StringBuilder ops = new StringBuilder(mut.lastOp);
                int extra = rnd.nextInt(3);
                for (int i = 0; i < extra && isSmallOp(mut.lastOp); i++) {
                    c = mut.mutate(c, other.data, true);
                    ops.append('+').append(mut.lastOp);
                }
                current = c;
                currentParent = p.id;
                currentOp = ops.toString();
            }
        }
        current = mut.cap(current);
        if (current.length == 0) {
            current = mut.seed();
        }
        if (current.length >= 4096) {
            // reproduction aid for executions that may be killed by the evaluation's timeout
            GuidanceSupport.writeAtomic(new File(outDir, "current.bin"), current);
            GuidanceSupport.writeText(new File(outDir, "current.json"), "{\"target\":\"V1\",\"test\":"
                    + "\"fuzzQuicServerCodecChannelRead\",\"file\":\"current.bin\",\"length\":" + current.length
                    + ",\"op\":\"" + GuidanceSupport.esc(currentOp) + "\",\"parent\":" + currentParent + "}");
        }
        DoSCounters.reset(Thread.currentThread());
        startNs = System.nanoTime();
        return new ByteArrayInputStream(current);
    }

    private static boolean isSmallOp(String op) {
        return op.startsWith("bitFlip") || op.startsWith("setByte") || op.startsWith("dict")
                || op.startsWith("insertBytes") || op.startsWith("deleteBytes");
    }

    private Entry longestEntry() {
        Entry best = corpus.get(0);
        for (Entry e : corpus) {
            if (e.data.length > best.data.length
                    || (e.data.length == best.data.length && e.treeVisits > best.treeVisits)) {
                best = e;
            }
        }
        return best;
    }

    private Entry topEntry() {
        Entry best = corpus.get(0);
        for (Entry e : corpus) {
            if (BY_SCORE.compare(e, best) < 0) {
                best = e;
            }
        }
        return best;
    }

    private Entry pickParent() {
        List<Entry> sorted = new ArrayList<>(corpus);
        sorted.sort(BY_SCORE);
        double r = rnd.nextDouble();
        int idx = (int) (sorted.size() * r * r * r);
        return sorted.get(Math.min(idx, sorted.size() - 1));
    }

    @Override
    public boolean hasInput() {
        return System.currentTimeMillis() < deadline;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        long tv = DoSCounters.v1TreeVisits;
        long mpl = DoSCounters.v1MaxPerLookup;
        long ke = DoSCounters.v1KeyEquals;
        long ch = DoSCounters.channelsAdded;
        DoSCounters.owner = null;
        lastExecMs = (System.nanoTime() - startNs) / 1_000_000L;

        Map<String, Double> s = new LinkedHashMap<>();
        s.put("v1TreeVisits", (double) tv);
        s.put("v1MaxPerLookup", (double) mpl);
        s.put("v1KeyEquals", (double) ke);
        s.put("channelsAdded", (double) ch);
        last = s;
        execs++;
        if (result == Result.INVALID) {
            invalid++;
        } else if (result == Result.FAILURE || result == Result.TIMEOUT) {
            failures++; // counted for stats only; JQF/the evaluation records failures (R6)
        }

        List<String> reasons = new ArrayList<>(3);
        if (currentIsSeed) {
            reasons.add("seed");
        }
        if (tv > bestTreeVisits) {
            bestTreeVisits = tv;
            reasons.add("treeVisits");
        }
        if (mpl > bestMaxPerLookup) {
            bestMaxPerLookup = mpl;
            reasons.add("maxPerLookup");
        }
        if (ke > bestKeyEquals) {
            bestKeyEquals = ke;
            reasons.add("keyEquals");
        }
        if (ch > bestChannels) {
            bestChannels = ch;
            reasons.add("channelsAdded");
        }
        // flat-signal progress (R46): longer than every kept input at this signal level, toward targetBytes
        int level = 64 - Long.numberOfLeadingZeros(tv);
        int prevLongest = levelLongest.getOrDefault(level, 0);
        if (current.length > prevLongest && prevLongest < targetBytes) {
            reasons.add("growth");
        }
        if (!reasons.isEmpty()) {
            keep(s, reasons, result, level);
        }
    }

    private void keep(Map<String, Double> s, List<String> reasons, Result result, int level) {
        int id = nextId++;
        Entry e = new Entry(id, current, s.get("v1TreeVisits").longValue(), s.get("v1MaxPerLookup").longValue());
        corpus.add(e);
        levelLongest.merge(level, current.length, Math::max);
        if (current.length > longest) {
            longest = current.length;
        }
        String name = String.format("id_%06d", id);
        GuidanceSupport.writeAtomic(new File(corpusDir, name + ".bin"), current);
        GuidanceSupport.writeText(new File(metaDir, name + ".json"), "{\"target\":\"V1\",\"testClass\":"
                + "\"io.netty.incubator.codec.quic.fuzz.QuicCodecFuzzTest\",\"test\":"
                + "\"fuzzQuicServerCodecChannelRead\",\"id\":" + id + ",\"file\":\"../corpus/" + name
                + ".bin\",\"length\":" + current.length + ",\"parent\":" + currentParent + ",\"op\":\""
                + GuidanceSupport.esc(currentOp) + "\",\"reasons\":\"" + String.join("|", reasons)
                + "\",\"result\":\"" + result + "\",\"execMs\":" + lastExecMs + ",\"signals\":"
                + GuidanceSupport.json(s) + ",\"timeMs\":" + (System.currentTimeMillis() - startMs) + "}");
        if (corpus.size() > CORPUS_CAP) {
            evict();
        }
    }

    private void evict() {
        Entry longestE = longestEntry();
        List<Entry> sorted = new ArrayList<>(corpus);
        sorted.sort(BY_SCORE);
        for (int i = sorted.size() - 1; i >= 0; i--) {
            Entry e = sorted.get(i);
            if (e != longestE) {
                corpus.remove(e);
                return;
            }
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        return ev -> { };
    }

    @Override
    public Map<String, Double> lastSignals() {
        return last;
    }

    private void logStats() {
        long t = System.currentTimeMillis() - startMs;
        log.println("{\"t\":" + t + ",\"target\":\"V1\",\"execs\":" + execs + ",\"invalid\":" + invalid
                + ",\"failures\":" + failures + ",\"corpus\":" + corpus.size() + ",\"longest\":" + longest
                + ",\"bestTreeVisits\":" + bestTreeVisits + ",\"bestMaxPerLookup\":" + bestMaxPerLookup
                + ",\"bestKeyEquals\":" + bestKeyEquals + ",\"bestChannels\":" + bestChannels
                + ",\"lastExecMs\":" + lastExecMs + ",\"last\":" + GuidanceSupport.json(last) + "}");
    }
}
