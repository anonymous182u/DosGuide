package v1;

import dosguide.validate.SignalSource;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

/**
 * Cost-Gradient Guidance for V1: unbounded recursion depth in Composer.composeNode.
 *
 * Tracks maxDepth (via V1DepthAgent) and hill-climbs toward deeper recursion.
 * Implements Guidance directly [R3], never extends existing guidances.
 * Never decides failures or writes failure files [R6].
 */
public class V1Guidance implements Guidance, SignalSource {

    // --- Configuration ---
    private final int maxInputSize;
    private final File corpusDir;
    private final long maxDurationMs;
    private final PrintStream log;
    private final Random rng = new Random();

    // --- Dictionary of YAML tokens from Scanner source on the attack path [R45b] ---
    private static final byte[][] DICTIONARY = {
        {(byte) '['}, {(byte) ']'}, {(byte) '{'}, {(byte) '}'},
        {(byte) ','}, {(byte) ':'}, {(byte) '-'}, {(byte) '*'},
        {(byte) '&'}, {(byte) '!'}, {(byte) '\n'}, {(byte) ' '},
        {(byte) '?'}, {(byte) '|'}, {(byte) '>'}, {(byte) '#'},
        {(byte) '\''}, {(byte) '"'},
        {(byte) '-', (byte) '-', (byte) '-'},
        {(byte) '.', (byte) '.', (byte) '.'},
    };

    // --- Corpus ---
    private final List<byte[]> corpus = new ArrayList<>();
    private long bestMaxDepth = 0;
    private int bestLength = 0;

    // --- Execution state ---
    private byte[] currentInput;
    private long totalExecs = 0;
    private long startTimeMs;
    private long lastLogTimeMs;
    private boolean finished = false;

    // --- Last execution signals (for SignalSource) ---
    private double lastMaxDepth = 0.0;
    private double lastNodeCount = 0.0;

    // --- Saved corpus counter ---
    private int savedCount = 0;

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.maxDurationMs = maxDurationMs;
        this.log = log;
        this.startTimeMs = System.currentTimeMillis();
        this.lastLogTimeMs = startTimeMs;

        // Seed corpus: small valid YAML inputs (not exploit payloads [R23])
        corpus.add(new byte[]{ (byte) 'a' });
        corpus.add(new byte[]{ (byte) '[', (byte) ']' });
        corpus.add(new byte[]{ (byte) '{', (byte) '}' });
        corpus.add(new byte[]{ (byte) '[', (byte) '1', (byte) ']' });
    }

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        // Reset counters before each execution
        DepthCounters.reset();

        if (totalExecs == 0) {
            // First execution: use first seed
            currentInput = corpus.get(0);
        } else {
            // Pick a parent from corpus, weighted by maxDepth signal
            byte[] parent = pickParent();
            // Mutate
            currentInput = mutate(parent);
        }

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (finished) return false;
        if (maxDurationMs > 0) {
            long elapsed = System.currentTimeMillis() - startTimeMs;
            if (elapsed >= maxDurationMs) {
                finished = true;
                return false;
            }
        }
        return true;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        totalExecs++;

        // Read signals from the agent [R26] — measured at the sink Composer#composeNode [R47]
        long measuredMaxDepth = DepthCounters.getMaxDepth();
        long measuredNodeCount = DepthCounters.getNodeCount();

        // Store for SignalSource.lastSignals() — per-execution values only
        lastMaxDepth = (double) measuredMaxDepth;
        lastNodeCount = (double) measuredNodeCount;

        // Retention policy [R46]:
        // Primary: keep if maxDepth improved
        // Secondary (flat signal): keep if input is longer than best (growth toward input_bytes)
        boolean retain = false;
        if (measuredMaxDepth > bestMaxDepth) {
            bestMaxDepth = measuredMaxDepth;
            retain = true;
        }
        if (currentInput.length > bestLength) {
            bestLength = currentInput.length;
            retain = true;
        }

        if (retain) {
            byte[] copy = Arrays.copyOf(currentInput, currentInput.length);
            corpus.add(copy);
            // Save to disk for reproduction [R7]
            try {
                Path p = corpusDir.toPath().resolve("id_" + String.format("%06d", savedCount++));
                Files.write(p, copy);
            } catch (IOException ignored) {
            }
        }

        // Logging every 1 second [R5]
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            lastLogTimeMs = now;
            long elapsed = now - startTimeMs;
            log.printf("[V1] %ds | execs=%d | corpus=%d | bestDepth=%d | bestLen=%d | thisDepth=%d | thisNodes=%d%n",
                    elapsed / 1000, totalExecs, corpus.size(),
                    bestMaxDepth, bestLength, measuredMaxDepth, measuredNodeCount);
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // We do NOT use JQF tracing; our signal comes from the custom agent [R43]
        return e -> { /* no-op */ };
    }

    // --- SignalSource implementation [Part D] ---
    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> signals = new LinkedHashMap<>();
        signals.put("maxDepth", lastMaxDepth);
        signals.put("nodeCount", lastNodeCount);
        return signals;
    }

    // --- Parent selection: weighted by depth ---
    private byte[] pickParent() {
        if (corpus.isEmpty()) {
            return new byte[]{(byte) '['};
        }
        // Simple weighted selection: prefer entries with higher index (newer/better)
        // and occasionally pick random for diversity
        if (rng.nextInt(10) < 3) {
            // Pick random from corpus
            return corpus.get(rng.nextInt(corpus.size()));
        }
        // Pick from the last quarter (likely higher depth)
        int start = Math.max(0, corpus.size() - Math.max(4, corpus.size() / 4));
        return corpus.get(start + rng.nextInt(corpus.size() - start));
    }

    // --- Mutation operators ---
    private byte[] mutate(byte[] parent) {
        // Choose mutation type
        int choice = rng.nextInt(100);
        byte[] result;
        if (choice < 25) {
            // Repetition [R45a]: duplicate a region
            result = mutateRepeat(parent);
        } else if (choice < 50) {
            // Dictionary insertion [R45b]
            result = mutateDictionary(parent);
        } else if (choice < 65) {
            // Byte flip
            result = mutateFlip(parent);
        } else if (choice < 80) {
            // Byte insertion
            result = mutateInsert(parent);
        } else if (choice < 90) {
            // Byte deletion
            result = mutateDelete(parent);
        } else {
            // Byte replacement
            result = mutateReplace(parent);
        }

        // Enforce max input size
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        if (result.length == 0) {
            result = new byte[]{(byte) '['};
        }
        return result;
    }

    /**
     * Repetition operator [R45a]:
     * Select a random region and repeat it k times, growing the input
     * toward maxInputSize. Can double the entire input or just a chunk.
     */
    private byte[] mutateRepeat(byte[] parent) {
        if (parent.length == 0) return parent;

        int start = rng.nextInt(parent.length);
        int len = 1 + rng.nextInt(Math.min(parent.length - start, Math.max(1, parent.length / 2)));

        // How many times to repeat — up to what fills maxInputSize
        int available = maxInputSize - parent.length;
        if (available <= 0) {
            // Already at max, just repeat a small chunk in place
            available = len * 2;
        }
        int maxK = Math.max(1, available / Math.max(1, len));
        int k = 1 + rng.nextInt(Math.min(maxK, 64)); // cap k to avoid huge allocation

        byte[] chunk = Arrays.copyOfRange(parent, start, start + len);
        int newLen = Math.min(parent.length + chunk.length * k, maxInputSize);
        byte[] result = new byte[newLen];

        // Copy prefix
        System.arraycopy(parent, 0, result, 0, start);
        // Write repeated chunk
        int pos = start;
        for (int i = 0; i <= k && pos + chunk.length <= newLen; i++) {
            System.arraycopy(chunk, 0, result, pos, chunk.length);
            pos += chunk.length;
        }
        // Copy suffix
        int remaining = newLen - pos;
        if (remaining > 0 && start + len < parent.length) {
            int suffixLen = Math.min(remaining, parent.length - start - len);
            System.arraycopy(parent, start + len, result, pos, suffixLen);
        }

        return result;
    }

    /**
     * Dictionary insertion [R45b]:
     * Insert a random token from the YAML dictionary at a random position.
     */
    private byte[] mutateDictionary(byte[] parent) {
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];
        int pos = rng.nextInt(parent.length + 1);
        byte[] result = new byte[Math.min(parent.length + token.length, maxInputSize)];
        System.arraycopy(parent, 0, result, 0, Math.min(pos, result.length));
        int tokenCopy = Math.min(token.length, result.length - pos);
        if (tokenCopy > 0) {
            System.arraycopy(token, 0, result, pos, tokenCopy);
        }
        int suffixStart = pos + tokenCopy;
        int suffixLen = Math.min(parent.length - pos, result.length - suffixStart);
        if (suffixLen > 0 && suffixStart < result.length) {
            System.arraycopy(parent, pos, result, suffixStart, suffixLen);
        }
        return result;
    }

    private byte[] mutateFlip(byte[] parent) {
        if (parent.length == 0) return parent;
        byte[] result = parent.clone();
        int pos = rng.nextInt(result.length);
        result[pos] ^= (byte) (1 << rng.nextInt(8));
        return result;
    }

    private byte[] mutateInsert(byte[] parent) {
        if (parent.length >= maxInputSize) return parent;
        int pos = rng.nextInt(parent.length + 1);
        byte[] result = new byte[parent.length + 1];
        System.arraycopy(parent, 0, result, 0, pos);
        result[pos] = (byte) rng.nextInt(256);
        System.arraycopy(parent, pos, result, pos + 1, parent.length - pos);
        return result;
    }

    private byte[] mutateDelete(byte[] parent) {
        if (parent.length <= 1) return parent;
        int pos = rng.nextInt(parent.length);
        byte[] result = new byte[parent.length - 1];
        System.arraycopy(parent, 0, result, 0, pos);
        System.arraycopy(parent, pos + 1, result, pos, parent.length - pos - 1);
        return result;
    }

    private byte[] mutateReplace(byte[] parent) {
        if (parent.length == 0) return parent;
        byte[] result = parent.clone();
        int pos = rng.nextInt(result.length);
        result[pos] = (byte) rng.nextInt(256);
        return result;
    }
}
