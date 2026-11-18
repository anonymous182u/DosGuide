package fuzzing.guidance;

import dosguide.validate.SignalSource;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;
import fuzzing.agent.CombinedMeasureAgent;
import fuzzing.agent.DepthCounters;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

/**
 * Cost-Gradient Guidance for V1: JSON recursive descent parsing DoS.
 *
 * Measures JSONTokener.nextValue() recursion depth via bytecode instrumentation
 * (DepthCounters) and hill-climbs toward maximum nesting depth.
 *
 * Implements Guidance directly [R3], does not extend any existing Guidance.
 * Implements SignalSource for DoSGuide validation.
 */
public class V1Guidance implements Guidance, SignalSource {

    private final int maxInputSize;
    private final long maxDurationMs;
    private final File corpusDir;
    private final PrintStream log;
    private final Random rng = new Random();

    // Dictionary tokens from JSONTokener/JSONArray/JSONObject source [R45(b)]
    private static final byte[][] DICT_TOKENS = {
        "[".getBytes(StandardCharsets.UTF_8),
        "]".getBytes(StandardCharsets.UTF_8),
        "{".getBytes(StandardCharsets.UTF_8),
        "}".getBytes(StandardCharsets.UTF_8),
        ":".getBytes(StandardCharsets.UTF_8),
        ",".getBytes(StandardCharsets.UTF_8),
        "\"".getBytes(StandardCharsets.UTF_8),
        "'".getBytes(StandardCharsets.UTF_8),
        "true".getBytes(StandardCharsets.UTF_8),
        "false".getBytes(StandardCharsets.UTF_8),
        "null".getBytes(StandardCharsets.UTF_8),
    };

    // Corpus
    private final List<CorpusEntry> corpus = new ArrayList<>();
    private long bestMaxDepth = 0;
    private int bestLength = 0;
    private long sinceImproved = 0;

    // State
    private long startTimeMs;
    private long executions = 0;
    private long lastLogTimeMs = 0;
    private byte[] currentInput;
    private boolean retransformed = false;

    // Last execution signals (for SignalSource)
    private double lastMaxDepth = 0;
    private double lastNodeCount = 0;

    // Seed: "[1]" triggers JSONArray constructor → nextValue() call
    // This is a well-formed JSON array, NOT a failure-inducing input.
    private static final byte[] INITIAL_SEED = "[1]".getBytes(StandardCharsets.UTF_8);

    public V1Guidance(File corpusDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 10240);
        this.maxDurationMs = maxDurationMs;
        this.corpusDir = corpusDir;
        this.log = log;
        this.startTimeMs = System.currentTimeMillis();
        this.lastLogTimeMs = this.startTimeMs;
        corpusDir.mkdirs();

        // Seed the corpus with an input that reaches nextValue()
        byte[] seed = INITIAL_SEED;
        if (seed.length > maxInputSize) {
            seed = Arrays.copyOf(seed, maxInputSize);
        }
        corpus.add(new CorpusEntry(seed, 0, seed.length));
    }

    @Override
    public InputStream getInput() throws GuidanceException {
        // On first call, trigger retransformation of already-loaded target classes
        if (!retransformed) {
            retransformed = true;
            try {
                CombinedMeasureAgent.retransformIfNeeded();
            } catch (Throwable t) {
                // Agent might not be loaded; ignore
            }
        }

        // Reset instrumentation counters before each execution
        DepthCounters.reset();

        // Generate input via mutation
        currentInput = generateInput();

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (maxDurationMs <= 0) return true; // infinite
        long elapsed = System.currentTimeMillis() - startTimeMs;
        return elapsed < maxDurationMs;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        executions++;

        // Read signals from instrumentation
        long maxDepth = DepthCounters.getMaxDepth();
        long nodeCount = DepthCounters.getNodeCount();

        // Store for SignalSource (per-execution, not running total)
        lastMaxDepth = (double) maxDepth;
        lastNodeCount = (double) nodeCount;

        // Retention logic
        boolean retained = false;

        // Primary: retain if maxDepth exceeds best
        if (maxDepth > bestMaxDepth) {
            bestMaxDepth = maxDepth;
            sinceImproved = 0;
            retained = true;
        } else {
            sinceImproved++;
        }

        // Secondary [R46]: when signal is flat, retain longer inputs
        if (!retained && sinceImproved > 200 && currentInput.length > bestLength) {
            retained = true;
        }

        // Bootstrap: retain early inputs to build initial corpus
        if (!retained && corpus.size() < 10 && currentInput.length > 0) {
            retained = true;
        }

        if (retained) {
            CorpusEntry entry = new CorpusEntry(
                    Arrays.copyOf(currentInput, currentInput.length),
                    maxDepth, currentInput.length);
            corpus.add(entry);
            if (currentInput.length > bestLength) {
                bestLength = currentInput.length;
            }
            try {
                saveCorpusEntry(entry, executions);
            } catch (Exception e) { /* ignore I/O errors */ }
        }

        // Log every 1 second
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            log.printf("[V1Guidance] exec=%d, corpus=%d, bestDepth=%d, lastDepth=%d, "
                            + "lastNodes=%d, bestLen=%d, elapsed=%.1fs%n",
                    executions, corpus.size(), bestMaxDepth, maxDepth,
                    nodeCount, bestLength,
                    (now - startTimeMs) / 1000.0);
            lastLogTimeMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        return (event) -> { };
    }

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> signals = new LinkedHashMap<>();
        signals.put("maxDepth", lastMaxDepth);
        signals.put("nodeCount", lastNodeCount);
        return signals;
    }

    // ========== Input generation ==========

    private byte[] generateInput() {
        CorpusEntry parent = selectParent();
        byte[] input = parent.data.clone();

        // Apply 1-3 mutations
        int numMutations = 1 + rng.nextInt(3);
        for (int i = 0; i < numMutations; i++) {
            input = mutate(input);
        }

        // Enforce max input size
        if (input.length > maxInputSize) {
            input = Arrays.copyOf(input, maxInputSize);
        }
        // Ensure non-empty
        if (input.length == 0) {
            input = INITIAL_SEED.length <= maxInputSize
                    ? INITIAL_SEED.clone()
                    : Arrays.copyOf(INITIAL_SEED, maxInputSize);
        }

        return input;
    }

    private CorpusEntry selectParent() {
        if (corpus.isEmpty()) {
            return new CorpusEntry(INITIAL_SEED, 0, INITIAL_SEED.length);
        }
        int size = corpus.size();
        // Prefer recent/better entries (80% from top half)
        if (size > 1 && rng.nextDouble() < 0.8) {
            int topHalf = Math.max(1, size / 2);
            return corpus.get(size - 1 - rng.nextInt(topHalf));
        }
        return corpus.get(rng.nextInt(size));
    }

    private byte[] mutate(byte[] input) {
        if (input.length == 0) {
            return DICT_TOKENS[rng.nextInt(DICT_TOKENS.length)].clone();
        }

        int op = rng.nextInt(10);
        switch (op) {
            case 0: return byteFlip(input);
            case 1: return byteInsert(input);
            case 2: return byteDelete(input);
            case 3: return blockCopy(input);
            case 4: case 5: case 6: return chunkRepetition(input);
            case 7: return wholeDoubling(input);
            case 8: case 9: return dictInsert(input);
            default: return input;
        }
    }

    private byte[] byteFlip(byte[] input) {
        byte[] result = input.clone();
        int pos = rng.nextInt(result.length);
        result[pos] = (byte) (result[pos] ^ (1 << rng.nextInt(8)));
        return result;
    }

    private byte[] byteInsert(byte[] input) {
        if (input.length >= maxInputSize) return input;
        byte[] result = new byte[input.length + 1];
        int pos = rng.nextInt(input.length + 1);
        System.arraycopy(input, 0, result, 0, pos);
        result[pos] = (byte) rng.nextInt(256);
        System.arraycopy(input, pos, result, pos + 1, input.length - pos);
        return result;
    }

    private byte[] byteDelete(byte[] input) {
        if (input.length <= 1) return input;
        byte[] result = new byte[input.length - 1];
        int pos = rng.nextInt(input.length);
        System.arraycopy(input, 0, result, 0, pos);
        System.arraycopy(input, pos + 1, result, pos, input.length - pos - 1);
        return result;
    }

    private byte[] blockCopy(byte[] input) {
        if (input.length < 2) return input;
        int srcPos = rng.nextInt(input.length);
        int blockLen = 1 + rng.nextInt(Math.min(input.length - srcPos, Math.max(1, input.length / 4)));
        int dstPos = rng.nextInt(input.length);
        int newLen = Math.min(input.length + blockLen, maxInputSize);
        byte[] result = new byte[newLen];
        int beforeLen = Math.min(dstPos, newLen);
        System.arraycopy(input, 0, result, 0, beforeLen);
        if (beforeLen < newLen) {
            int copyLen = Math.min(blockLen, newLen - beforeLen);
            System.arraycopy(input, srcPos, result, beforeLen, copyLen);
            int afterStart = beforeLen + copyLen;
            int remaining = Math.min(input.length - dstPos, newLen - afterStart);
            if (remaining > 0) {
                System.arraycopy(input, dstPos, result, afterStart, remaining);
            }
        }
        return result;
    }

    private byte[] chunkRepetition(byte[] input) {
        if (input.length == 0) return input;
        int chunkStart = rng.nextInt(input.length);
        int maxChunkLen = Math.max(1, Math.min(input.length / 2, input.length - chunkStart));
        int chunkLen = 1 + rng.nextInt(maxChunkLen);
        byte[] chunk = Arrays.copyOfRange(input, chunkStart, chunkStart + chunkLen);

        int totalLen = Math.min(chunkLen * Math.max(2, maxInputSize / chunkLen), maxInputSize);
        byte[] result = new byte[totalLen];
        int pos = 0;
        while (pos + chunkLen <= totalLen) {
            System.arraycopy(chunk, 0, result, pos, chunkLen);
            pos += chunkLen;
        }
        if (pos < totalLen) {
            System.arraycopy(chunk, 0, result, pos, totalLen - pos);
        }
        return result;
    }

    private byte[] wholeDoubling(byte[] input) {
        int newLen = Math.min(input.length * 2, maxInputSize);
        if (newLen <= input.length) return input;
        byte[] result = new byte[newLen];
        System.arraycopy(input, 0, result, 0, input.length);
        System.arraycopy(input, 0, result, input.length, newLen - input.length);
        return result;
    }

    private byte[] dictInsert(byte[] input) {
        byte[] token = DICT_TOKENS[rng.nextInt(DICT_TOKENS.length)];
        int pos = rng.nextInt(input.length + 1);
        int newLen = Math.min(input.length + token.length, maxInputSize);
        byte[] result = new byte[newLen];
        int copyBefore = Math.min(pos, newLen);
        System.arraycopy(input, 0, result, 0, copyBefore);
        int tokenCopy = Math.min(token.length, newLen - copyBefore);
        if (tokenCopy > 0) {
            System.arraycopy(token, 0, result, copyBefore, tokenCopy);
        }
        int afterPos = copyBefore + tokenCopy;
        int remaining = Math.min(input.length - pos, newLen - afterPos);
        if (remaining > 0) {
            System.arraycopy(input, pos, result, afterPos, remaining);
        }
        return result;
    }

    // ========== Corpus persistence ==========

    private void saveCorpusEntry(CorpusEntry entry, long id) throws Exception {
        File binFile = new File(corpusDir, "id_" + id + ".bin");
        try (FileOutputStream fos = new FileOutputStream(binFile)) {
            fos.write(entry.data);
        }
    }

    private static class CorpusEntry {
        final byte[] data;
        final long maxDepth;
        final int length;
        CorpusEntry(byte[] data, long maxDepth, int length) {
            this.data = data;
            this.maxDepth = maxDepth;
            this.length = length;
        }
    }
}
