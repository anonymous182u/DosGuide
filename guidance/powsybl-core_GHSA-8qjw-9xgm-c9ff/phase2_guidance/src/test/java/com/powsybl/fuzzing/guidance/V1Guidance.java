package com.powsybl.fuzzing.guidance;

import com.powsybl.fuzzing.counter.RegexStepCounter;
import dosguide.validate.SignalSource;
import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;

import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Consumer;

/**
 * Custom Guidance for target V1: RegexCriterion.filter() ReDoS via user-controlled regex.
 *
 * <p>Implements {@link Guidance} directly (does not extend any JQF built-in guidance).
 * Measures NFA backtracking steps via the bytecode-instrumented
 * {@code RegexStepCounter} and retains inputs that maximize this signal.</p>
 *
 * <p>Mutation operators: byte flip, byte insert, byte delete, block overwrite,
 * chunk repeat (for input growth), and regex-metacharacter dictionary insert.</p>
 */
public class V1Guidance implements Guidance, SignalSource {

    // ── Configuration ────────────────────────────────────────────────
    private static final String TARGET_ID = "V1";
    private static final int DEFAULT_MAX_INPUT = 10240;
    private static final int SEED_SIZE = 8;
    private static final int INITIAL_SEED_COUNT = 4;

    /** Regex metacharacter dictionary tokens for DICTIONARY_INSERT mutation. */
    private static final byte[][] DICTIONARY = {
        "(a+)+".getBytes(), "(a+)+$".getBytes(), "(a*)*b".getBytes(),
        "([a-z]+)+$".getBytes(), "(a|a)+$".getBytes(),
        "(a+)+".getBytes(), ".*".getBytes(), ".+".getBytes(),
        "(".getBytes(), ")".getBytes(), "+".getBytes(), "*".getBytes(),
        "?".getBytes(), ".".getBytes(), "[".getBytes(), "]".getBytes(),
        "{".getBytes(), "}".getBytes(), "|".getBytes(), "^".getBytes(),
        "$".getBytes(), "\\".getBytes(), "a".getBytes(), "!".getBytes(),
    };

    // ── State ────────────────────────────────────────────────────────
    private final int maxInputSize;
    private final long maxDurationMs;
    private final PrintStream log;
    private final File corpusDir;
    private final Random rng = new Random();

    /** Corpus: list of (bytes, nfaSteps) pairs. */
    private final List<byte[]> corpusInputs = new ArrayList<>();
    private final List<Long> corpusSteps = new ArrayList<>();

    private long bestSteps = 0;
    private long totalExecs = 0;
    private long startTimeMs = -1;
    private long lastLogMs = 0;
    private double lastNfaSteps = 0.0;
    private byte[] currentInput;

    // ── Constructor ──────────────────────────────────────────────────
    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxDurationMs = maxDurationMs;
        this.log = log;
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", DEFAULT_MAX_INPUT);

        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();

        // Seed the corpus with small random inputs
        for (int i = 0; i < INITIAL_SEED_COUNT; i++) {
            byte[] seed = new byte[SEED_SIZE];
            rng.nextBytes(seed);
            corpusInputs.add(seed);
            corpusSteps.add(0L);
        }

        log.printf("[%s] Initialized: maxInput=%d, maxDuration=%dms%n",
                TARGET_ID, maxInputSize, maxDurationMs);
    }

    // ── Guidance interface ───────────────────────────────────────────

    @Override
    public InputStream getInput() throws GuidanceException {
        if (startTimeMs < 0) {
            startTimeMs = System.currentTimeMillis();
            lastLogMs = startTimeMs;
        }

        // Select parent: weighted toward higher nfaSteps
        byte[] parent = selectParent();

        // Mutate
        currentInput = mutate(parent);

        // Reset the step counter before the execution
        RegexStepCounter.reset();

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (startTimeMs < 0) return true; // not started yet
        if (maxDurationMs <= 0) return true; // infinite
        return (System.currentTimeMillis() - startTimeMs) < maxDurationMs;
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        long steps = RegexStepCounter.get();
        lastNfaSteps = (double) steps;
        totalExecs++;

        // Decide retention
        boolean retain = false;
        if (steps > bestSteps) {
            bestSteps = steps;
            retain = true;
        } else if (bestSteps == 0 && result == Result.SUCCESS && currentInput != null) {
            // While signal is flat: retain successful compilations (regex parsed OK)
            // that are longer (growing toward target size)
            if (corpusInputs.isEmpty() || currentInput.length > corpusInputs.get(0).length) {
                retain = true;
            }
        }

        if (retain && currentInput != null) {
            corpusInputs.add(currentInput.clone());
            corpusSteps.add(steps);
            saveToCorpus(currentInput, steps);
        }

        // Log every 1 second
        long now = System.currentTimeMillis();
        if (now - lastLogMs >= 1000) {
            long elapsed = now - startTimeMs;
            log.printf("[%s] %dms | execs=%d | bestSteps=%d | lastSteps=%d | corpus=%d%n",
                    TARGET_ID, elapsed, totalExecs, bestSteps, steps, corpusInputs.size());
            lastLogMs = now;
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // No-op: we use the agent for instrumentation, not JQF's trace events
        return event -> { };
    }

    // ── SignalSource interface ────────────────────────────────────────

    @Override
    public Map<String, Double> lastSignals() {
        return Collections.singletonMap("nfaSteps", lastNfaSteps);
    }

    // ── Mutation operators ───────────────────────────────────────────

    private byte[] mutate(byte[] parent) {
        if (parent.length == 0) {
            byte[] seed = new byte[SEED_SIZE];
            rng.nextBytes(seed);
            return seed;
        }

        // Weighted mutation selection
        int roll = rng.nextInt(100);
        byte[] result;
        if (roll < 20) {
            result = flipByte(parent);
        } else if (roll < 35) {
            result = insertByte(parent);
        } else if (roll < 45) {
            result = deleteByte(parent);
        } else if (roll < 60) {
            result = overwriteBlock(parent);
        } else if (roll < 85) {
            result = repeatChunk(parent);
        } else {
            result = dictionaryInsert(parent);
        }

        // Cap at maxInputSize
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        return result;
    }

    /** FLIP_BYTE: flip a random byte. */
    private byte[] flipByte(byte[] input) {
        byte[] out = input.clone();
        int pos = rng.nextInt(out.length);
        out[pos] ^= (byte) (1 << rng.nextInt(8));
        return out;
    }

    /** INSERT_BYTE: insert a random byte at a random position. */
    private byte[] insertByte(byte[] input) {
        byte[] out = new byte[input.length + 1];
        int pos = rng.nextInt(input.length + 1);
        System.arraycopy(input, 0, out, 0, pos);
        out[pos] = (byte) rng.nextInt(256);
        System.arraycopy(input, pos, out, pos + 1, input.length - pos);
        return out;
    }

    /** DELETE_BYTE: remove a byte at a random position. */
    private byte[] deleteByte(byte[] input) {
        if (input.length <= 1) return input;
        byte[] out = new byte[input.length - 1];
        int pos = rng.nextInt(input.length);
        System.arraycopy(input, 0, out, 0, pos);
        System.arraycopy(input, pos + 1, out, pos, input.length - pos - 1);
        return out;
    }

    /** OVERWRITE_BLOCK: copy a random block from one position to another. */
    private byte[] overwriteBlock(byte[] input) {
        byte[] out = input.clone();
        int blockLen = 1 + rng.nextInt(Math.max(1, input.length / 4));
        int srcPos = rng.nextInt(input.length);
        int dstPos = rng.nextInt(input.length);
        int actualLen = Math.min(blockLen, Math.min(input.length - srcPos, input.length - dstPos));
        System.arraycopy(input, srcPos, out, dstPos, actualLen);
        return out;
    }

    /**
     * REPEAT_CHUNK: select a random contiguous chunk, repeat it k times.
     * This is the primary mechanism for growing inputs from small seeds
     * to the target 64+ bytes. A single repeat can double the input.
     */
    private byte[] repeatChunk(byte[] input) {
        int chunkStart = rng.nextInt(input.length);
        int maxChunkLen = Math.min(input.length - chunkStart, Math.max(1, input.length / 2));
        int chunkLen = 1 + rng.nextInt(maxChunkLen);

        // k: repeat count 2..8 (capped by maxInputSize)
        int maxK = Math.min(8, maxInputSize / Math.max(1, chunkLen));
        int k = 2 + rng.nextInt(Math.max(1, maxK - 1));

        byte[] chunk = Arrays.copyOfRange(input, chunkStart, chunkStart + chunkLen);
        // Build: prefix + chunk*k + suffix
        byte[] prefix = Arrays.copyOfRange(input, 0, chunkStart);
        byte[] suffix = Arrays.copyOfRange(input, chunkStart + chunkLen, input.length);

        int newLen = prefix.length + (chunk.length * k) + suffix.length;
        if (newLen > maxInputSize) {
            // Reduce k to fit
            k = (maxInputSize - prefix.length - suffix.length) / Math.max(1, chunk.length);
            if (k < 2) return input; // can't repeat, return as-is
            newLen = prefix.length + (chunk.length * k) + suffix.length;
        }

        byte[] out = new byte[newLen];
        int pos = 0;
        System.arraycopy(prefix, 0, out, pos, prefix.length);
        pos += prefix.length;
        for (int i = 0; i < k; i++) {
            System.arraycopy(chunk, 0, out, pos, chunk.length);
            pos += chunk.length;
        }
        System.arraycopy(suffix, 0, out, pos, suffix.length);
        return out;
    }

    /**
     * DICTIONARY_INSERT: insert or overwrite a regex metacharacter token
     * at a random position in the input.
     */
    private byte[] dictionaryInsert(byte[] input) {
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];

        // 50% insert, 50% overwrite
        if (rng.nextBoolean()) {
            // Insert
            int pos = rng.nextInt(input.length + 1);
            byte[] out = new byte[input.length + token.length];
            System.arraycopy(input, 0, out, 0, pos);
            System.arraycopy(token, 0, out, pos, token.length);
            System.arraycopy(input, pos, out, pos + token.length, input.length - pos);
            return out;
        } else {
            // Overwrite
            byte[] out = input.clone();
            int pos = rng.nextInt(input.length);
            int copyLen = Math.min(token.length, input.length - pos);
            System.arraycopy(token, 0, out, pos, copyLen);
            return out;
        }
    }

    // ── Parent selection (weighted by nfaSteps) ──────────────────────

    private byte[] selectParent() {
        if (corpusInputs.isEmpty()) {
            byte[] seed = new byte[SEED_SIZE];
            rng.nextBytes(seed);
            return seed;
        }

        // If bestSteps > 0, weight towards higher-step entries
        if (bestSteps > 0) {
            // Weighted selection: probability proportional to (steps + 1)
            long totalWeight = 0;
            for (long s : corpusSteps) totalWeight += (s + 1);
            long pick = Math.abs(rng.nextLong()) % totalWeight;
            long cumulative = 0;
            for (int i = 0; i < corpusInputs.size(); i++) {
                cumulative += (corpusSteps.get(i) + 1);
                if (cumulative > pick) {
                    return corpusInputs.get(i);
                }
            }
        }

        // Uniform random selection
        return corpusInputs.get(rng.nextInt(corpusInputs.size()));
    }

    // ── Corpus persistence ───────────────────────────────────────────

    private void saveToCorpus(byte[] input, long steps) {
        try {
            String name = String.format("id_%06d_steps_%d.bin", totalExecs, steps);
            Path path = corpusDir.toPath().resolve(name);
            Files.write(path, input);
        } catch (IOException e) {
            // Non-fatal: log and continue
            log.printf("[%s] WARN: failed to save corpus entry: %s%n",
                    TARGET_ID, e.getMessage());
        }
    }
}
