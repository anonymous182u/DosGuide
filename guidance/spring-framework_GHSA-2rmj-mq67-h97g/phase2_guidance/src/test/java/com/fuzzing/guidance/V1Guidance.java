package com.fuzzing.guidance;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Consumer;

import edu.berkeley.cs.jqf.fuzz.guidance.Guidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.instrument.tracing.events.TraceEvent;

import dosguide.validate.SignalSource;

/**
 * Cost-Gradient Guidance for V1: ETAG_HEADER_VALUE_PATTERN quadratic regex
 * backtracking in HttpHeaders.getIfNoneMatch().
 *
 * Signal: regexSteps — total Pattern$Node.match() invocations per execution,
 * measured by V1MeasureAgent (Tier 1 bytecode instrumentation).
 *
 * Two-phase strategy:
 *   Phase 1 (growth): aggressively double inputs to reach maxInputSize while
 *           keeping them diverse (fast execution, no quadratic wall).
 *   Phase 2 (optimization): homogenize inputs to discover that whitespace
 *           maximizes regexSteps (quadratic backtracking).
 *
 * Implements Guidance directly ([R3]). Does not extend/delegate Zest or others.
 * Implements SignalSource for DoSGuide validation.
 *
 * Input model: byte[]/InputStream ([R31]).
 * No failure decisions ([R6]).
 */
public final class V1Guidance implements Guidance, SignalSource {

    // --- Configuration ---
    private final int maxInputSize;
    private final long maxDurationMs;
    private final File corpusDir;
    private final PrintStream log;
    private final Random rng = new Random();

    // --- Agent signal access (reflection on bootstrap V1Counters) ---
    private Method counterReset;
    private Method counterGetSteps;

    // --- Corpus ---
    private final List<CorpusEntry> corpus = new ArrayList<>();
    private long bestRegexSteps = -1;
    private int longestInputLen = 0;

    // --- Per-execution state ---
    private byte[] currentInput;
    private double lastRegexSteps = 0.0;

    // --- Statistics ---
    private long totalExecs = 0;
    private long startTimeMs;
    private long lastLogTimeMs;
    private int seedsGenerated = 0;

    // --- Seed phase: generate diverse initial seeds before mutating ---
    private static final int MAX_SEEDS = 5;

    // --- Whitespace bytes that Java's \s matches (the regex uses \s*) ---
    private static final byte[] WS = {0x20, 0x09, 0x0A, 0x0D};

    // --- Dictionary tokens from ETag grammar source ([R45](b)) ---
    private static final byte[][] DICTIONARY = {
        {0x20},             // space (\s)
        {0x09},             // tab (\s)
        {0x0A},             // newline (\s)
        {0x0D},             // carriage return (\s)
        {0x22},             // " (quote delimiter)
        {0x2A},             // * (first regex alternative)
        {0x2C},             // , (comma separator)
        {0x57, 0x2F},       // W/ (weak ETag prefix)
    };

    public V1Guidance(File outputDir, long maxDurationMs, PrintStream log) {
        this.maxInputSize = Integer.getInteger("jqf.ei.MAX_INPUT_SIZE", 131072);
        this.maxDurationMs = maxDurationMs;
        this.corpusDir = new File(outputDir, "corpus");
        this.corpusDir.mkdirs();
        this.log = log;
        this.startTimeMs = System.currentTimeMillis();
        this.lastLogTimeMs = this.startTimeMs;

        log.println("[V1Guidance] maxInputSize=" + this.maxInputSize);

        // Resolve V1Counters via bootstrap classloader (null = bootstrap CL)
        try {
            Class<?> countersClass = Class.forName(
                    "com.fuzzing.agent.V1Counters", true, null);
            this.counterReset = countersClass.getMethod("reset");
            this.counterGetSteps = countersClass.getMethod("getStepCount");
        } catch (ClassNotFoundException e) {
            // Agent not loaded — fall back to no-op (signal stays 0)
            this.counterReset = null;
            this.counterGetSteps = null;
            log.println("[V1Guidance] WARNING: V1Counters not on bootstrap classpath. "
                    + "Signal will be zero. Run with -javaagent:agent/v1-agent.jar");
        } catch (NoSuchMethodException e) {
            throw new GuidanceException("V1Counters API mismatch", e);
        }
    }

    // ---- Guidance interface ----

    @Override
    public InputStream getInput() throws IllegalStateException, GuidanceException {
        // Reset the counter before this execution
        resetCounter();

        if (seedsGenerated < MAX_SEEDS || corpus.isEmpty()) {
            // Seed phase: generate diverse well-formed ETag examples
            currentInput = generateInitialSeed();
            seedsGenerated++;
        } else {
            // Mutation phase: mutate a corpus entry
            CorpusEntry parent = selectParent();
            currentInput = mutate(parent.input);
        }

        return new ByteArrayInputStream(currentInput);
    }

    @Override
    public boolean hasInput() {
        if (maxDurationMs > 0) {
            return (System.currentTimeMillis() - startTimeMs) < maxDurationMs;
        }
        return true; // infinite by default ([R8])
    }

    @Override
    public void handleResult(Result result, Throwable error) throws GuidanceException {
        totalExecs++;

        // Read the regex step count from the agent
        long steps = readStepCount();
        lastRegexSteps = (double) steps;

        // Retention decisions (never declare failure, [R6])
        boolean retain = false;

        // Primary: new max regexSteps
        if (steps > bestRegexSteps) {
            bestRegexSteps = steps;
            retain = true;
        }

        // Secondary ([R46]): input is longer than any retained input (progress while flat)
        if (currentInput.length > longestInputLen) {
            longestInputLen = currentInput.length;
            retain = true;
        }

        if (retain) {
            CorpusEntry entry = new CorpusEntry(
                    currentInput.clone(), steps, currentInput.length);
            corpus.add(entry);
            saveToCorpus(entry);

            // Evict if corpus is too large (keep top entries by steps + longest)
            if (corpus.size() > 100) {
                evictCorpus();
            }
        }

        // Structured logging every 1 second ([R5])
        long now = System.currentTimeMillis();
        if (now - lastLogTimeMs >= 1000) {
            lastLogTimeMs = now;
            long elapsed = now - startTimeMs;
            log.printf("[V1Guidance] elapsed=%dms execs=%d corpus=%d "
                            + "bestSteps=%d longestInput=%d lastSteps=%d lastLen=%d phase=%s%n",
                    elapsed, totalExecs, corpus.size(),
                    bestRegexSteps, longestInputLen,
                    steps, currentInput.length,
                    longestInputLen < maxInputSize ? "growth" : "optimize");
        }
    }

    @Override
    public Consumer<TraceEvent> generateCallBack(Thread thread) {
        // No-op: we use the custom agent, not JQF tracing ([R43])
        return event -> { };
    }

    // ---- SignalSource interface ----

    @Override
    public Map<String, Double> lastSignals() {
        Map<String, Double> signals = new HashMap<>();
        signals.put("regexSteps", lastRegexSteps);
        return signals;
    }

    // ---- Initial seed generation ----

    /**
     * Generate an initial seed. 1/3 random bytes for diversity, 2/3 well-formed
     * ETag header values with whitespace padding — ordinary examples of the
     * If-None-Match format that the search can mutate.
     */
    private byte[] generateInitialSeed() {
        if (rng.nextInt(3) == 0) {
            // Random bytes for diversity
            int len = rng.nextInt(Math.min(32, maxInputSize)) + 1;
            byte[] input = new byte[len];
            rng.nextBytes(input);
            return input;
        } else {
            // Well-formed ETag header value
            return generateEtagSeed();
        }
    }

    /**
     * Generate a well-formed ETag header value with whitespace padding.
     * Covers all combinations of ETag parts: strong ETags ("value"),
     * weak ETags (W/"value"), wildcards (*), comma-separated lists,
     * and varying whitespace between tokens.
     */
    private byte[] generateEtagSeed() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int targetLen = Math.min(rng.nextInt(200) + 10, maxInputSize);

        while (out.size() < targetLen) {
            // Leading whitespace (the ETag format allows OWS between tokens)
            int wsLen = rng.nextInt(15) + 1;
            byte ws = WS[rng.nextInt(WS.length)];
            for (int j = 0; j < wsLen && out.size() < targetLen; j++) {
                out.write(ws);
            }

            if (out.size() >= targetLen) break;

            // ETag construct: * | [W/]"value"
            int kind = rng.nextInt(3);
            if (kind == 0) {
                out.write('*');
            } else {
                // Optional weak prefix
                if (rng.nextBoolean()) {
                    out.write('W');
                    out.write('/');
                }
                // Quoted string
                out.write('"');
                int valLen = rng.nextInt(8) + 1;
                for (int j = 0; j < valLen; j++) {
                    // Printable non-quote character
                    byte b = (byte) (rng.nextInt(94) + 33);
                    if (b == '"') b = 'x';
                    out.write(b);
                }
                out.write('"');
            }

            // Trailing whitespace
            int wsLen2 = rng.nextInt(10) + 1;
            byte ws2 = WS[rng.nextInt(WS.length)];
            for (int j = 0; j < wsLen2 && out.size() < targetLen; j++) {
                out.write(ws2);
            }

            // Comma separator for lists
            if (out.size() < targetLen) {
                out.write(',');
            }
        }

        byte[] result = out.toByteArray();
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        return result;
    }

    // ---- Mutation operators ----

    /**
     * Two-phase mutation strategy:
     * - Growth phase (longestInputLen < maxInputSize): aggressively double inputs
     *   with diverse content (fast execution). No homogenize — avoids quadratic wall.
     * - Optimization phase: homogenize to discover which byte class maximizes signal
     *   (the search discovers whitespace causes quadratic backtracking).
     */
    private byte[] mutate(byte[] parent) {
        boolean growthPhase = longestInputLen < maxInputSize;
        int op = rng.nextInt(100);
        byte[] result;

        if (growthPhase) {
            // --- Growth phase: fast doubling, no homogenize ---
            if (op < 60) {
                // 60% — Doubling: guaranteed 2× growth, stays diverse → fast
                result = mutateDouble(parent);
            } else if (op < 75) {
                // 15% — Repetition: variable growth
                result = mutateRepeat(parent);
            } else if (op < 85) {
                // 10% — Dictionary insert
                result = mutateDictionary(parent);
            } else if (op < 95) {
                // 10% — Byte flip
                result = mutateFlip(parent);
            } else {
                // 5% — Byte delete
                result = mutateDelete(parent);
            }
        } else {
            // --- Optimization phase: homogenize + refine structure ---
            if (op < 20) {
                // 20% — Repetition: further growth
                result = mutateRepeat(parent);
            } else if (op < 40) {
                // 20% — Homogenize: pick a byte from input, spread it.
                //        Search discovers whitespace → max signal.
                result = mutateHomogenize(parent);
            } else if (op < 50) {
                // 10% — Dictionary insert
                result = mutateDictionary(parent);
            } else if (op < 60) {
                // 10% — Byte flip
                result = mutateFlip(parent);
            } else if (op < 65) {
                // 5% — Byte insert
                result = mutateInsert(parent);
            } else if (op < 75) {
                // 10% — Byte delete
                result = mutateDelete(parent);
            } else {
                // 25% — Havoc (combine multiple mutations)
                result = parent.clone();
                int rounds = rng.nextInt(4) + 2;
                for (int i = 0; i < rounds; i++) {
                    int subOp = rng.nextInt(6);
                    result = switch (subOp) {
                        case 0 -> mutateRepeat(result);
                        case 1 -> mutateHomogenize(result);
                        case 2 -> mutateDictionary(result);
                        case 3 -> mutateFlip(result);
                        case 4 -> mutateDelete(result);
                        default -> mutateInsert(result);
                    };
                }
            }
        }

        // Enforce max input size
        if (result.length > maxInputSize) {
            result = Arrays.copyOf(result, maxInputSize);
        }
        if (result.length == 0) {
            return new byte[]{(byte) rng.nextInt(256)};
        }
        return result;
    }

    /**
     * Doubling: concatenate the input with itself (up to maxInputSize).
     * This is the primary growth operator — guaranteed 2× growth per call.
     * During the growth phase the input is diverse (not homogeneous whitespace),
     * so each execution is fast (linear cost, not quadratic).
     */
    private byte[] mutateDouble(byte[] input) {
        if (input.length == 0) return input;
        int newLen = Math.min(input.length * 2, maxInputSize);
        byte[] result = new byte[newLen];
        System.arraycopy(input, 0, result, 0, input.length);
        int secondHalf = newLen - input.length;
        if (secondHalf > 0) {
            System.arraycopy(input, 0, result, input.length, secondHalf);
        }
        return result;
    }

    /** Repetition: copy a chunk and repeat it k times ([R45](a)). */
    private byte[] mutateRepeat(byte[] input) {
        if (input.length == 0) return input;

        int start = rng.nextInt(input.length);
        int chunkLen = rng.nextInt(input.length - start) + 1;

        // k chosen to grow toward maxInputSize
        int maxK = Math.max(2, maxInputSize / Math.max(chunkLen, 1));
        int k = rng.nextInt(Math.min(maxK, 128)) + 2;

        int newLen = Math.min(start + chunkLen * k + (input.length - start - chunkLen),
                maxInputSize);
        byte[] result = new byte[newLen];

        // Copy prefix
        System.arraycopy(input, 0, result, 0, start);

        // Repeat chunk k times
        int pos = start;
        for (int i = 0; i < k && pos + chunkLen <= newLen; i++) {
            System.arraycopy(input, start, result, pos, chunkLen);
            pos += chunkLen;
        }

        // Copy suffix if space remains
        int suffixStart = start + chunkLen;
        int remaining = newLen - pos;
        if (remaining > 0 && suffixStart < input.length) {
            int toCopy = Math.min(remaining, input.length - suffixStart);
            System.arraycopy(input, suffixStart, result, pos, toCopy);
        }

        return result;
    }

    /**
     * Homogenize: pick a random byte from the input and spread it, replacing
     * other bytes. The search discovers which source byte maximizes the signal
     * (whitespace bytes cause quadratic backtracking; the guidance finds this
     * through its fitness function without hardcoding which byte to spread).
     * Only used in optimization phase (after inputs reach target size).
     */
    private byte[] mutateHomogenize(byte[] input) {
        if (input.length == 0) return input;
        byte[] result = input.clone();

        // Pick a random byte FROM the input (not a fixed value)
        byte target = result[rng.nextInt(result.length)];

        if (rng.nextBoolean()) {
            // Contiguous fill: fill a region with the target byte
            int start = rng.nextInt(result.length);
            int len = rng.nextInt(result.length - start) + 1;
            Arrays.fill(result, start, start + len, target);
        } else {
            // Scattered: replace random positions with the target byte
            int count = rng.nextInt(result.length) + 1;
            for (int i = 0; i < count; i++) {
                result[rng.nextInt(result.length)] = target;
            }
        }
        return result;
    }

    /** Dictionary: insert or overwrite a token at a random position ([R45](b)). */
    private byte[] mutateDictionary(byte[] input) {
        byte[] token = DICTIONARY[rng.nextInt(DICTIONARY.length)];

        if (rng.nextBoolean() && input.length > 0) {
            // Overwrite at random position
            byte[] result = input.clone();
            int pos = rng.nextInt(input.length);
            for (int i = 0; i < token.length && pos + i < result.length; i++) {
                result[pos + i] = token[i];
            }
            return result;
        } else {
            // Insert at random position
            int pos = input.length == 0 ? 0 : rng.nextInt(input.length + 1);
            int newLen = Math.min(input.length + token.length, maxInputSize);
            byte[] result = new byte[newLen];
            System.arraycopy(input, 0, result, 0, pos);
            int tokenCopy = Math.min(token.length, newLen - pos);
            System.arraycopy(token, 0, result, pos, tokenCopy);
            int remaining = Math.min(input.length - pos, newLen - pos - tokenCopy);
            if (remaining > 0) {
                System.arraycopy(input, pos, result, pos + tokenCopy, remaining);
            }
            return result;
        }
    }

    /** Byte flip: change a random byte to a random value. */
    private byte[] mutateFlip(byte[] input) {
        if (input.length == 0) return input;
        byte[] result = input.clone();
        int pos = rng.nextInt(result.length);
        result[pos] = (byte) rng.nextInt(256);
        return result;
    }

    /** Byte insert: insert 1-4 random bytes at a random position. */
    private byte[] mutateInsert(byte[] input) {
        int count = rng.nextInt(4) + 1;
        int newLen = Math.min(input.length + count, maxInputSize);
        int actualInsert = newLen - input.length;
        if (actualInsert <= 0) return input.clone();

        byte[] result = new byte[newLen];
        int pos = input.length == 0 ? 0 : rng.nextInt(input.length + 1);
        System.arraycopy(input, 0, result, 0, pos);
        for (int i = 0; i < actualInsert; i++) {
            result[pos + i] = (byte) rng.nextInt(256);
        }
        int remaining = Math.min(input.length - pos, newLen - pos - actualInsert);
        if (remaining > 0) {
            System.arraycopy(input, pos, result, pos + actualInsert, remaining);
        }
        return result;
    }

    /** Byte delete: remove 1-4 bytes from a random position. */
    private byte[] mutateDelete(byte[] input) {
        if (input.length <= 1) return input;
        int count = Math.min(rng.nextInt(4) + 1, input.length - 1);
        int pos = rng.nextInt(input.length - count + 1);
        byte[] result = new byte[input.length - count];
        System.arraycopy(input, 0, result, 0, pos);
        System.arraycopy(input, pos + count, result, pos, input.length - pos - count);
        return result;
    }

    // ---- Parent selection ----

    private CorpusEntry selectParent() {
        if (corpus.isEmpty()) return null;

        // During growth phase, strongly prefer the longest input so doubling
        // compounds (diverse inputs execute fast — no quadratic wall)
        if (longestInputLen < maxInputSize && rng.nextInt(10) < 8) {
            return findLongestEntry();
        }

        // Normal weighted selection: proportional to regexSteps, with length as tiebreaker
        long totalWeight = 0;
        for (CorpusEntry e : corpus) {
            totalWeight += Math.max(e.regexSteps, 1) + e.length;
        }
        long pick = rng.nextLong(totalWeight) + 1;
        long cumulative = 0;
        for (CorpusEntry e : corpus) {
            cumulative += Math.max(e.regexSteps, 1) + e.length;
            if (cumulative >= pick) {
                return e;
            }
        }
        return corpus.get(corpus.size() - 1);
    }

    private CorpusEntry findLongestEntry() {
        CorpusEntry longest = corpus.get(0);
        for (int i = 1; i < corpus.size(); i++) {
            if (corpus.get(i).length > longest.length) {
                longest = corpus.get(i);
            }
        }
        return longest;
    }

    // ---- Corpus management ----

    private void evictCorpus() {
        // Keep the entry with the longest input (for growth) and sort by steps
        corpus.sort((a, b) -> Long.compare(b.regexSteps, a.regexSteps));

        // Find the longest entry
        int longestIdx = 0;
        for (int i = 1; i < corpus.size(); i++) {
            if (corpus.get(i).length > corpus.get(longestIdx).length) {
                longestIdx = i;
            }
        }

        // Keep top 50 by steps + the longest entry
        List<CorpusEntry> kept = new ArrayList<>();
        for (int i = 0; i < Math.min(50, corpus.size()); i++) {
            kept.add(corpus.get(i));
        }
        if (longestIdx >= 50) {
            kept.add(corpus.get(longestIdx));
        }
        corpus.clear();
        corpus.addAll(kept);
    }

    private void saveToCorpus(CorpusEntry entry) {
        try {
            String name = String.format("id_%06d_steps_%d_len_%d",
                    totalExecs, entry.regexSteps, entry.length);
            Path path = corpusDir.toPath().resolve(name);
            Files.write(path, entry.input);
        } catch (IOException e) {
            // Non-fatal: just log
            log.println("[V1Guidance] WARNING: could not save corpus entry: " + e.getMessage());
        }
    }

    // ---- Agent signal helpers ----

    private void resetCounter() {
        if (counterReset != null) {
            try {
                counterReset.invoke(null);
            } catch (Exception e) {
                // Ignore
            }
        }
    }

    private long readStepCount() {
        if (counterGetSteps != null) {
            try {
                return (long) counterGetSteps.invoke(null);
            } catch (Exception e) {
                return 0;
            }
        }
        return 0;
    }

    // ---- Corpus entry ----

    private static final class CorpusEntry {
        final byte[] input;
        final long regexSteps;
        final int length;

        CorpusEntry(byte[] input, long regexSteps, int length) {
            this.input = input;
            this.regexSteps = regexSteps;
            this.length = length;
        }
    }
}
